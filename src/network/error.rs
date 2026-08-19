use crate::AppState;
use crate::config::config::BackendConfig;
use crate::config::config::BackendInput;
use crate::network::loadbalancing::forward_failover;
use crate::network::shared_client::BoxBody;
use crate::network::shared_client::ClientOptions;
use crate::network::shared_client::get_or_build_client;
use crate::token::csrf::inject_csrf_token;
use actix_web::rt::time::timeout;
use actix_web::{HttpRequest, HttpResponse, web};
use brotli::{CompressorWriter, Decompressor};
use flate2::{
    Compression,
    read::{DeflateDecoder, GzDecoder},
    write::{DeflateEncoder, GzEncoder},
};
use http_body_util::{BodyExt, Empty, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper::header::{ACCEPT_LANGUAGE, CONTENT_TYPE, COOKIE, HeaderValue, ORIGIN, USER_AGENT};
use std::convert::Infallible;
use std::io::{Read, Write};
use std::time::Duration;

fn toggle_error_block(html: String, error_text: &str) -> String {
    let start_marker = "<!-- BEGIN_BLOCK_ERROR -->";
    let end_marker = "<!-- END_BLOCK_ERROR -->";

    if error_text.is_empty() {
        return html;
    }

    let (Some(s), Some(e)) = (html.find(start_marker), html.find(end_marker)) else {
        return html;
    };

    let block_start = s + start_marker.len();
    let block_end = e;

    let mut block = html[block_start..block_end].to_string();
    block = block.replace("<!--", "").replace("-->", "");
    block = block.replace("{{ error }}", error_text);

    let mut out = html;
    out.replace_range(block_start..block_end, &block);
    out
}

pub async fn render_error_page(
    req: &HttpRequest,
    data: web::Data<AppState>,
    error_text: &str,
) -> HttpResponse {
    let logout_url: String = match &data.config.logout_redirect_url {
        Some(u) if !u.is_empty() => u.clone(),
        _ => return HttpResponse::BadRequest().body("logout_redirect_url is not configured"),
    };

    let (path, query_opt) =
        if logout_url.starts_with("http://") || logout_url.starts_with("https://") {
            match logout_url
                .split_once("://")
                .and_then(|(_, rest)| rest.split_once('/'))
            {
                Some((_, tail)) => {
                    if let Some((p, q)) = tail.split_once('?') {
                        (
                            format!("/{}", p.trim_start_matches('/')),
                            Some(q.to_string()),
                        )
                    } else {
                        (format!("/{}", tail.trim_start_matches('/')), None)
                    }
                }
                None => ("/".to_string(), None),
            }
        } else if let Some((p, q)) = logout_url.split_once('?') {
            (p.to_string(), Some(q.to_string()))
        } else {
            (logout_url.clone(), None)
        };

    let Some(rule) = data
        .routes
        .routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
    else {
        return HttpResponse::BadRequest().body("No matching route for logout_redirect_url path");
    };

    let raw_forward = path
        .strip_prefix(&rule.prefix)
        .unwrap_or("")
        .trim_start_matches('/');
    let cleaned = raw_forward.trim_end_matches('/');

    let forward_path = if cleaned.is_empty() {
        "".to_string()
    } else {
        format!("/{}", cleaned)
    };

    let mut target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);
    if let Some(q) = &query_opt {
        if !q.is_empty() {
            target_url.push('?');
            target_url.push_str(q);
        }
    }
    let full_url = if target_url.starts_with("http") {
        target_url.clone()
    } else {
        format!("http://{}", target_url)
    };

    // ── Client : on passe par le cache global, pas de thread-local ──────────
    let client_opts = if !rule.cert.is_empty() {
        ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: true,
            cert_path: rule.cert.get("file").cloned(),
            key_path: rule.cert.get("key").cloned(),
        }
    } else {
        ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: false,
            cert_path: None,
            key_path: None,
        }
    };
    let client = get_or_build_client(client_opts, &data.config);

    let backend_host = match full_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/').map(|(h, _)| h))
    {
        Some(h) => h,
        None => "",
    };

    let mut rb = Request::builder()
        .method("GET")
        .uri(&full_url)
        .header("Host", backend_host)
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .header("Accept-Encoding", "gzip, deflate, br");

    if let Some(ua) = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
    {
        rb = rb.header(USER_AGENT, ua);
    }
    if let Some(ck) = req.headers().get("cookie").and_then(|v| v.to_str().ok()) {
        rb = rb.header(COOKIE, ck);
    }
    if let Some(al) = req
        .headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
    {
        rb = rb.header(ACCEPT_LANGUAGE, al);
    }
    if let Some(ori) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        rb = rb.header(ORIGIN, ori);
    }

    let hyper_req = match rb.body(Empty::<Bytes>::new().boxed()) {
        Ok(r) => r,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to build backend request");
        }
    };

    let response_result: hyper::Response<BoxBody> = if !rule.backends.is_empty() {
        let backends: Vec<BackendConfig> = rule
            .backends
            .iter()
            .map(|b| match b {
                BackendInput::Simple(url) => BackendConfig {
                    url: url.clone(),
                    weight: 1,
                },
                BackendInput::Detailed(cfg) => cfg.clone(),
            })
            .collect();

        match forward_failover(hyper_req, &backends, None).await {
            Ok(res) => res,
            Err(_e) => {
                return HttpResponse::ServiceUnavailable()
                    .insert_header(("server", "ProxyAuth"))
                    .body("Failover failed");
            }
        }
    } else {
        match timeout(Duration::from_millis(500), client.request(hyper_req)).await {
            Ok(Ok(res)) => {
                let (parts, body) = res.into_parts();
                let bytes = match body.collect().await {
                    Ok(c) => c.to_bytes(),
                    Err(_) => {
                        return HttpResponse::ServiceUnavailable()
                            .insert_header(("server", "ProxyAuth"))
                            .body("Upstream body error");
                    }
                };
                let boxed: BoxBody = Full::new(bytes).map_err(|e: Infallible| e).boxed();
                hyper::Response::from_parts(parts, boxed)
            }
            Ok(Err(_e)) => {
                return HttpResponse::ServiceUnavailable()
                    .insert_header(("server", "ProxyAuth"))
                    .body("Upstream client error");
            }
            Err(_to) => {
                return HttpResponse::ServiceUnavailable()
                    .insert_header(("server", "ProxyAuth"))
                    .body("Upstream timeout");
            }
        }
    };

    if response_result.status().is_client_error() || response_result.status().is_server_error() {
        return HttpResponse::BadRequest()
            .insert_header(("server", "ProxyAuth"))
            .body(format!("Backend status: {}", response_result.status()));
    }

    let (parts, body) = response_result.into_parts();
    let headers: hyper::HeaderMap = parts.headers;

    let encoding = headers
        .get("content-encoding")
        .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
        .map(|s: &str| s.to_lowercase());

    let body_bytes: Bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return HttpResponse::InternalServerError().body("Failed to read backend body"),
    };

    let mut html = match encoding.as_deref() {
        Some("gzip") => {
            let mut d = GzDecoder::new(&body_bytes[..]);
            let mut out = String::new();
            d.read_to_string(&mut out).unwrap_or(0);
            out
        }
        Some("deflate") => {
            let mut d = DeflateDecoder::new(&body_bytes[..]);
            let mut out = String::new();
            d.read_to_string(&mut out).unwrap_or(0);
            out
        }
        Some("br") => {
            let mut out = Vec::new();
            let mut d = Decompressor::new(&body_bytes[..], 4096);
            d.read_to_end(&mut out).unwrap_or(0);
            String::from_utf8_lossy(&out).into_owned()
        }
        _ => String::from_utf8_lossy(&body_bytes).into_owned(),
    };

    html = toggle_error_block(html, error_text);

    let mut plain: bytes::Bytes = bytes::Bytes::from(html.into_bytes());

    let mut inj_headers: hyper::HeaderMap = headers.clone();
    inj_headers.remove("content-encoding");

    if !inj_headers.contains_key("content-type") {
        inj_headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    } else if let Some(ct) = inj_headers
        .get("content-type")
        .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
        .map(|s: &str| s.to_ascii_lowercase())
    {
        if !ct.contains("html") {
            inj_headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
        }
    }

    if data.config.session_cookie && data.config.csrf_token {
        if let Some((new_body, _)) = inject_csrf_token(&inj_headers, &plain, &data.config.secret) {
            plain = new_body;
        }
    }

    let (final_body, final_ce_opt) = match encoding.as_deref() {
        Some("gzip") => {
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(plain.as_ref()).ok();
            (e.finish().unwrap_or_default(), Some("gzip"))
        }
        Some("deflate") => {
            let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
            e.write_all(plain.as_ref()).ok();
            (e.finish().unwrap_or_default(), Some("deflate"))
        }
        Some("br") => {
            let mut e = CompressorWriter::new(Vec::new(), 4096, 5, 22);
            e.write_all(plain.as_ref()).ok();
            (e.into_inner(), Some("br"))
        }
        _ => (plain.to_vec(), None),
    };

    let mut resp = HttpResponse::Unauthorized();
    resp.insert_header(("server", "ProxyAuth"));
    resp.insert_header((
        "cache-control",
        "no-store, no-cache, must-revalidate, max-age=0",
    ));
    resp.insert_header(("pragma", "no-cache"));
    resp.insert_header(("expires", "0"));
    resp.insert_header(("content-type", "text/html; charset=utf-8"));
    if let Some(enc) = final_ce_opt {
        resp.insert_header(("content-encoding", enc));
    }
    resp.insert_header(("content-length", final_body.len().to_string()));
    resp.body(final_body)
}
