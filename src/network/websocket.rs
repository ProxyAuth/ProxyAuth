//! Relais WebSocket (`forward_websocket: true` dans routes.yml).
//!
//! ```yaml
//! vhosts:
//!   - vhost: ["app.example.com"]
//!     routes:
//!       - prefix: "/socket"
//!         target: "ws://127.0.0.1:3000"     # ou wss://, http://, https://
//!         forward_websocket: true
//!         required_login: true              # appliqué avant le tunnel
//! ```
//!
//! Déroulé, pour une requête d'ouverture WebSocket (HTTP/1.1 `GET` avec
//! `Upgrade: websocket`) sur une route qui l'autorise :
//!
//! 1. Toutes les vérifications habituelles de la route ont déjà eu lieu
//!    (jeton, `username`/rôles, rate limit, en-têtes filtrés et
//!    `X-User`/`X-Forwarded-*` ajoutés) : la requête envoyée au backend
//!    est celle que le proxy aurait envoyée, plus `Connection: Upgrade`
//!    et `Upgrade: websocket`.
//! 2. ProxyAuth ouvre sa propre connexion vers la cible (TLS pour
//!    `wss://`/`https://`) et y joue la poignée de main WebSocket.
//! 3. Si le backend accepte (`101 Switching Protocols`), ProxyAuth
//!    répond `101` au client avec les en-têtes du backend
//!    (`Sec-WebSocket-Accept`, sous-protocole, extensions), puis relaie
//!    les octets dans les deux sens jusqu'à la fermeture d'un côté.
//!    Sinon, la réponse du backend est renvoyée telle quelle.
//!
//! Les trames ne sont pas décodées : le tunnel est transparent (texte,
//! binaire, ping/pong, compression `permessage-deflate` négociée de bout
//! en bout).
//!
//! # HTTP/2 (RFC 8441)
//!
//! Le serveur annonce le CONNECT étendu (`SETTINGS_ENABLE_CONNECT_PROTOCOL`).
//! Un client HTTP/2 ouvre alors sa WebSocket comme un flux de la
//! connexion existante : `CONNECT` avec `:protocol: websocket`, sans
//! `Upgrade` ni `Sec-WebSocket-Key`. ProxyAuth fait la même poignée de
//! main HTTP/1.1 vers le backend (en générant la clé et en vérifiant le
//! `Sec-WebSocket-Accept` du backend), répond `200` au client et relaie
//! les octets entre le flux HTTP/2 et la connexion du backend. Le backend
//! n'a donc rien de particulier à gérer. Un vhost en `protocol: h2`
//! accepte ainsi les WebSocket.
//!
//! Limites : la cible principale `target` seulement (pas de
//! `backends:`) ; pas de proxy sortant. Le jeton est vérifié à l'ouverture : une connexion déjà
//! ouverte n'est pas coupée à son expiration.

use crate::hyper_web::http::header::{self, HeaderMap, HeaderValue};
use crate::hyper_web::http::{Method, StatusCode, Version};
use crate::hyper_web::{HttpRequest, HttpResponse};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Uri;
use hyper_util::rt::TokioIo;
use std::time::Duration;
use tracing::{debug, warn};

use crate::hyper_web::server::{ClientUpgrade, ConnectProtocol};

/// Comment le client a ouvert sa WebSocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsMode {
    /// HTTP/1.1 `GET` + `Upgrade: websocket` (RFC 6455).
    Http1,
    /// HTTP/2 CONNECT étendu avec `:protocol: websocket` (RFC 8441).
    Http2,
}

/// GUID de la RFC 6455 §1.3, pour `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn accept_for(key: &str) -> String {
    use base64::Engine as _;
    let mut input = Vec::with_capacity(key.len() + WS_GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

fn random_key() -> String {
    use base64::Engine as _;
    let mut k = [0u8; 16];
    let _ = getrandom::fill(&mut k);
    base64::engine::general_purpose::STANDARD.encode(k)
}

fn header_has_token(headers: &HeaderMap, name: header::HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|v| {
        v.to_str()
            .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
            .unwrap_or(false)
    })
}

/// Vraie demande d'ouverture WebSocket ? HTTP/1.1 (RFC 6455 §4.1) ou
/// HTTP/2 (RFC 8441 §4).
pub fn websocket_request(req: &HttpRequest) -> Option<WsMode> {
    let h = req.headers();
    if req.method() == Method::GET
        && req.version() == Version::HTTP_11
        && header_has_token(h, header::CONNECTION, "upgrade")
        && header_has_token(h, header::UPGRADE, "websocket")
        && h.contains_key(header::SEC_WEBSOCKET_KEY)
        && h.contains_key(header::SEC_WEBSOCKET_VERSION)
    {
        return Some(WsMode::Http1);
    }
    let is_ws_connect = req.method() == Method::CONNECT
        && req.version() == Version::HTTP_2
        && req
            .extensions()
            .get::<ConnectProtocol>()
            .is_some_and(|p| p.0.eq_ignore_ascii_case("websocket"));
    is_ws_connect.then_some(WsMode::Http2)
}

/// `ws://` → `http://`, `wss://` → `https://` ; sans schéma → `http://`.
pub fn normalize_target_url(s: String) -> String {
    if let Some(rest) = s.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if let Some(rest) = s.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if s.starts_with("http://") || s.starts_with("https://") {
        s
    } else {
        format!("http://{s}")
    }
}

fn plain(status: StatusCode, body: &'static str) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header(("server", "ProxyAuth"))
        .body(body)
}

thread_local! {
    /// Un connecteur (racines de confiance chargées une fois) par worker.
    static CONNECTOR: hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector> = {
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("Failed to load native roots")
            .https_or_http()
            // HTTP/1.1 seulement : l'upgrade WebSocket n'existe qu'en h1.
            .enable_http1()
            .wrap_connector(http)
    };
}

/// Ouvre le tunnel. `request_builder` est la requête déjà préparée par
/// le proxy pour `full_url` (en-têtes filtrés, identité injectée).
pub async fn tunnel(
    req: &HttpRequest,
    mode: WsMode,
    request_builder: hyper::http::request::Builder,
    full_url: &str,
    timeout: Duration,
    ip: &str,
) -> HttpResponse {
    let Some(client_upgrade) = req.extensions_mut().remove::<ClientUpgrade>() else {
        // Requête arrivée sur une connexion sans upgrade possible (HTTP/2).
        return plain(StatusCode::BAD_REQUEST, "WebSocket requires HTTP/1.1");
    };

    let uri: Uri = match full_url.parse() {
        Ok(u) => u,
        Err(_) => return plain(StatusCode::BAD_GATEWAY, "502 Bad Gateway"),
    };

    // Requête vers le backend : chemin relatif, plus les deux en-têtes
    // d'upgrade que le filtrage hop-by-hop a (à juste titre) retirés.
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // Vers le backend, toujours la poignée de main HTTP/1.1 : un client
    // HTTP/2 arrive en CONNECT, sans clé — ProxyAuth en génère une.
    let ws_key = match mode {
        WsMode::Http1 => None,
        WsMode::Http2 => Some(random_key()),
    };
    let mut builder = request_builder
        .method(hyper::Method::GET)
        .uri(path)
        .version(hyper::Version::HTTP_11);
    if let Some(h) = builder.headers_mut() {
        h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        if let Some(k) = &ws_key {
            if let Ok(v) = HeaderValue::from_str(k) {
                h.insert(header::SEC_WEBSOCKET_KEY, v);
            }
            if !h.contains_key(header::SEC_WEBSOCKET_VERSION) {
                h.insert(header::SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
            }
        }
        if !h.contains_key(header::HOST) {
            if let Some(auth) = uri.authority() {
                if let Ok(v) = HeaderValue::from_str(auth.as_str()) {
                    h.insert(header::HOST, v);
                }
            }
        }
    }
    let backend_req = match builder.body(Empty::<Bytes>::new()) {
        Ok(r) => r,
        Err(e) => {
            warn!(client_ip = %ip, target = %full_url, "websocket: invalid upstream request: {e}");
            return plain(StatusCode::BAD_GATEWAY, "502 Bad Gateway");
        }
    };

    let handshake = async {
        use tower_service::Service;
        let mut connector = CONNECTOR.with(|c| c.clone());
        let io = connector
            .call(uri.clone())
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(io)
            .await
            .map_err(|e| format!("handshake: {e}"))?;
        tokio::task::spawn_local(async move {
            if let Err(e) = conn.with_upgrades().await {
                debug!("websocket upstream connection ended: {e}");
            }
        });
        sender
            .send_request(backend_req)
            .await
            .map_err(|e| format!("request: {e}"))
    };

    let mut backend_resp = match tokio::time::timeout(timeout, handshake).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!(client_ip = %ip, target = %full_url, "websocket: upstream unreachable: {e}");
            return plain(StatusCode::BAD_GATEWAY, "502 Bad Gateway");
        }
        Err(_) => {
            warn!(client_ip = %ip, target = %full_url, "websocket: upstream handshake timed out");
            return plain(StatusCode::GATEWAY_TIMEOUT, "504 Gateway Timeout");
        }
    };

    // Refus du backend (401, 403, 426…) : relayé tel quel.
    if backend_resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        let status = backend_resp.status();
        let headers = backend_resp.headers().clone();
        let body = match backend_resp.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => Bytes::new(),
        };
        let mut out = HttpResponse::with_body(status, body);
        for (k, v) in headers.iter() {
            if !crate::network::proxy::is_hop_by_hop_header(k.as_str()) {
                out.headers_mut().append(k.clone(), v.clone());
            }
        }
        return out;
    }

    let backend_upgrade = hyper::upgrade::on(&mut backend_resp);

    let res = match mode {
        // 101 pour le client, avec la poignée de main du backend
        // (Sec-WebSocket-Accept / -Protocol / -Extensions, Upgrade,
        // Connection) : le client a fourni la clé, le backend y a répondu.
        WsMode::Http1 => {
            let mut res = HttpResponse::new(StatusCode::SWITCHING_PROTOCOLS);
            for (k, v) in backend_resp.headers().iter() {
                res.headers_mut().append(k.clone(), v.clone());
            }
            res
        }
        // 200 pour le client HTTP/2 (RFC 8441 §5), après avoir vérifié que
        // le backend a bien accepté *notre* clé. Seuls le sous-protocole et
        // les extensions négociés sont transmis : les en-têtes propres à
        // la connexion n'existent pas en HTTP/2, et un CONNECT réussi ne
        // doit porter ni corps ni Content-Length.
        WsMode::Http2 => {
            let expected = ws_key.as_deref().map(accept_for);
            let got = backend_resp
                .headers()
                .get(header::SEC_WEBSOCKET_ACCEPT)
                .and_then(|v| v.to_str().ok());
            if expected.as_deref() != got {
                warn!(client_ip = %ip, target = %full_url, "websocket: upstream returned an invalid Sec-WebSocket-Accept");
                return plain(StatusCode::BAD_GATEWAY, "502 Bad Gateway");
            }
            let mut res = HttpResponse::new(StatusCode::OK);
            for name in [header::SEC_WEBSOCKET_PROTOCOL, header::SEC_WEBSOCKET_EXTENSIONS] {
                for v in backend_resp.headers().get_all(&name) {
                    res.headers_mut().append(name.clone(), v.clone());
                }
            }
            res
        }
    };
    let res = res.set_body(crate::hyper_web::body::Body::none());

    let target = full_url.to_string();
    let ip = ip.to_string();
    tokio::task::spawn_local(async move {
        let (client, backend) = match tokio::join!(client_upgrade.0, backend_upgrade) {
            (Ok(c), Ok(b)) => (c, b),
            (c, b) => {
                debug!(
                    client_ip = %ip, target = %target,
                    "websocket: upgrade failed (client: {:?}, upstream: {:?})",
                    c.err(), b.err()
                );
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let mut backend = TokioIo::new(backend);
        match tokio::io::copy_bidirectional(&mut client, &mut backend).await {
            Ok((up, down)) => debug!(
                client_ip = %ip, target = %target,
                "websocket closed ({up} bytes up, {down} bytes down)"
            ),
            Err(e) => debug!(client_ip = %ip, target = %target, "websocket ended: {e}"),
        }
    });

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc6455_example() {
        // RFC 6455 §1.3
        assert_eq!(accept_for("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_ne!(random_key(), random_key());
        assert_eq!(random_key().len(), 24);
    }

    #[test]
    fn target_schemes_are_normalized() {
        assert_eq!(normalize_target_url("ws://10.0.0.1:3000/x".into()), "http://10.0.0.1:3000/x");
        assert_eq!(normalize_target_url("wss://h.example/x".into()), "https://h.example/x");
        assert_eq!(normalize_target_url("https://h.example".into()), "https://h.example");
        assert_eq!(normalize_target_url("10.0.0.1:3000".into()), "http://10.0.0.1:3000");
    }
}
