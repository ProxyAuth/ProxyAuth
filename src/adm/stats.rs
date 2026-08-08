use crate::AppState;
use crate::network::stats::build_stats_response;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, Responder, http::header, web};
use subtle::ConstantTimeEq;
use tracing::warn;

fn cors_response(mut resp: HttpResponseBuilder, req: &HttpRequest) -> HttpResponseBuilder {
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        if let Ok(origin_str) = origin.to_str() {
            if let Some(cors_origins) = &req
                .app_data::<web::Data<AppState>>()
                .and_then(|data| data.config.cors_origins.as_ref())
                {
                    let origin_clean = origin_str.trim_end_matches('/');
                    if cors_origins
                        .iter()
                        .any(|o| o.trim_end_matches('/') == origin_clean)
                        {
                            resp.append_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str));
                            resp.append_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
                            resp.append_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
                        }
                }
        }
    }
    resp
}

/// Verifies the `X-Auth-Token: <token>` header against the configured admin token.
/// Uses constant-time comparison to prevent timing attacks.
fn is_valid_admin_token(req: &HttpRequest, data: &web::Data<AppState>) -> bool {
    let expected = &data.config.token_admin;

    if expected.is_empty() {
        return false; // no admin token configured -> endpoint disabled
    }

    let provided = req
    .headers()
    .get("X-Auth-Token")
    .and_then(|v| v.to_str().ok());

    match provided {
        Some(token) => token.as_bytes().ct_eq(expected.as_bytes()).into(),
        None => false,
    }
}

/// GET /proxyauth/stats
pub async fn get_proxy_stats(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if !is_valid_admin_token(&req, &data) {
        warn!("Unauthorized access attempt to /proxyauth/stats");
        return HttpResponse::Unauthorized()
        .append_header(("server", "ProxyAuth"))
        .body("Invalid or missing admin token");
    }

    let active_sessions = data.counter.count_active_sessions();
    let resp = build_stats_response(&data.stats, active_sessions).await;

    cors_response(HttpResponse::Ok(), &req)
    .append_header(("server", "ProxyAuth"))
    .json(resp)
}

/// GET /proxyauth/stats/sessions
pub async fn get_proxy_sessions(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if !is_valid_admin_token(&req, &data) {
        warn!("Unauthorized access attempt to /proxyauth/stats/sessions");
        return HttpResponse::Unauthorized()
        .append_header(("server", "ProxyAuth"))
        .body("Invalid or missing admin token");
    }

    let sessions = data.counter.get_active_sessions_json();

    cors_response(HttpResponse::Ok(), &req)
    .append_header(("server", "ProxyAuth"))
    .json(sessions)
}
