use crate::AppState;
use crate::network::stats::build_stats_response;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, Responder, http::header, web};
use chrono::Utc;
use chrono_tz::Tz;
use serde::Serialize;
use std::sync::atomic::Ordering;
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
pub(crate) fn is_valid_admin_token(req: &HttpRequest, data: &web::Data<AppState>) -> bool {
    let expected = &data.config.token_admin;
    if expected.is_empty() {
        return false;
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

/// Formats a UTC timestamp into the configured timezone as a human-readable string.
/// Falls back to UTC if the configured timezone string is invalid.
fn format_in_configured_tz(dt: chrono::DateTime<Utc>, tz_str: &str) -> String {
    match tz_str.parse::<Tz>() {
        Ok(tz) => {
            let local = dt.with_timezone(&tz);
            local.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        Err(_) => {
            warn!(
                "Invalid timezone '{}' in config, falling back to UTC",
                tz_str
            );
            dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        }
    }
}

#[derive(Serialize)]
pub struct TokenUsageView {
    pub token_id: String,
    pub count: u64,
    pub delivery_at: String,
    pub expire_at: String,
}

#[derive(Serialize)]
pub struct AllTokenUsageView {
    pub user: String,
    pub tokens: Vec<TokenUsageView>,
}

/// GET /adm/stats/live
pub async fn get_proxy_stats(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if !is_valid_admin_token(&req, &data) {
        warn!("Unauthorized access attempt to /adm/stats/live");
        return HttpResponse::Unauthorized()
            .append_header(("server", "ProxyAuth"))
            .body("Invalid or missing admin token");
    }

    let active_sessions = data.counter.count_active_sessions();
    let resp = build_stats_response(&data.stats, active_sessions);

    cors_response(HttpResponse::Ok(), &req)
        .append_header(("server", "ProxyAuth"))
        .json(resp)
}

/// GET /adm/stats/sessions
pub async fn get_proxy_sessions(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if !is_valid_admin_token(&req, &data) {
        warn!("Unauthorized access attempt to /adm/stats/sessions");
        return HttpResponse::Unauthorized()
            .append_header(("server", "ProxyAuth"))
            .body("Invalid or missing admin token");
    }

    let tz_str = &data.config.timezone;

    let sessions: Vec<AllTokenUsageView> = data
        .counter
        .get_active_sessions_json()
        .into_iter()
        .map(|user_usage| AllTokenUsageView {
            user: user_usage.user,
            tokens: user_usage
                .tokens
                .into_iter()
                .map(|t| TokenUsageView {
                    token_id: t.token_id,
                    count: t.count.load(Ordering::Relaxed),
                    delivery_at: format_in_configured_tz(t.delivery_at, tz_str),
                    expire_at: format_in_configured_tz(t.expire_at, tz_str),
                })
                .collect(),
        })
        .collect();

    cors_response(HttpResponse::Ok(), &req)
        .append_header(("server", "ProxyAuth"))
        .json(sessions)
}
