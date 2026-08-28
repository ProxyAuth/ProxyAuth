use crate::AppState;
use crate::revoke::load::revoke_token;
use crate::token::security::validate_token;
use actix_web::{HttpRequest, HttpResponse, http::header, http::header::ContentType, web};
use time::{OffsetDateTime, format_description::well_known::Rfc2822};
use tracing::warn;

pub async fn logout_options(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> impl actix_web::Responder {
    let origin_header = req.headers().get(header::ORIGIN);
    let origin = origin_header.and_then(|v| v.to_str().ok());

    let vhost_route = crate::network::proxy::find_vhost_route(
        crate::network::proxy::request_host(&req).as_deref(),
        &data.routes.routes,
    );
    let allowed = vhost_route
        .and_then(|r| r.resolved_cors_origins(&data.config))
        .or(data.config.cors_origins.as_ref());

    let is_allowed = match (origin, allowed) {
        (Some(o), Some(list)) => {
            let origin_normalized = o.trim_end_matches('/');
            list.iter()
                .any(|allowed| allowed.trim_end_matches('/') == origin_normalized)
        }
        _ => false,
    };

    if let (Some(origin_str), true) = (origin, is_allowed) {
        HttpResponse::Ok()
            .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str))
            .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS"))
            .insert_header((
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Authorization, Content-Type, Accept",
            ))
            .insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"))
            .finish()
    } else {
        HttpResponse::Forbidden().body("CORS origin not allowed")
    }
}

pub async fn logout_session(req: HttpRequest, data: web::Data<AppState>) -> HttpResponse {
    // SECURITY: previously this handler only cleared the client-side
    // cookie — the token itself stayed fully valid server-side until its
    // natural expiry. A copy of the token obtained before logout (XSS,
    // shared/borrowed session, log exposure, etc.) kept working
    // indefinitely. We now best-effort revoke the token server-side too,
    // via the same revoke_token() used by /adm/revoke.
    if let Some(cookie) = req.cookie("session_token") {
        let ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                req.connection_info()
                    .realip_remote_addr()
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "-".to_string());

        match validate_token(cookie.value(), &data, &data.config, &ip).await {
            Ok((username, token_id, _)) => {
                if let Err(e) = revoke_token(&token_id, None, &data.revoked_tokens).await {
                    warn!(
                        "[{}] Failed to revoke token {} for user {} on logout: {}",
                        ip, token_id, username, e
                    );
                }
            }
            Err(_) => {
                // Cookie was missing/invalid/already expired — nothing
                // meaningful to revoke; still proceed with clearing it.
            }
        }
    }

    let expires_str = OffsetDateTime::UNIX_EPOCH.format(&Rfc2822).unwrap();

    let raw_cookie = format!(
        "session_token=; Expires={}; Path=/; HttpOnly; Secure; SameSite=Strict",
        expires_str
    );

    let vhost_route = crate::network::proxy::find_vhost_route(
        crate::network::proxy::request_host(&req).as_deref(),
        &data.routes.routes,
    );
    let logout_redirect_url = vhost_route
        .and_then(|r| r.resolved_logout_redirect_url(&data.config))
        .or(data.config.logout_redirect_url.as_deref());

    let mut resp = if let Some(url) = logout_redirect_url {
        if !url.is_empty() {
            let mut r = HttpResponse::Found();
            r.insert_header((header::LOCATION, url));
            r
        } else {
            HttpResponse::Ok()
        }
    } else {
        HttpResponse::Ok()
    };

    resp.insert_header((header::SET_COOKIE, raw_cookie));
    resp.insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));

    if let Some(origin) = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
    }

    if data
        .config
        .logout_redirect_url
        .as_ref()
        .map_or(true, |s| s.is_empty())
    {
        resp.insert_header(ContentType::plaintext());
        resp.body("Session cookie cleared")
    } else {
        resp.finish()
    }
}
