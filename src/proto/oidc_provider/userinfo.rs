//! `GET /userinfo` — the OIDC userinfo endpoint. Called by the relying
//! party with the `access_token` obtained from `/token`, as a Bearer
//! token — returns claims about the authenticated user.
//!
//! Unlike `/authorize` (reached by the browser, so it also accepts a
//! `session_token` cookie) this only ever accepts `Authorization:
//! Bearer <access_token>` — a userinfo call is meant to be made by
//! the relying party itself, not forwarded from an end user's
//! browser, so there's no session-cookie fallback to consider here.

use crate::config::config::AppState;
use crate::network::proxy::{find_vhost_route, request_host};
use crate::proto::oidc_provider::jwt::signing_key;
use crate::proto::oidc_provider::token::AccessTokenClaims;
use actix_web::{HttpRequest, HttpResponse, web};
use serde_json::{Map, Value};

fn userinfo_error(status: actix_web::http::StatusCode, error: &str) -> HttpResponse {
    HttpResponse::build(status)
        .append_header(("server", "ProxyAuth"))
        .append_header(("www-authenticate", format!(r#"Bearer error="{error}""#)))
        .content_type("application/json")
        .json(serde_json::json!({ "error": error }))
}

pub async fn userinfo_handler(req: HttpRequest, data: web::Data<AppState>) -> HttpResponse {
    let Some(access_token) = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    else {
        return userinfo_error(actix_web::http::StatusCode::UNAUTHORIZED, "invalid_request");
    };

    let key = signing_key();
    let claims = match jsonwebtoken::decode::<AccessTokenClaims>(
        access_token,
        &key.decoding_key,
        &key.validation_no_audience(),
    ) {
        Ok(decoded) => decoded.claims,
        Err(_) => {
            return userinfo_error(actix_web::http::StatusCode::UNAUTHORIZED, "invalid_token");
        }
    };

    // The access_token's own `iss` must match the vhost this request
    // actually came in on — without this, an access_token issued for
    // one oidc-enabled vhost could be replayed against another vhost
    // that also happens to have `oidc:` configured (they all
    // currently share one signing key — see `jwt`'s own doc comment —
    // so the signature alone doesn't distinguish which vhost a token
    // was really meant for).
    let Some(host) = request_host(&req) else {
        return userinfo_error(actix_web::http::StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) else {
        return userinfo_error(actix_web::http::StatusCode::BAD_REQUEST, "invalid_request");
    };
    if rule.oidc.is_none() {
        return userinfo_error(actix_web::http::StatusCode::BAD_REQUEST, "invalid_request");
    }
    let expected_issuer = format!("https://{host}");
    if claims.iss != expected_issuer {
        return userinfo_error(actix_web::http::StatusCode::UNAUTHORIZED, "invalid_token");
    }

    let scopes: Vec<&str> = claims.scope.split_whitespace().collect();

    let mut response = Map::new();
    response.insert("sub".to_string(), Value::String(claims.sub.clone()));

    if scopes.contains(&"email") || scopes.contains(&"profile") {
        if let Some(user) = data
            .config
            .combined_users()
            .into_iter()
            .find(|u| u.username == claims.sub)
        {
            if scopes.contains(&"email") {
                if let Some(emails) = &user.email {
                    let chosen = emails.iter().find(|e| e.primary).or(emails.first());
                    if let Some(entry) = chosen {
                        response.insert(
                            "email".to_string(),
                            Value::String(entry.address.clone()),
                        );
                        response.insert("email_verified".to_string(), Value::Bool(true));
                    }
                }
            }
            if scopes.contains(&"profile") {
                // `name` falls back to the username itself — ProxyAuth's
                // own User model has no separate display-name field to
                // draw from, and `sub` (already required regardless of
                // scope) is the only stable identifier every relying
                // party already has anyway.
                response.insert("name".to_string(), Value::String(user.username.clone()));
            }
        }
    }

    HttpResponse::Ok()
        .append_header(("server", "ProxyAuth"))
        .append_header(("cache-control", "no-store"))
        .content_type("application/json")
        .json(Value::Object(response))
}
