// Copyright 2025 Vladimir Souchet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Refresh tokens for API sessions (`session_cookie: false`).
//!
//! ```text
//! POST /auth            → { token, expires_at, refresh_token, refresh_token_expires_at }
//! POST /refresh_token   → the same shape, a new pair
//! ```
//!
//! - The access token and the refresh token are two different tokens
//!   carrying the **same token id**, for the whole life of the session.
//!   `POST /adm/revoke` with that id ends the session: both tokens, and
//!   every pair issued by later refreshes.
//! - A refresh token is marked as such and refused as an access token;
//!   an access token is refused by `/refresh_token`.
//! - Each refresh moves the session to the next *generation*. Tokens of
//!   an older generation — the previous access token as well as the
//!   previous refresh token — are refused from then on.
//! - A refresh token presented a second time means two parties hold it:
//!   the whole session is revoked (refresh token reuse detection).
//! - `refresh_token_expiry_seconds: 0`, globally or on the vhost, turns
//!   all of this off.

use crate::AppState;
use crate::config::config::{AppConfig, RouteRule, max_token_lifetime};
use crate::revoke::load::{GenerationStep, advance_generation, publish_generation, revoke_token};
use crate::token::security::{
    TokenData, TokenKind, issue_session_token, now_secs, validate_refresh_token,
};
use actix_web::http::header;
use actix_web::{Error as ActixError, HttpRequest, HttpResponse, web};
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use tracing::{error, info, warn};

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// A freshly issued access + refresh pair.
#[derive(Debug, Clone)]
pub struct IssuedPair {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

/// Expiries of a pair issued at `now`: access for `token_expiry_seconds`,
/// refresh for `refresh_lifetime`, neither past the end of the session
/// when `max_lifetime` is set.
pub fn pair_expiries(
    now: u64,
    access_lifetime: u64,
    refresh_lifetime: u64,
    session_started_at: u64,
    max_lifetime: u64,
) -> (u64, u64) {
    let session_end = if max_lifetime > 0 {
        session_started_at.saturating_add(max_lifetime)
    } else {
        u64::MAX
    };
    (
        now.saturating_add(access_lifetime).min(session_end),
        now.saturating_add(refresh_lifetime).min(session_end),
    )
}

/// The refresh token issued alongside the access token at login. Same
/// token id, generation 0.
pub fn issue_login_refresh_token(
    username: &str,
    index_user: usize,
    token_id: &str,
    refresh_lifetime: u64,
    max_lifetime: u64,
) -> Result<(String, u64), String> {
    let now = now_secs();
    let (_, refresh_expires_at) = pair_expiries(now, 0, refresh_lifetime, now, max_lifetime);
    let token = issue_session_token(
        username,
        refresh_expires_at,
        token_id,
        &TokenData {
            index_user,
            issued_at: now,
            session_started_at: now,
            kind: TokenKind::Refresh,
            ..TokenData::default()
        },
    )?;
    Ok((token, refresh_expires_at))
}

/// Issues both tokens of a refreshed session.
#[allow(clippy::too_many_arguments)]
pub fn issue_pair(
    config: &AppConfig,
    username: &str,
    index_user: usize,
    token_id: &str,
    session_started_at: u64,
    generation: u32,
    refresh_lifetime: u64,
    max_lifetime: u64,
) -> Result<IssuedPair, String> {
    let now = now_secs();
    let (access_expires_at, refresh_expires_at) = pair_expiries(
        now,
        config.token_expiry_seconds.max(0) as u64,
        refresh_lifetime,
        session_started_at,
        max_lifetime,
    );
    let base = TokenData {
        index_user,
        issued_at: now,
        session_started_at,
        generation,
        ..TokenData::default()
    };
    let access_token = issue_session_token(username, access_expires_at, token_id, &base)?;
    let refresh_token = issue_session_token(
        username,
        refresh_expires_at,
        token_id,
        &TokenData {
            kind: TokenKind::Refresh,
            ..base
        },
    )?;
    Ok(IssuedPair {
        access_token,
        access_expires_at,
        refresh_token,
        refresh_expires_at,
    })
}

/// An expiry in the configured timezone, formatted like `/auth` always
/// has: `2026-09-17 10:00:00 +02:00`.
pub fn format_expiry(config: &AppConfig, unix_secs: u64) -> String {
    let tz = crate::token::auth::resolve_timezone(config);
    Utc.timestamp_opt(unix_secs.min(i64::MAX as u64) as i64, 0)
        .single()
        .map(|t| t.with_timezone(&tz).format("%Y-%m-%d %H:%M:%S %:z").to_string())
        .unwrap_or_default()
}

/// The JSON body `/auth` and `/refresh_token` answer with.
pub fn pair_json(config: &AppConfig, pair: &IssuedPair) -> serde_json::Value {
    serde_json::json!({
        "token": pair.access_token,
        "expires_at": format_expiry(config, pair.access_expires_at),
        "refresh_token": pair.refresh_token,
        "refresh_token_expires_at": format_expiry(config, pair.refresh_expires_at),
    })
}

fn error_response(status: actix_web::http::StatusCode, code: &str, description: &str) -> HttpResponse {
    HttpResponse::build(status)
        .append_header(("server", "ProxyAuth"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(serde_json::json!({ "error": code, "error_description": description }))
}

/// Refresh lifetime and session cap in force for this request's vhost.
/// A vhost using session cookies has no refresh tokens — `/auth` never
/// issues one there — so its lifetime is `0`.
pub fn policy(rule: Option<&RouteRule>, config: &AppConfig) -> (u64, u64) {
    match rule {
        Some(r) => (
            if r.session_cookie_enabled(config) {
                0
            } else {
                r.resolved_refresh_token_expiry(config)
            },
            r.resolved_session_refresh(config).max_lifetime_secs,
        ),
        None => (
            if config.session_cookie {
                0
            } else {
                config.refresh_token_expiry_seconds
            },
            config.session_max_lifetime_secs,
        ),
    }
}

/// `POST /refresh_token`.
pub async fn refresh_token_dispatch(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    use actix_web::http::StatusCode;

    let host = crate::network::proxy::request_host(&req);
    let vhost_route = crate::network::proxy::find_vhost_route(host.as_deref(), &data.routes.routes);

    // An OIDC vhost belongs to its backend, like /auth and /logout.
    if vhost_route.map(|r| r.oidc.is_some()).unwrap_or(false) {
        return crate::network::proxy::global_proxy(req, body, data).await;
    }

    let (refresh_lifetime, max_lifetime) = policy(vhost_route, &data.config);
    if refresh_lifetime == 0 {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "refresh tokens are disabled on this host",
        ));
    }

    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let parsed: Option<RefreshRequest> = if content_type.contains("application/json") {
        serde_json::from_slice(&body).ok()
    } else if content_type.contains("application/x-www-form-urlencoded") {
        serde_urlencoded::from_bytes(&body).ok()
    } else {
        None
    };
    let Some(request) = parsed.filter(|r| !r.refresh_token.trim().is_empty()) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "send refresh_token as JSON or as a form field",
        ));
    };

    let ip = crate::network::proxy::client_ip(&req, &data.config)
        .map(|i| i.to_string())
        .unwrap_or_else(|| "-".to_string());

    let session = match validate_refresh_token(
        request.refresh_token.trim(),
        &data,
        &data.config,
        &ip,
        refresh_lifetime,
    )
    .await
    {
        Ok(session) => session,
        Err(reason) => {
            warn!("[{ip}] refresh refused: {reason}");
            return Ok(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_grant",
                "the refresh token is invalid, expired or revoked",
            ));
        }
    };

    // The account may have changed since login.
    let Some(user) = data.config.user_by_index(session.data.index_user) else {
        return Ok(error_response(StatusCode::UNAUTHORIZED, "invalid_grant", "unknown account"));
    };
    if !crate::token::auth::is_ip_allowed(&ip, &user) {
        warn!("[{ip}] refresh denied for {}: address not allowed", user.username);
        return Ok(error_response(StatusCode::FORBIDDEN, "access_denied", "access denied"));
    }
    if let Some(rule) = vhost_route {
        if !rule.login_authorized(&user.username, &data.config) {
            warn!("[{ip}] refresh denied for {}: not authorized on this vhost", user.username);
            return Ok(error_response(StatusCode::FORBIDDEN, "access_denied", "access denied"));
        }
    }

    let now = now_secs();
    let started_at = if session.data.session_started_at > 0 {
        session.data.session_started_at
    } else {
        session.data.issued_at
    };
    if max_lifetime > 0 && now >= started_at.saturating_add(max_lifetime) {
        info!("[{ip}] session of {} reached session_max_lifetime_secs; sign-in required", user.username);
        return Ok(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_grant",
            "the session has ended, sign in again",
        ));
    }

    let (_, refresh_expires_at) = pair_expiries(now, 0, refresh_lifetime, started_at, max_lifetime);

    let generation = match advance_generation(
        &session.token_id,
        session.data.generation,
        refresh_expires_at,
        &data.revoked_tokens,
    ) {
        GenerationStep::Advanced { generation, value } => {
            if let Err(e) = publish_generation(&session.token_id, value, &data.revoked_tokens).await {
                warn!("[{ip}] refresh generation not persisted everywhere: {e}");
            }
            generation
        }
        GenerationStep::Stale { current } => {
            // Already exchanged: someone else holds this refresh token.
            // End the session for everyone.
            warn!(
                "[{ip}] refresh token reuse for {} (generation {} presented, {} current): session {} revoked",
                user.username, session.data.generation, current, session.token_id
            );
            let keep_until = now.saturating_add(max_token_lifetime(&data.config, &data.routes.routes));
            if let Err(e) = revoke_token(&session.token_id, Some(keep_until), &data.revoked_tokens).await {
                warn!("[{ip}] session revocation not persisted everywhere: {e}");
            }
            return Ok(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_grant",
                "this refresh token was already used; the session has been revoked",
            ));
        }
    };

    let pair = match issue_pair(
        &data.config,
        &user.username,
        session.data.index_user,
        &session.token_id,
        started_at,
        generation,
        refresh_lifetime,
        max_lifetime,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            error!("[{ip}] failed to issue refreshed tokens for {}: {e}", user.username);
            return Ok(HttpResponse::InternalServerError().finish());
        }
    };

    info!(
        "[{ip}] session of {} refreshed (generation {generation})",
        user.username
    );

    Ok(HttpResponse::Ok()
        .append_header(("server", "ProxyAuth"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(pair_json(&data.config, &pair)))
}
