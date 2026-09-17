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

//! Session renewal: replacing a session token while it is being used,
//! without asking the user to sign in again.
//!
//! ```text
//! login ──── interval ────┬──────────────── token_expiry_seconds ───┐
//!                          │ next request: new token in Set-Cookie   │
//!                          │ old token: accepted for grace_secs,      │
//!                          │            then refused                  │
//!                          └─ new token ──── interval ────┬── …       │
//!                                                          …          ▼
//! session_max_lifetime_secs (optional): hard end, counted from login
//! ```
//!
//! - Only a token that arrived in the `session_token` cookie is renewed:
//!   a `Bearer` client has nowhere to receive a new cookie.
//! - The new token has a new id and a full `token_expiry_seconds`
//!   lifetime (capped by `session_max_lifetime_secs` when set), and keeps
//!   the original login time.
//! - The old token is revoked with a delay through the regular
//!   revocation store (see `revoke::load::revoke_token_after`), so every
//!   node sharing Redis applies it.
//! - Requests that arrive together with the same old token — a page and
//!   its assets, several tabs — all receive the *same* new token instead
//!   of minting one each. That deduplication is per process.

use crate::AppState;
use crate::config::config::{RouteRule, SessionRefreshPolicy};
use crate::revoke::load::{revoke_token_after, rotated_key, unpack_rotation};
use crate::token::auth::generate_random_string;
use crate::token::security::{TokenData, ValidSession, issue_session_token, now_secs};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpMessage, HttpRequest, web};
use dashmap::DashMap;
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// What the caller should do with a request whose session just
/// validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRefresh {
    /// Nothing to do: renewal disabled, not due yet, or not a cookie
    /// session.
    Keep,
    /// A new token was issued; this `Set-Cookie` value must be added to
    /// the response.
    Renewed(String),
    /// The session is older than `session_max_lifetime_secs`: treat it as
    /// expired and send the visitor to sign in again.
    TooOld,
}

/// A renewal waiting to be attached to the response. Stored in the
/// request extensions by [`remember_renewal`], read by
/// [`take_renewal_cookie`] once the response exists.
#[derive(Debug, Clone)]
pub struct PendingSessionCookie(pub String);

/// Recent renewals, by old token id: the `Set-Cookie` already issued and
/// until when it may be handed out again.
fn recent_renewals() -> &'static DashMap<String, (String, u64)> {
    static RECENT: OnceLock<DashMap<String, (String, u64)>> = OnceLock::new();
    RECENT.get_or_init(DashMap::new)
}

/// Pure decision, separated so it can be tested without a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalDecision {
    Keep,
    Renew,
    TooOld,
}

/// Decides what to do with a valid session at `now`.
///
/// `token_lifetime_secs` is `token_expiry_seconds`: for a token issued
/// before renewal existed (no issue date inside), the age is estimated
/// from its remaining lifetime.
pub fn decide(
    policy: &SessionRefreshPolicy,
    session: &ValidSession,
    token_lifetime_secs: u64,
    now: u64,
) -> RenewalDecision {
    let issued_at = effective_issued_at(session, token_lifetime_secs);
    let started_at = effective_session_start(session, token_lifetime_secs);

    if policy.max_lifetime_secs > 0 && now >= started_at.saturating_add(policy.max_lifetime_secs) {
        return RenewalDecision::TooOld;
    }

    if !policy.enabled() {
        return RenewalDecision::Keep;
    }

    if now.saturating_sub(issued_at) < policy.interval_secs {
        return RenewalDecision::Keep;
    }

    // Renewal also rotates the token, so it happens even when the new
    // token cannot last longer than the current one: with a
    // `session_max_lifetime_secs` shorter than `token_expiry_seconds`,
    // the token issued at login already outlives the session, and
    // skipping renewal there meant never rotating at all. The new
    // token's expiry is capped at the session end by `renewed_expiry`.
    RenewalDecision::Renew
}

fn effective_issued_at(session: &ValidSession, token_lifetime_secs: u64) -> u64 {
    if session.data.issued_at > 0 {
        session.data.issued_at
    } else {
        session.expires_at.saturating_sub(token_lifetime_secs)
    }
}

fn effective_session_start(session: &ValidSession, token_lifetime_secs: u64) -> u64 {
    if session.data.session_started_at > 0 {
        session.data.session_started_at
    } else {
        effective_issued_at(session, token_lifetime_secs)
    }
}

/// Expiry of the replacement token: a full lifetime from `now`, never
/// past the session's hard limit.
pub fn renewed_expiry(
    policy: &SessionRefreshPolicy,
    session_started_at: u64,
    token_lifetime_secs: u64,
    now: u64,
) -> u64 {
    let full = now.saturating_add(token_lifetime_secs);
    if policy.max_lifetime_secs > 0 {
        full.min(session_started_at.saturating_add(policy.max_lifetime_secs))
    } else {
        full
    }
}

/// Whether the session token of `req` came from the cookie rather than
/// an `Authorization: Bearer` header.
pub fn token_came_from_cookie(req: &HttpRequest) -> bool {
    !req.headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "))
}

/// Checks a freshly validated session against the route's renewal
/// policy, renewing it when due.
pub async fn refresh_session(
    req: &HttpRequest,
    data: &web::Data<AppState>,
    rule: &RouteRule,
    session: &ValidSession,
) -> SessionRefresh {
    let policy = rule.resolved_session_refresh(&data.config);
    let lifetime = data.config.token_expiry_seconds.max(0) as u64;
    let now = now_secs();

    // This token came from a renewal and is being used: the browser has
    // it, so the token it replaced has no reason to stay valid until the
    // end of its grace period.
    if let Some(previous) = &session.data.previous_token_id {
        retire_predecessor(previous, &policy, lifetime, now, &data.revoked_tokens).await;
    }

    match decide(&policy, session, lifetime, now) {
        RenewalDecision::Keep => {
            debug!(
                "session of {}: no renewal ({})",
                session.username,
                if policy.enabled() {
                    format!(
                        "token issued {}s ago, renewal after {}s",
                        now.saturating_sub(effective_issued_at(session, lifetime)),
                        policy.interval_secs
                    )
                } else {
                    "session_refresh_interval_secs is 0 for this route".to_string()
                }
            );
            return SessionRefresh::Keep;
        }
        RenewalDecision::TooOld => {
            info!(
                "session of {} reached session_max_lifetime_secs ({}s); sign-in required",
                session.username, policy.max_lifetime_secs
            );
            return SessionRefresh::TooOld;
        }
        RenewalDecision::Renew => {}
    }

    if !token_came_from_cookie(req) {
        debug!(
            "session of {}: due for renewal but sent as a Bearer token, which cannot receive a cookie",
            session.username
        );
        return SessionRefresh::Keep;
    }

    // Already renewed moments ago by a concurrent request: hand out the
    // same cookie.
    let recent = recent_renewals();
    if let Some(entry) = recent.get(&session.token_id) {
        if entry.1 > now {
            return SessionRefresh::Renewed(entry.0.clone());
        }
    }

    let started_at = effective_session_start(session, lifetime);
    let expires_at = renewed_expiry(&policy, started_at, lifetime, now);
    let new_id = generate_random_string(48);
    let token_data = TokenData {
        index_user: session.data.index_user,
        issued_at: now,
        session_started_at: started_at,
        // An id that cannot be carried is simply left out: the old token
        // then keeps its full grace period, and the session still works.
        previous_token_id: crate::token::security::is_token_id(&session.token_id)
            .then(|| session.token_id.clone()),
        ..TokenData::default()
    };

    let token = match issue_session_token(&session.username, expires_at, &new_id, &token_data) {
        Ok(token) => token,
        Err(e) => {
            // The current token is still valid: keep serving with it.
            warn!("session renewal for {} failed: {e}", session.username);
            return SessionRefresh::Keep;
        }
    };

    let cookie = session_cookie(
        &token,
        rule.resolved_max_age_session_cookie(&data.config),
        lifetime,
        expires_at.saturating_sub(now),
    );

    // Never push a refusal later than one already recorded — for
    // instance by an earlier renewal whose successor has been used.
    let refuse_from = match data.revoked_tokens.get(&rotated_key(&session.token_id)) {
        Some(value) => unpack_rotation(*value).0.min(now.saturating_add(policy.grace_secs)),
        None => now.saturating_add(policy.grace_secs),
    };
    if let Err(e) = revoke_token_after(
        &session.token_id,
        refuse_from,
        session.expires_at,
        &data.revoked_tokens,
    )
    .await
    {
        // Not fatal for the visitor, but the old token would stay usable
        // until it expires on its own — worth a loud line.
        warn!(
            "session renewal for {}: could not schedule revocation of the previous token: {e}",
            session.username
        );
    }

    remember(recent, &session.token_id, &cookie, refuse_from, now);

    info!(
        "session of {} renewed (token issued {}s ago); previous token accepted for {}s more",
        session.username,
        now.saturating_sub(effective_issued_at(session, lifetime)),
        policy.grace_secs
    );

    SessionRefresh::Renewed(cookie)
}

/// Seconds a replaced token still gets once its successor has been used:
/// requests already on their way with the old cookie are not refused
/// halfway through a page load.
pub const IN_FLIGHT_SECS: u64 = 2;

/// When a replaced token must stop being accepted, given that its
/// successor has just been used. `None` if it is already refused by then
/// (nothing to write).
pub fn predecessor_deadline(
    existing: Option<u64>,
    policy: &SessionRefreshPolicy,
    lifetime: u64,
    now: u64,
) -> Option<(u64, u64)> {
    let refuse_from = now.saturating_add(policy.grace_secs.min(IN_FLIGHT_SECS));
    let (current_refusal, purge_at) = match existing {
        Some(value) => unpack_rotation(value),
        // Renewed on another instance whose revocation has not reached
        // this one yet: bound it by the longest a token can live.
        None => (u64::MAX, now.saturating_add(lifetime)),
    };
    if current_refusal <= refuse_from {
        return None;
    }
    Some((refuse_from, purge_at.max(refuse_from)))
}

/// Ends the predecessor of a session being logged out, at once: after a
/// logout there is no in-flight request worth protecting.
pub async fn retire_predecessor_now(
    previous: &str,
    lifetime: u64,
    revoked: &crate::revoke::db::RevokedTokenMap,
) {
    let no_margin = SessionRefreshPolicy {
        interval_secs: 0,
        grace_secs: 0,
        max_lifetime_secs: 0,
    };
    retire_predecessor(previous, &no_margin, lifetime, now_secs(), revoked).await;
}

/// Brings the refusal of a replaced token forward to now (plus
/// [`IN_FLIGHT_SECS`], or less with a shorter grace period). Written
/// once: later requests find the entry already due and do nothing. Goes
/// through the revocation store, so every instance sharing Redis applies
/// it.
async fn retire_predecessor(
    previous: &str,
    policy: &SessionRefreshPolicy,
    lifetime: u64,
    now: u64,
    revoked: &crate::revoke::db::RevokedTokenMap,
) {
    let existing = revoked.get(&rotated_key(previous)).map(|v| *v);
    let Some((refuse_from, purge_at)) = predecessor_deadline(existing, policy, lifetime, now) else {
        return;
    };
    if let Err(e) = revoke_token_after(previous, refuse_from, purge_at, revoked).await {
        warn!("could not retire the token replaced by a renewal: {e}");
    } else {
        debug!("token replaced by a renewal retired: its successor is in use");
    }
    // The shared renewal stays in `recent_renewals`: a request still in
    // flight with the old token gets the same successor, instead of
    // triggering a second renewal.
}

fn remember(
    recent: &DashMap<String, (String, u64)>,
    old_id: &str,
    cookie: &str,
    until: u64,
    now: u64,
) {
    // Bounded without a background task: expired entries are dropped
    // whenever the map grows.
    if recent.len() > 1024 {
        recent.retain(|_, (_, until)| *until > now);
    }
    recent.insert(old_id.to_string(), (cookie.to_string(), until));
}

/// The `Set-Cookie` value for a renewed token — same attributes as the
/// one `/auth` sets.
pub fn session_cookie(
    token: &str,
    max_age_session_cookie: i64,
    token_lifetime_secs: u64,
    token_remaining_secs: u64,
) -> String {
    let cap = max_age_session_cookie
        .max(0)
        .min(token_lifetime_secs.min(i64::MAX as u64) as i64) as u64;
    let max_age = token_remaining_secs.min(cap) as i64;

    Cookie::build("session_token", token.to_string())
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(max_age))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .finish()
        .to_string()
}

/// Marks a request as coming from a signed-in visitor (valid session
/// cookie), so its response is kept out of shared caches and revalidated
/// by the browser — otherwise a page served from cache never reaches
/// ProxyAuth, and the session cannot be renewed on it.
#[derive(Debug, Clone, Copy)]
pub struct SignedInVisitor;

pub fn mark_signed_in(req: &HttpRequest) {
    req.extensions_mut().insert(SignedInVisitor);
}

pub fn is_signed_in(req: &HttpRequest) -> bool {
    req.extensions().get::<SignedInVisitor>().is_some()
}

/// Queues a renewed cookie for the response to this request.
pub fn remember_renewal(req: &HttpRequest, cookie: String) {
    req.extensions_mut().insert(PendingSessionCookie(cookie));
}

/// The renewed cookie queued for this request, if any.
pub fn take_renewal_cookie(req: &HttpRequest) -> Option<String> {
    req.extensions_mut()
        .remove::<PendingSessionCookie>()
        .map(|c| c.0)
}

/// Startup summary of the renewal policy: the global one, every vhost
/// that overrides it, and settings that cannot work.
pub fn describe_policies(
    config: &crate::config::config::AppConfig,
    routes: &[RouteRule],
) -> Vec<String> {
    let lifetime = config.token_expiry_seconds.max(0) as u64;
    let describe = |p: &SessionRefreshPolicy| {
        if !p.enabled() {
            let mut text = "off (session_refresh_interval_secs = 0)".to_string();
            if p.max_lifetime_secs > 0 {
                text.push_str(&format!(", sessions end {}s after login", p.max_lifetime_secs));
            }
            return text;
        }
        let mut text = format!(
            "every {}s, previous token accepted {}s more",
            p.interval_secs, p.grace_secs
        );
        if p.max_lifetime_secs > 0 {
            text.push_str(&format!(", sessions end {}s after login", p.max_lifetime_secs));
        }
        text
    };

    let global = SessionRefreshPolicy {
        interval_secs: config.session_refresh_interval_secs,
        grace_secs: config.session_refresh_grace_secs,
        max_lifetime_secs: config.session_max_lifetime_secs,
    };
    let mut lines = vec![format!("session renewal {}", describe(&global))];

    let mut seen = std::collections::BTreeSet::new();
    for rule in routes.iter().filter(|r| r.required_login) {
        let policy = rule.resolved_session_refresh(config);
        let label = if rule.vhost.is_empty() {
            rule.prefix.clone()
        } else {
            format!("{}{}", rule.vhost.join(","), rule.prefix)
        };
        if policy != global && seen.insert(label.clone()) {
            lines.push(format!("session renewal on {label}: {}", describe(&policy)));
        }
        if policy.enabled() && policy.interval_secs >= lifetime && seen.insert(format!("warn:{label}")) {
            lines.push(format!(
                "warning: session renewal on {label} never happens: session_refresh_interval_secs ({}) is not shorter than token_expiry_seconds ({lifetime})",
                policy.interval_secs
            ));
        }
    }

    lines
}
