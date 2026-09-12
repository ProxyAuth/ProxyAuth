use crate::AppState;
use crate::adm::method_otp::{generate_base32_secret, generate_otpauth_uri};
use crate::adm::stats::is_valid_admin_token;
use crate::config::config::{add_otpkey, clear_otpkey, resolve_otpkey};
use crate::token::auth::{is_ip_allowed, verify_credentials_constant_time};
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, Responder, http::header, web};
use serde::{Deserialize, Serialize};
use totp_rs::Algorithm;
use tracing::warn;

/// Clears `username`'s TOTP secret wherever they're actually stored —
/// tries `config.json` first, and falls back to the database if the
/// user isn't a file-based account, mirroring
/// `token::reset_password`'s exact file-then-database precedence
/// (and for the same reason: `config::config::clear_otpkey` only ever
/// knows about `config.json`, so a database-backed account — anyone
/// added via `db-add-user` rather than hand-edited into the file —
/// would otherwise fail here with "not found in the configuration
/// file" even though the account is real and its otpkey genuinely
/// needs clearing). Also updates whichever in-memory snapshot is
/// relevant (`otp_overrides` for the file case, the `db_users`
/// overlay for the database case) so the change is visible to every
/// worker immediately rather than after the next restart or scan
/// tick — the same reasoning `reset_otp_route` already applied to the
/// file case alone.
async fn clear_otpkey_anywhere(data: &web::Data<AppState>, username: &str) -> Result<(), String> {
    match clear_otpkey("/etc/proxyauth/config/config.json", username) {
        Ok(_) => {
            data.otp_overrides.insert(username.to_string(), None);
            return Ok(());
        }
        Err(e) if e.contains("not found in the configuration file") => {
            // Not a file-based account — fall through to the database
            // branch below rather than treating this as a real error.
        }
        Err(e) => return Err(e),
    }

    let Some(db_cfg) = data.config.databases.clone() else {
        return Err(format!(
            "User '{username}' not found in the configuration file, and no database is configured — nowhere left to look."
        ));
    };

    // Blocking Diesel I/O — never run directly on an async worker
    // thread, same reasoning as token::reset_password's own
    // persist_db_password_change.
    let username_owned = username.to_string();
    let outcome = tokio::task::spawn_blocking(move || {
        crate::databases::db::with_connection(&db_cfg, |conn| {
            crate::databases::db::ensure_schema(conn)?;
            crate::databases::db::update_otpkey(conn, &username_owned, None)
        })
    })
    .await
    .map_err(|join_err| format!("Internal error clearing database otpkey: {join_err}"))?;

    match outcome {
        Ok(true) => {
            // Refresh the in-memory db_users snapshot for this one
            // user immediately, same as persist_db_password_change
            // does after a successful password write.
            let db_cfg_for_reread = data.config.databases.clone();
            if let Some(db_cfg) = db_cfg_for_reread {
                let username_for_reread = username.to_string();
                if let Ok(Ok(Some(updated_user))) = tokio::task::spawn_blocking(move || {
                    crate::databases::db::with_connection(&db_cfg, |conn| {
                        crate::databases::db::load_user_by_username(conn, &username_for_reread)
                    })
                })
                .await
                {
                    data.config.upsert_db_user_now(updated_user);
                }
            }
            // Also patches the LMDB fallback cache — otherwise a
            // database outage between now and the next full refresh
            // would fall back to the OLD otpkey, silently
            // reintroducing what was just cleared. Best-effort, only
            // logged on failure — the real database write already
            // succeeded, so this doesn't change the outcome reported
            // to the caller either way.
            if let Err(e) = crate::databases::cache::patch_otpkey(username, None) {
                warn!("Failed to patch LMDB fallback cache after clearing otpkey for {username}: {e}");
            }
            Ok(())
        }
        Ok(false) => Err(format!("User '{username}' not found in the configuration file or the database.")),
        Err(e) => Err(format!("Database error clearing otpkey: {e}")),
    }
}

/// Provisions a brand-new TOTP secret for `username`, wherever
/// they're actually stored — file-based accounts first (via
/// `config::config::add_otpkey`, whose internally-generated secret
/// only ever lands in the config file it just wrote, so reading it
/// back is the only way to retrieve it), falling back to a
/// database-backed account if the file doesn't have this user at all.
/// Without this fallback, first-time enrollment itself — not just
/// `allow_totp_reenroll`'s re-enrollment path — silently fails for
/// any database-backed account, the exact same class of gap
/// `clear_otpkey_anywhere` fixes for clearing. Returns the new secret
/// on success, and updates whichever in-memory overlay is relevant,
/// same reasoning as `clear_otpkey_anywhere`.
async fn add_otpkey_anywhere(data: &web::Data<AppState>, username: &str) -> Result<String, String> {
    if let Err(e) = add_otpkey("/etc/proxyauth/config/config.json", username) {
        // Not necessarily fatal here — "user not found in the file" is
        // the expected, normal case for a database-backed account, and
        // the file-re-read fallback below (then the database branch
        // further down) already handles that correctly either way.
        // Logged so a *genuine* failure (unreadable/malformed
        // config.json) is still visible somewhere, now that it no
        // longer panics loudly the way it used to.
        tracing::debug!("add_otpkey (file): {e}");
    }

    if let Ok(config_str) = std::fs::read_to_string("/etc/proxyauth/config/config.json") {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&config_str) {
            let otpkey = json
                .get("users")
                .and_then(|users| users.as_array())
                .and_then(|users| {
                    users
                        .iter()
                        .find(|u| u.get("username").and_then(|n| n.as_str()) == Some(username))
                })
                .and_then(|u| u.get("otpkey").and_then(|v| v.as_str()))
                .map(|s| s.to_string());
            if let Some(secret) = otpkey {
                data.otp_overrides
                    .insert(username.to_string(), Some(secret.clone()));
                return Ok(secret);
            }
        }
    }

    // Not a file-based account (or the file-based attempt otherwise
    // came up empty) — try the database instead.
    let Some(db_cfg) = data.config.databases.clone() else {
        return Err(format!(
            "User '{username}' not found in the configuration file, and no database is configured — nowhere left to provision an OTP key."
        ));
    };

    let secret = generate_base32_secret(32);
    let username_owned = username.to_string();
    let secret_owned = secret.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        crate::databases::db::with_connection(&db_cfg, |conn| {
            crate::databases::db::ensure_schema(conn)?;
            crate::databases::db::update_otpkey(conn, &username_owned, Some(&secret_owned))
        })
    })
    .await
    .map_err(|join_err| format!("Internal error provisioning database otpkey: {join_err}"))?;

    match outcome {
        Ok(true) => {
            let db_cfg_for_reread = data.config.databases.clone();
            if let Some(db_cfg) = db_cfg_for_reread {
                let username_for_reread = username.to_string();
                if let Ok(Ok(Some(updated_user))) = tokio::task::spawn_blocking(move || {
                    crate::databases::db::with_connection(&db_cfg, |conn| {
                        crate::databases::db::load_user_by_username(conn, &username_for_reread)
                    })
                })
                .await
                {
                    data.config.upsert_db_user_now(updated_user);
                }
            }
            // Same reasoning as clear_otpkey_anywhere's own patch call
            // — keeps the LMDB fallback cache from handing back a
            // stale (here: the pre-enrollment, nonexistent) secret if
            // the database goes unreachable before the next full
            // refresh.
            if let Err(e) = crate::databases::cache::patch_otpkey(username, Some(&secret)) {
                warn!("Failed to patch LMDB fallback cache after provisioning otpkey for {username}: {e}");
            }
            Ok(secret)
        }
        Ok(false) => Err(format!(
            "User '{username}' not found in the configuration file or the database."
        )),
        Err(e) => Err(format!("Database error provisioning otpkey: {e}")),
    }
}

#[derive(Deserialize)]
pub struct OtpRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct OtpAuthUriResponse {
    pub otpauth_uri: String,
    pub otpkey: String,
}

pub async fn get_otpauth_uri_option(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> impl actix_web::Responder {
    let origin_header = req.headers().get(header::ORIGIN);
    let origin = origin_header.and_then(|v| v.to_str().ok());

    let allowed = data.config.cors_origins.as_ref();

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

pub async fn get_otpauth_uri(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> impl Responder {
    let ip = req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());

    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let auth: OtpRequest = if content_type.contains("application/json") {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return HttpResponse::BadRequest().body("Invalid JSON"),
        }
    } else if content_type.contains("x-www-form-urlencoded") {
        match serde_urlencoded::from_bytes(&body) {
            Ok(v) => v,
            Err(_) => return HttpResponse::BadRequest().body("Invalid form data"),
        }
    } else {
        return HttpResponse::UnsupportedMediaType().body("Unsupported content type");
    };

    // SECURITY: was `.find(|u| u.username == auth.username &&
    // verify_password(...))`, which short-circuits on the username check
    // and skips the expensive Argon2 verification entirely for unknown
    // usernames, leaking account existence through response timing (same
    // issue and same fix as token/auth.rs's login handler).
    let combined_users = data.config.combined_users();
    let user = verify_credentials_constant_time(&combined_users, &auth.username, &auth.password);

    if user.is_none() {
        return HttpResponse::Unauthorized().body("Invalid username or password");
    }

    let user = user.unwrap();

    if !is_ip_allowed(&ip, user) {
        warn!(
            "[{}] Access denied: IP not allowed for user {}",
            ip, user.username
        );
        return HttpResponse::Forbidden()
            .append_header(("server", "ProxyAuth"))
            .body("Access denied");
    }

    // SECURITY: this endpoint must only ever hand out the TOTP secret ONCE,
    // at first enrollment. Re-disclosing an already-provisioned secret to
    // anyone who merely supplies the account password would collapse 2FA
    // back down to a single factor (password alone becomes sufficient to
    // obtain the second factor too). If the user already has an otpkey,
    // refuse instead of returning it again — UNLESS this vhost has
    // explicitly opted into self-service re-enrollment via
    // `allow_totp_reenroll` (see that field's own doc comment for the
    // security trade-off this represents). In that case, clear the old
    // key exactly the way an admin's `/adm/auth/totp/reset` would, then
    // fall through to the normal first-enrollment path below to
    // provision a fresh one.
    //
    // BUG FIXED HERE: this used to check `user.otpkey.is_some()`
    // directly — `user` comes from `combined_users()`, which is a
    // snapshot from server startup and knows nothing about
    // `otp_overrides`. Any enrollment or reset that happened *after*
    // startup (i.e. basically every real one, since this same
    // endpoint is how enrollment happens) was invisible to that
    // check: a user who'd already enrolled via this very endpoint
    // would still read as `otpkey: None` here, so `allow_totp_reenroll`
    // never even got consulted, and add_otpkey()'s own internal guard
    // silently no-opped on the real, already-existing key — meaning
    // re-enrollment "worked" (200 OK) but silently kept handing back
    // the SAME old secret every time, no error, no actual re-enrollment.
    // `resolve_otpkey` — the same overlay-aware resolution login
    // validation itself uses — is the fix.
    let current_otpkey = resolve_otpkey(&data, &auth.username, user.otpkey.as_deref());
    if current_otpkey.is_some() {
        let vhost_route = crate::network::proxy::find_vhost_route(
            crate::network::proxy::request_host(&req).as_deref(),
            &data.routes.routes,
        );
        let reenroll_allowed = vhost_route
            .map(|r| r.totp_reenroll_allowed())
            .unwrap_or(false);

        if reenroll_allowed {
            match clear_otpkey_anywhere(&data, &auth.username).await {
                Ok(()) => {
                    warn!(
                        "[{}] Self-service OTP re-enrollment for user {} (allow_totp_reenroll is on for this vhost)",
                        ip, auth.username
                    );
                    // Falls through to the normal enrollment path below,
                    // now via add_otpkey_anywhere — file-based and
                    // database-backed accounts alike correctly get a
                    // fresh secret from there regardless of which one
                    // this account actually is.
                }
                Err(e) => {
                    warn!(
                        "[{}] Failed to clear OTP key for self-service re-enrollment of {}: {}",
                        ip, auth.username, e
                    );
                    return HttpResponse::InternalServerError().body("OTP re-enrollment failed");
                }
            }
        } else {
            warn!(
                "[{}] Rejected OTP re-disclosure attempt for user {} (already enrolled)",
                ip, user.username
            );
            return HttpResponse::Conflict().body(
                "OTP is already enrolled for this account. Ask an administrator to reset it \
if you need to re-provision your authenticator app.",
            );
        }
    }

    match add_otpkey_anywhere(&data, &user.username).await {
        Ok(secret) => {
            let uri = generate_otpauth_uri(
                &auth.username,
                "ProxyAuth",
                &secret,
                Algorithm::SHA512,
                6,
                30,
            );

            cors_response(HttpResponse::Ok(), &req).json(OtpAuthUriResponse {
                otpauth_uri: uri,
                otpkey: secret,
            })
        }
        Err(e) => {
            warn!("Failed to provision OTP key for {}: {e}", user.username);
            HttpResponse::InternalServerError().body("OTP generation failed")
        }
    }
}

#[derive(Deserialize)]
pub struct OtpResetRequest {
    pub username: String,
}

/// Admin-only: clears a user's TOTP secret so they can re-enroll from
/// scratch via `/adm/auth/totp/get`. This is the mechanism the 409
/// response in `get_otpauth_uri` refers to when it says "ask an
/// administrator to reset it" — without this route that message was a
/// dead end and the only way to unstick a user was to hand-edit
/// config.json on the server.
///
/// Protected by the admin token (`X-Auth-Token`), checked with the same
/// constant-time comparison used by `/adm/revoke` and `/adm/logs`.
pub async fn reset_otp_route(
    req: HttpRequest,
    data: web::Data<AppState>,
    body: web::Json<OtpResetRequest>,
) -> impl Responder {
    if !is_valid_admin_token(&req, &data) {
        return HttpResponse::Unauthorized().body("Invalid or missing token");
    }

    match clear_otpkey_anywhere(&data, &body.username).await {
        Ok(()) => {
            warn!("OTP key reset for user {} by admin request", body.username);
            HttpResponse::Ok().body(format!(
                "OTP key cleared for '{}'. They can now re-enroll via /adm/auth/totp/get.",
                body.username
            ))
        }
        Err(e) => {
            warn!("Failed to reset OTP key for {}: {}", body.username, e);
            HttpResponse::InternalServerError().body("Failed to reset OTP key")
        }
    }
}
