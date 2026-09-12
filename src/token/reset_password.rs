//! `POST /reset-password` — the endpoint the form at `page_change_password`
//! submits to. Handles both flows the same way once a token exists:
//! an admin's `proxyauth reset-password`, and the automatic redirect a
//! user gets on login when their `must_change_password` flag is set
//! (see `token::auth::maybe_force_password_change`). Neither flow needs
//! special-casing here — a valid, unexpired token is a valid, unexpired
//! token either way.

use crate::AppState;
use crate::config::config::{User, resolve_password_override, set_user_password};
use crate::network::error::render_error_page;
use crate::reset::db as reset_db;
use crate::token::auth::verify_password;
use crate::token::csrf::verify_csrf_token;
use actix_web::{
    Error as ActixError, FromRequest, HttpRequest, HttpResponse, Responder,
    dev::Payload,
    error::ErrorBadRequest,
    web::{self, Form, Json},
};
use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};
use futures_util::FutureExt;
use futures_util::future::{LocalBoxFuture, ready};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
    pub verif_password: String,
    pub csrf_token: Option<String>,
}

pub enum EitherResetPassword {
    Json(ResetPasswordRequest),
    Form(ResetPasswordRequest),
}

impl FromRequest for EitherResetPassword {
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let content_type = req
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        if content_type.contains("application/json") {
            Json::<ResetPasswordRequest>::from_request(req, payload)
                .map(|res| res.map(|json| EitherResetPassword::Json(json.into_inner())))
                .boxed_local()
        } else if content_type.contains("application/x-www-form-urlencoded") {
            Form::<ResetPasswordRequest>::from_request(req, payload)
                .map(|res| res.map(|form| EitherResetPassword::Form(form.into_inner())))
                .boxed_local()
        } else {
            ready(Err(ErrorBadRequest("Unsupported Content-Type"))).boxed_local()
        }
    }
}

fn payload_inner(payload: &EitherResetPassword) -> &ResetPasswordRequest {
    match payload {
        EitherResetPassword::Json(r) | EitherResetPassword::Form(r) => r,
    }
}

fn validate_csrf(payload: &EitherResetPassword, secret: &str) -> bool {
    match payload_inner(payload).csrf_token.as_deref() {
        Some(t) => verify_csrf_token(secret, t),
        None => false,
    }
}

pub async fn reset_password_route(
    req: HttpRequest,
    data: web::Data<AppState>,
    payload: EitherResetPassword,
) -> impl Responder {
    // CSRF is mandatory here regardless of whether the instance has
    // csrf_token enabled for the normal /auth flow — this endpoint sets
    // a new password from an unauthenticated context, there's no
    // scenario where skipping CSRF is acceptable.
    if !validate_csrf(&payload, &data.config.secret) {
        return render_error_page(&req, data.clone(), "invalid csrf request").await;
    }

    let body = payload_inner(&payload);

    if body.password != body.verif_password {
        return HttpResponse::BadRequest()
            .append_header(("server", "ProxyAuth"))
            .body("Passwords do not match");
    }

    // Not full password-strength policy (no charset/entropy checks
    // anywhere in this codebase yet) — just a floor against trivially
    // weak passwords, since this endpoint had none at all before.
    const MIN_PASSWORD_LEN: usize = 12;
    if body.password.chars().count() < MIN_PASSWORD_LEN {
        return HttpResponse::BadRequest()
            .append_header(("server", "ProxyAuth"))
            .body(format!(
                "Password must be at least {MIN_PASSWORD_LEN} characters long"
            ));
    }

    // SECURITY: validate_and_consume_token checks and deletes the token
    // atomically (single LMDB read-write transaction) — the previous
    // validate-then-consume-later split left a real race window open
    // for exactly as long as the Argon2 hashing below takes. See that
    // function's own doc comment in reset/db.rs for the full reasoning.
    let username = match reset_db::validate_and_consume_token(&body.token) {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::BadRequest()
                .append_header(("server", "ProxyAuth"))
                .body("Invalid or expired reset link");
        }
    };

    let salt = SaltString::generate(&mut OsRng);
    let hash = match Argon2::default().hash_password(body.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .append_header(("server", "ProxyAuth"))
                .body("Failed to hash password");
        }
    };

    // Try file-based storage first, then the database — a username
    // only ever lives in one of the two, and we don't know which
    // without checking (mirrors how `combined_users()` treats both as
    // equally valid sources, file-first).
    let file_updated =
        match set_user_password("/etc/proxyauth/config/config.json", &username, &hash) {
            Ok(updated) => updated,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .append_header(("server", "ProxyAuth"))
                    .body(format!("Failed to update password: {e}"));
            }
        };

    if file_updated {
        // Reflect immediately for this and every other already-running
        // worker/instance sharing this AppState — otherwise the new
        // password would only take effect after config.json is
        // re-read, i.e. never, until a restart. Mirrors
        // `otp_overrides`'s reasoning exactly.
        data.password_overrides.insert(username.clone(), hash);
        data.must_change_overrides.insert(username.clone(), false);
    } else {
        // SECURITY/CORRECTNESS: everything below is blocking Diesel
        // I/O (a DB connection attempt included) — running it directly
        // in an async handler would tie up a tokio worker thread for
        // however long a slow/unreachable database takes to time out,
        // the same failure mode that can make the whole service
        // unresponsive to SIGTERM during a DB outage. Wrapped in
        // spawn_blocking to protect concurrent requests and graceful
        // shutdown.
        let data_for_blocking = data.clone();
        let username_owned = username.clone();
        let hash_owned = hash.clone();

        let outcome = tokio::task::spawn_blocking(move || {
            persist_db_password_change(&data_for_blocking, &username_owned, &hash_owned)
        })
        .await;

        match outcome {
            Ok(PersistOutcome::Updated) => {}
            Ok(PersistOutcome::NoDatabaseConfigured) | Ok(PersistOutcome::UnknownUser) => {
                return HttpResponse::NotFound()
                    .append_header(("server", "ProxyAuth"))
                    .body("Unknown user");
            }
            Ok(PersistOutcome::Error(e)) => {
                // SECURITY: never return the raw Diesel/connection error
                // to an unauthenticated caller — it can include internal
                // hostnames, ports, and other infrastructure details.
                // Log the real detail server-side; the client only gets
                // a generic message.
                eprintln!("[reset-password] failed to update password: {e}");
                return HttpResponse::InternalServerError()
                    .append_header(("server", "ProxyAuth"))
                    .body("Internal error updating password");
            }
            Err(join_error) => {
                eprintln!("[reset-password] blocking task failed: {join_error}");
                return HttpResponse::InternalServerError()
                    .append_header(("server", "ProxyAuth"))
                    .body("Internal error updating password");
            }
        }
    }

    // Token was already consumed atomically inside validate_and_consume_token
    // above, at the point of validation — nothing left to do here.

    HttpResponse::Ok()
        .append_header(("server", "ProxyAuth"))
        .json(serde_json::json!({ "status": "ok" }))
}

/// Outcome of `persist_db_password_change`, letting the async caller
/// build the right HTTP response without itself doing any blocking
/// I/O — see the `spawn_blocking` call site above for why this is
/// split out.
enum PersistOutcome {
    Updated,
    NoDatabaseConfigured,
    UnknownUser,
    /// Covers both "couldn't connect" and "connected but the query
    /// failed" — the caller treats both identically (a generic 500,
    /// with the real detail only logged server-side), and
    /// `with_connection` doesn't preserve that distinction past its
    /// own boundary anyway (see its doc comment).
    Error(String),
}

/// The database branch of setting a new password — connect, ensure the
/// schema, write the new hash, and reflect it into the in-memory
/// `db_users` snapshot immediately (same reasoning as the file-based
/// branch's overlay inserts: don't wait for the next scan tick).
/// Entirely blocking (real Diesel I/O) — always call this through
/// `tokio::task::spawn_blocking`, never directly from an async context.
fn persist_db_password_change(data: &AppState, username: &str, hash: &str) -> PersistOutcome {
    let Some(db_cfg) = &data.config.databases else {
        return PersistOutcome::NoDatabaseConfigured;
    };

    let result = crate::databases::db::with_connection(db_cfg, |conn| {
        crate::databases::db::ensure_schema(conn)?;
        crate::databases::db::update_password(conn, username, hash)
    });

    match result {
        Ok(true) => {
            // Best-effort re-read to refresh the in-memory snapshot;
            // this one specifically goes through with_connection too,
            // reusing the same shared connection rather than opening
            // another one just for this follow-up read.
            if let Ok(Some(updated_user)) = crate::databases::db::with_connection(db_cfg, |conn| {
                crate::databases::db::load_user_by_username(conn, username)
            }) {
                data.config.upsert_db_user_now(updated_user);
            }
            PersistOutcome::Updated
        }
        Ok(false) => PersistOutcome::UnknownUser,
        Err(e) => PersistOutcome::Error(e),
    }
}

/// Kept here for reuse by both the CLI (`reset-password`) and the
/// forced first-login redirect (`token::auth`) — resolves whichever
/// email address is on file for `username`, if any, using the same
/// file-or-database lookup order as the rest of the reset flow.
/// Resolves which email to actually use for `username` — the entry
/// explicitly marked `primary`, if any; otherwise falls back to the
/// first one on file (covers data that predates the explicit flag, or
/// simply has none marked). Never picks a *second* primary entry over
/// the first — `db-add-user`/config.json are expected to keep at most
/// one `primary: true` per user, but this stays deterministic even if
/// that's violated.
pub fn find_user_email(users: &[User], username: &str) -> Option<String> {
    let emails = users
        .iter()
        .find(|u| u.username == username)
        .and_then(|u| u.email.as_ref())?;

    emails
        .iter()
        .find(|e| e.primary)
        .or_else(|| emails.first())
        .map(|e| e.address.clone())
}

/// Unused directly by the route above (kept for symmetry / potential
/// future direct-password-check use cases, e.g. requiring the old
/// password too) — verifies a plaintext password against a stored
/// Argon2 hash, resolving any live override first.
#[allow(dead_code)]
pub fn verify_current_password(state: &AppState, user: &User, plaintext: &str) -> bool {
    let hash = resolve_password_override(state, &user.username, &user.password);
    verify_password(plaintext, &hash)
}
