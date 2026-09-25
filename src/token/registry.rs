//! `POST /auth/registry` — self-service account creation (username,
//! password, email).
//!
//! Enabled per vhost in `routes.yml`, through a `registry:` block on a
//! route or (usually) on a `vhosts:` group:
//!
//! ```yaml
//! vhosts:
//!   - vhost: ["app.example.com"]
//!     allow_groups: ["members"]      # so new accounts can actually log in
//!     registry:
//!       enabled: true
//!       default_groups: ["members"]
//!       default_roles: ["reader"]
//!       redirect_url: "/login?registered=1"   # optional, form posts only
//!     routes:
//!       - prefix: "/"
//!         target: "http://127.0.0.1:8080"
//! ```
//!
//! The groups/roles an account gets come **only** from that block —
//! the request body carries username/password/email and nothing else,
//! so nobody can register themselves into `admins`.
//!
//! Accounts are always written to the `databases` backend. `config.json`
//! is not an option here: file-based users are an immutable snapshot
//! loaded once at startup, and issued tokens embed a user's *index* in
//! `AppConfig::combined_users()` (file users first, then database users)
//! — inserting a file user at runtime would shift every database user's
//! index and break (or worse, cross-wire) every session already issued.
//! Database users, on the other hand, are append-only in memory
//! (`AppConfig::upsert_db_user_now`), which is exactly what's needed.

use crate::AppConfig;
use crate::AppState;
use crate::config::config::{EmailEntry, RouteRule, User};
use crate::databases::db::NewUserOutcome;
use crate::network::error::render_error_page;
use crate::network::proxy::client_ip;
use crate::token::csrf::verify_csrf_token;
use actix_web::{
    Error as ActixError, FromRequest, HttpRequest, HttpResponse, Responder,
    dev::Payload,
    error::ErrorBadRequest,
    web::{self, Form, Json},
};
use argon2::Argon2;
use argon2::password_hash::PasswordHasher;
use futures_util::FutureExt;
use futures_util::future::{LocalBoxFuture, ready};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

/// Same floor as `/reset-password` — see `token::reset_password`.
pub const MIN_PASSWORD_LEN: usize = 12;
/// Argon2 cost is per input byte hashed; without a ceiling a single
/// request with a multi-megabyte "password" would pin a worker.
pub const MAX_PASSWORD_LEN: usize = 1024;
pub const MIN_USERNAME_LEN: usize = 3;
pub const MAX_USERNAME_LEN: usize = 64;
pub const MAX_EMAIL_LEN: usize = 254;

// ── Configuration ──────────────────────────────────────────────

/// The `registry:` block of a route / `vhosts:` group in `routes.yml`.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
pub struct RegistryConfig {
    /// Must be `true` for `/auth/registry` to accept anything on this
    /// vhost. Off by default even when the block is present: opening
    /// public sign-up should always be a line someone wrote on purpose.
    #[serde(default)]
    pub enabled: bool,

    /// Groups every new account is placed in (created in the `groups`
    /// table on first use). Pair with the vhost's `allow_groups` —
    /// otherwise the account exists but `login_authorized` refuses it.
    #[serde(default)]
    pub default_groups: Vec<String>,

    /// Roles every new account receives (forwarded to backends as
    /// `X-User-Roles`, and usable in `allow_roles`).
    #[serde(default)]
    pub default_roles: Vec<String>,

    /// Where to send the browser (`303 See Other`) after a successful
    /// *form* submission. JSON callers always get `201` + a JSON body.
    /// Unset: form submissions get the JSON body too.
    #[serde(default)]
    pub redirect_url: Option<String>,
}

fn non_empty(list: &[String]) -> Option<Vec<String>> {
    let cleaned: Vec<String> = list
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cleaned.is_empty() { None } else { Some(cleaned) }
}

impl RegistryConfig {
    pub fn default_groups_opt(&self) -> Option<Vec<String>> {
        non_empty(&self.default_groups)
    }

    pub fn default_roles_opt(&self) -> Option<Vec<String>> {
        non_empty(&self.default_roles)
    }
}

/// Picks the route whose `registry` block applies to a request for
/// `host`: exact vhost match first, then wildcard vhost, then a
/// catch-all route (empty `vhost`) — same exact-before-wildcard
/// precedence as `network::proxy::find_vhost_route`, plus the catch-all
/// fallback so single-host setups without any `vhost:` work too.
///
/// Only routes that actually carry a `registry` block are considered,
/// so the block can sit on any route of the vhost, not only the first.
pub fn find_registry_route<'a>(host: Option<&str>, routes: &'a [RouteRule]) -> Option<&'a RouteRule> {
    use crate::network::proxy::{vhost_matches, vhost_matches_exactly};

    let with_block = || routes.iter().filter(|r| r.registry.is_some());

    with_block()
        .find(|r| vhost_matches_exactly(host, &r.vhost))
        .or_else(|| with_block().find(|r| !r.vhost.is_empty() && vhost_matches(host, &r.vhost)))
        .or_else(|| with_block().find(|r| r.vhost.is_empty()))
}

/// Startup summary, printed by `main.rs` next to the session policies:
/// one line per vhost with registration enabled, plus a warning for
/// every misconfiguration that would silently make it useless.
pub fn describe_registry(config: &AppConfig, routes: &[RouteRule]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for r in routes {
        let Some(reg) = &r.registry else { continue };
        let label = if r.vhost.is_empty() {
            "*".to_string()
        } else {
            r.vhost.join(",")
        };
        if seen.contains(&label) {
            continue;
        }
        seen.push(label.clone());

        if !reg.enabled {
            lines.push(format!(
                "[registry] {label}: `registry` block present but `enabled` is not true — /auth/registry stays disabled"
            ));
            continue;
        }

        lines.push(format!(
            "[registry] {label}: /auth/registry enabled (default_groups: {:?}, default_roles: {:?})",
            reg.default_groups, reg.default_roles
        ));

        if config.databases.is_none() {
            lines.push(format!(
                "[registry] {label}: WARNING no `databases` block in config.json — every registration will be refused (503)"
            ));
        }
        if !config.blakegate.is_empty() {
            lines.push(format!(
                "[registry] {label}: WARNING Blakegate backup mode is active — every registration will be refused (503), Blakegate owns the user list"
            ));
        }

        // A vhost with an empty allow list denies every login (see
        // `RouteRule::login_authorized`), and one whose allow lists
        // don't include the defaults denies these accounts specifically.
        if !r.vhost.is_empty() {
            let groups_ok = reg.default_groups.iter().any(|g| r.allow_groups.contains(g));
            let roles_ok = reg.default_roles.iter().any(|x| r.allow_roles.contains(x));
            if !groups_ok && !roles_ok {
                lines.push(format!(
                    "[registry] {label}: WARNING none of default_groups/default_roles appear in this vhost's allow_groups/allow_roles — new accounts will be refused at login"
                ));
            }
        }
    }
    lines
}

// ── Request payload ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegistryRequest {
    pub username: String,
    pub password: String,
    /// Optional confirmation field; when present it must match.
    #[serde(default)]
    pub verif_password: Option<String>,
    pub email: String,
    #[serde(default)]
    pub csrf_token: Option<String>,
}

pub enum EitherRegistry {
    Json(RegistryRequest),
    Form(RegistryRequest),
}

impl EitherRegistry {
    fn inner(&self) -> &RegistryRequest {
        match self {
            EitherRegistry::Json(r) | EitherRegistry::Form(r) => r,
        }
    }

    fn is_form(&self) -> bool {
        matches!(self, EitherRegistry::Form(_))
    }
}

impl FromRequest for EitherRegistry {
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
            Json::<RegistryRequest>::from_request(req, payload)
                .map(|res| res.map(|json| EitherRegistry::Json(json.into_inner())))
                .boxed_local()
        } else if content_type.contains("application/x-www-form-urlencoded") {
            Form::<RegistryRequest>::from_request(req, payload)
                .map(|res| res.map(|form| EitherRegistry::Form(form.into_inner())))
                .boxed_local()
        } else {
            ready(Err(ErrorBadRequest("Unsupported Content-Type"))).boxed_local()
        }
    }
}

// ── Input validation ───────────────────────────────────────────

/// 3–64 characters, ASCII letters/digits plus `.`, `_`, `-`, starting
/// with a letter or digit. Deliberately narrow: usernames end up in
/// `X-User` headers, log lines and URLs, and look-alike Unicode
/// usernames are a classic impersonation trick.
pub fn validate_username(username: &str) -> Result<(), String> {
    let len = username.chars().count();
    if !(MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&len) {
        return Err(format!(
            "Username must be between {MIN_USERNAME_LEN} and {MAX_USERNAME_LEN} characters long"
        ));
    }
    let mut chars = username.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphanumeric()) {
        return Err("Username must start with a letter or a digit".into());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("Username may only contain letters, digits, '.', '_' and '-'".into());
    }
    Ok(())
}

/// Structural check only (no DNS/MX lookup, no confirmation mail):
/// one `@`, a non-empty local part of at most 64 bytes, a dotted
/// domain, no whitespace or characters that would need quoting.
pub fn validate_email(email: &str) -> Result<(), String> {
    let invalid = || Err("Invalid email address".to_string());

    if email.is_empty() || email.len() > MAX_EMAIL_LEN {
        return invalid();
    }
    if email
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || "<>()[],;:\\\"".contains(c))
    {
        return invalid();
    }
    let Some((local, domain)) = email.split_once('@') else {
        return invalid();
    };
    if local.is_empty() || local.len() > 64 || domain.contains('@') {
        return invalid();
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return invalid();
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        return invalid();
    }
    Ok(())
}

pub fn validate_password(password: &str, confirmation: Option<&str>) -> Result<(), String> {
    if let Some(c) = confirmation {
        if c != password {
            return Err("Passwords do not match".into());
        }
    }
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return Err(format!(
            "Password must be at least {MIN_PASSWORD_LEN} characters long"
        ));
    }
    if len > MAX_PASSWORD_LEN {
        return Err(format!(
            "Password must be at most {MAX_PASSWORD_LEN} characters long"
        ));
    }
    Ok(())
}

/// Builds the account exactly as it will be stored — the only place
/// groups/roles come from is `reg`, never the request.
pub fn build_new_user(
    username: &str,
    password_hash: String,
    email: &str,
    reg: &RegistryConfig,
) -> User {
    User {
        username: username.to_string(),
        password: password_hash,
        otpkey: None,
        allow: None,
        roles: reg.default_roles_opt(),
        groups: reg.default_groups_opt(),
        email: Some(vec![EmailEntry {
            address: email.to_string(),
            primary: true,
        }]),
        must_change_password: false,
    }
}

/// Username/email collision against accounts already known in memory —
/// crucially the `config.json` users, which the database insert can't
/// see at all. Case-insensitive, like the database check.
fn collides_in_memory(config: &AppConfig, username: &str, email: &str) -> bool {
    config.combined_users().iter().any(|u| {
        u.username.eq_ignore_ascii_case(username)
            || u.email
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|e| e.address.eq_ignore_ascii_case(email))
    })
}

// ── Handler ────────────────────────────────────────────────────

fn plain(status: actix_web::http::StatusCode, body: impl Into<String>) -> HttpResponse {
    HttpResponse::build(status)
        .append_header(("server", "ProxyAuth"))
        .body(body.into())
}

fn conflict() -> HttpResponse {
    // Same message for a taken username and a taken email: telling
    // them apart would turn this endpoint into an email-enumeration
    // oracle for every address on file.
    plain(
        actix_web::http::StatusCode::CONFLICT,
        "Username or email already in use",
    )
}

enum StoreOutcome {
    Stored(NewUserOutcome),
    Error(String),
}

/// Hashing + database write + in-memory refresh. Entirely blocking
/// (Argon2 and Diesel) — always run through `spawn_blocking`, same
/// reasoning as `reset_password::persist_db_password_change`.
fn store_new_user(data: &AppState, username: &str, password: &str, email: &str, reg: &RegistryConfig) -> StoreOutcome {
    let Some(db_cfg) = &data.config.databases else {
        return StoreOutcome::Error("no databases block".into());
    };

    let hash = match Argon2::default().hash_password(password.as_bytes()) {
        Ok(h) => h.to_string(),
        Err(e) => return StoreOutcome::Error(format!("password hashing failed: {e}")),
    };

    let user = build_new_user(username, hash, email, reg);

    let result = crate::databases::db::with_connection(db_cfg, |conn| {
        crate::databases::db::ensure_schema(conn)?;
        crate::databases::db::insert_new_user(conn, &user)
    });

    match result {
        Ok(NewUserOutcome::Created) => {
            // Make the account usable right away on this instance
            // (other instances pick it up on their next incremental
            // scan). Prefer the row as re-read from the database; fall
            // back to what we just wrote.
            let fresh = crate::databases::db::with_connection(db_cfg, |conn| {
                crate::databases::db::load_user_by_username(conn, username)
            })
            .ok()
            .flatten()
            .unwrap_or(user);
            data.config.upsert_db_user_now(fresh);
            data.config.bump_generation();
            StoreOutcome::Stored(NewUserOutcome::Created)
        }
        Ok(other) => StoreOutcome::Stored(other),
        Err(e) => StoreOutcome::Error(e),
    }
}

pub async fn registry_route(
    req: HttpRequest,
    data: web::Data<AppState>,
    payload: EitherRegistry,
) -> impl Responder {
    use actix_web::http::StatusCode;

    let host = crate::network::proxy::request_host(&req);
    let Some(route) = find_registry_route(host.as_deref(), &data.routes.routes) else {
        return plain(StatusCode::NOT_FOUND, "Not Found");
    };
    let Some(reg) = route.registry.clone().filter(|r| r.enabled) else {
        return plain(StatusCode::NOT_FOUND, "Not Found");
    };

    // Same CSRF rule as the login form of this vhost: required whenever
    // CSRF is enabled for it (its own `csrf_token`, else the global one).
    if route.csrf_enabled(&data.config) {
        let ok = payload
            .inner()
            .csrf_token
            .as_deref()
            .is_some_and(|t| verify_csrf_token(&data.config.secret, t));
        if !ok {
            // A browser form gets the vhost's usual error page; an API
            // client gets an unambiguous 403 rather than an HTML page
            // that `render_error_page` may serve with a 200.
            if payload.is_form() {
                return render_error_page(&req, data.clone(), "invalid csrf request").await;
            }
            return plain(StatusCode::FORBIDDEN, "invalid csrf request");
        }
    }

    if data.config.databases.is_none() {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "Account registration requires a database backend",
        );
    }
    if data.config.blakegate_backup_mode_active() {
        // The next `users_sync` push is authoritative and would revoke
        // any account created locally — refuse rather than hand out an
        // account that silently disappears minutes later.
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "Account registration is unavailable on this instance",
        );
    }

    let is_form = payload.is_form();
    let body = payload.inner();
    let username = body.username.trim().to_string();
    let email = body.email.trim().to_string();

    if let Err(msg) = validate_username(&username) {
        return plain(StatusCode::BAD_REQUEST, msg);
    }
    if let Err(msg) = validate_email(&email) {
        return plain(StatusCode::BAD_REQUEST, msg);
    }
    if let Err(msg) = validate_password(&body.password, body.verif_password.as_deref()) {
        return plain(StatusCode::BAD_REQUEST, msg);
    }

    if collides_in_memory(&data.config, &username, &email) {
        return conflict();
    }

    let ip = client_ip(&req, &data.config)
        .map(|i| i.to_string())
        .unwrap_or_else(|| "-".to_string());

    let data_blocking = data.clone();
    let (u, p, e, r) = (username.clone(), body.password.clone(), email.clone(), reg.clone());
    let outcome =
        tokio::task::spawn_blocking(move || store_new_user(&data_blocking, &u, &p, &e, &r)).await;

    match outcome {
        Ok(StoreOutcome::Stored(NewUserOutcome::Created)) => {
            info!(
                "[{}] [registry] account '{}' created (groups: {:?}, roles: {:?})",
                ip, username, reg.default_groups, reg.default_roles
            );
            if is_form {
                if let Some(target) = reg.redirect_url.as_deref() {
                    return HttpResponse::SeeOther()
                        .append_header(("server", "ProxyAuth"))
                        .append_header(("location", target))
                        .finish();
                }
            }
            HttpResponse::Created()
                .append_header(("server", "ProxyAuth"))
                .json(serde_json::json!({
                    "status": "created",
                    "username": username,
                }))
        }
        Ok(StoreOutcome::Stored(_)) => {
            warn!("[{}] [registry] refused: username or email already in use", ip);
            conflict()
        }
        Ok(StoreOutcome::Error(e)) => {
            // SECURITY: never echo Diesel/connection errors to an
            // unauthenticated caller (hostnames, ports, schema names).
            error!("[registry] failed to create account: {e}");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "Internal error creating account")
        }
        Err(join_error) => {
            error!("[registry] blocking task failed: {join_error}");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "Internal error creating account")
        }
    }
}
