use crate::AppConfig;
use crate::AppState;
use crate::config::config::{AuthRequest, RouteRule, User};
use crate::network::error::render_error_page;
use crate::network::proxy::client_ip;
use crate::token::csrf::verify_csrf_token;
use crate::token::security::{issue_token, validate_token};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{
    Error as ActixError, FromRequest, HttpRequest, HttpResponse, Responder,
    dev::Payload,
    error::ErrorBadRequest,
    http::{StatusCode, header},
    web::{self, Form, Json},
};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use blake3;
use chrono::{DateTime, Duration, TimeZone, Utc};
use chrono_tz::Tz;
use futures_util::FutureExt;
use futures_util::future::{LocalBoxFuture, ready};
use hex;
use ipnet::IpNet;
use rand::seq::IndexedRandom;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use totp_rs::{Algorithm, TOTP};
use tracing::{error, info, warn};

pub enum EitherAuth {
    Json(AuthRequest),
    Form(AuthRequest),
}

impl FromRequest for EitherAuth {
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
            Json::<AuthRequest>::from_request(req, payload)
                .map(|res| res.map(|json| EitherAuth::Json(json.into_inner())))
                .boxed_local()
        } else if content_type.contains("application/x-www-form-urlencoded") {
            Form::<AuthRequest>::from_request(req, payload)
                .map(|res| res.map(|form| EitherAuth::Form(form.into_inner())))
                .boxed_local()
        } else {
            ready(Err(ErrorBadRequest("Unsupported Content-Type"))).boxed_local()
        }
    }
}

pub fn validate_csrf(req: &HttpRequest, payload: &EitherAuth, secret: &str) -> bool {
    let m = req.method();
    if matches!(
        m,
        &actix_web::http::Method::GET
            | &actix_web::http::Method::HEAD
            | &actix_web::http::Method::OPTIONS
    ) {
        return true;
    }

    let t_opt = match *payload {
        EitherAuth::Json(ref j) => j.csrf_token.as_deref(),
        EitherAuth::Form(ref f) => f.csrf_token.as_deref(),
    };

    if let Some(t) = t_opt {
        return verify_csrf_token(secret, t);
    }

    false
}

pub fn is_ip_allowed(ip_str: &str, user: &User) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };

    match &user.allow {
        None => true,
        Some(list) if list.is_empty() => true,
        Some(list) => list.iter().any(|net_str| {
            net_str
                .parse::<IpNet>()
                .map_or(false, |net| net.contains(&ip))
        }),
    }
}

pub fn verify_password(input: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(input.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A syntactically valid Argon2id hash with no correspondence to any real
/// account password. Computed once (lazily, at the same cost as hashing a
/// real user's password) and cached for the life of the process.
///
/// SECURITY: used to verify against *something* with the same Argon2 cost
/// even when the supplied username doesn't match any account, so that
/// login response time doesn't reveal which usernames exist. Without this,
/// `verify_password` (expensive) only ran for known usernames, giving an
/// attacker a timing oracle for username enumeration.
pub fn dummy_password_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        Argon2::default()
            .hash_password(b"proxyauth-constant-time-placeholder", &salt)
            .map(|h| h.to_string())
            // Fallback (should never trigger): a fixed, syntactically
            // valid Argon2id PHC hash, still forces real Argon2 work on
            // verification even if it can't be generated at runtime.
            .unwrap_or_else(|_| {
                "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$\
3lJ8m5vRHkNfhVn8wq6qF7z0h9k0m3qkQeQwzE9pM4"
                    .to_string()
            })
    })
}

/// Runs an Argon2 verification against either the matched user's real
/// password hash, or the dummy hash if no user matched — always doing the
/// same amount of expensive work either way. Returns `true` only if a
/// user actually matched *and* the password was correct.
///
/// SECURITY: replaces the old `user.username == auth.username &&
/// verify_password(...)` short-circuit pattern, which skipped the
/// expensive Argon2 check entirely for unknown usernames and thereby leaked
/// account existence through response timing.
pub fn verify_credentials_constant_time<'a>(
    users: &'a [User],
    username: &str,
    password: &str,
) -> Option<&'a User> {
    match users.iter().find(|u| u.username == username) {
        Some(user) => {
            if verify_password(password, &user.password) {
                Some(user)
            } else {
                None
            }
        }
        None => {
            // Burn the same Argon2 cost as a real check; result discarded.
            let _ = verify_password(password, dummy_password_hash());
            None
        }
    }
}

/// Outcome of `check_login_credentials` — every caller (`/auth`, and
/// the OIDC provider's own `POST /authorize` login step) needs to
/// react differently to each case, so this stays a plain enum rather
/// than folding straight into an `HttpResponse` here.
pub enum LoginResult<'a> {
    /// Credentials, IP allow-list, vhost login authorization, and TOTP
    /// (if required) all checked out — safe to establish a session
    /// for this user now.
    Ok(&'a User),
    /// Rejected at some check — `message` is a plain, non-specific
    /// reason suitable for `render_error_page`. Deliberately not
    /// detailed enough to distinguish "wrong password" from "TOTP
    /// missing" from "IP denied" from the response alone, matching
    /// `/auth`'s existing behavior of not giving an attacker a
    /// finer-grained oracle than "the login didn't work."
    Denied(&'static str),
    /// Credentials (and TOTP, if required) checked out, but this
    /// account is flagged `must_change_password` — the caller decides
    /// what to do next (`/auth` redirects to `page_change_password`;
    /// the OIDC provider currently just shows an error, since
    /// completing a password change mid-authorization-code-flow isn't
    /// wired up yet).
    MustChangePassword(&'a User),
}

/// Runs every check `/auth` itself runs between "a username/password
/// pair arrived" and "a session can be established" — credential
/// verification (constant-time, see `verify_credentials_constant_time`
/// above), IP allow-list, vhost-level login authorization, TOTP (if
/// `login_via_otp` resolves to true for this vhost), and the
/// must-change-password flag — in the same order, with the same
/// security properties, so a second caller (the OIDC provider's own
/// login step) never has to re-derive or risk drifting from this
/// logic. Logging (`warn!`) happens here too, once, rather than in
/// each caller.
pub async fn check_login_credentials<'a>(
    data: &web::Data<AppState>,
    combined_users: &'a [User],
    vhost_route: Option<&RouteRule>,
    username: &str,
    password: &str,
    totp_code: Option<&str>,
    ip: &str,
) -> LoginResult<'a> {
    let Some(matched_user) = verify_credentials_constant_time(combined_users, username, password)
    else {
        return LoginResult::Denied("Invalid credentials");
    };

    if !is_ip_allowed(ip, matched_user) {
        warn!(
            "[{}] Access ip denied for user {}",
            ip, matched_user.username
        );
        return LoginResult::Denied("Access denied");
    }

    if let Some(vr) = vhost_route {
        if !vr.login_authorized(&matched_user.username, &data.config) {
            warn!(
                "[{}] Login denied for user {} — not authorized for this vhost (allow_users/allow_groups/allow_roles/exclude_users)",
                ip, matched_user.username
            );
            return LoginResult::Denied("Access denied");
        }
    }

    let login_via_otp_enabled = vhost_route
        .map(|r| r.resolved_login_via_otp(&data.config))
        .unwrap_or(data.config.login_via_otp);

    if login_via_otp_enabled {
        let Some(totp_code) = totp_code.map(|c| c.trim()).filter(|c| !c.is_empty()) else {
            warn!(
                "[{}] Missing TOTP code for user {}",
                ip, matched_user.username
            );
            return LoginResult::Denied("Missing TOTP code");
        };

        let resolved_otpkey = crate::config::config::resolve_otpkey(
            data,
            &matched_user.username,
            matched_user.otpkey.as_deref(),
        );

        let Some(totp_key) = resolved_otpkey.as_deref() else {
            warn!(
                "[{}] Missing TOTP secret for user {}",
                ip, matched_user.username
            );
            return LoginResult::Denied("Missing TOTP secret");
        };

        let Some(decoded_secret) =
            base32::decode(base32::Alphabet::Rfc4648 { padding: false }, totp_key)
        else {
            warn!(
                "Invalid base32 TOTP secret for user {}",
                matched_user.username
            );
            return LoginResult::Denied("Internal TOTP error");
        };

        let totp =
            TOTP::new(Algorithm::SHA512, 6, 0, 30, decoded_secret).expect("TOTP creation failed");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let generated_code = totp.generate(now);

        // SECURITY: constant-time comparison — see the identical
        // comment at /auth's own original TOTP check for why a plain
        // `!=` here would leak timing information.
        if !bool::from(generated_code.as_bytes().ct_eq(totp_code.as_bytes())) {
            warn!("Invalid TOTP code for user {}", matched_user.username);
            return LoginResult::Denied("Invalid TOTP code");
        }
    }

    let must_change = crate::config::config::resolve_must_change_password(
        data,
        &matched_user.username,
        matched_user.must_change_password,
    );
    if must_change {
        return LoginResult::MustChangePassword(matched_user);
    }

    LoginResult::Ok(matched_user)
}

/// Builds a signed, encrypted ProxyAuth session token and its
/// corresponding `Set-Cookie` header value — the exact same
/// construction `/auth`'s own success path uses (`issue_token`, which
/// seals through the shared `zerocrypt` vault), factored out
/// so the OIDC provider's login step produces byte-for-byte the same
/// kind of token `/auth` would, verifiable by the exact same
/// `token::security::validate_token` everything else already uses.
///
/// Returns `(bearer_token, cookie_header_value)` — `bearer_token` is
/// what a caller not using cookies (or issuing an OIDC session
/// separately) would use in an `Authorization: Bearer` header;
/// `cookie_header_value` is the complete `Set-Cookie` string.
pub fn establish_session(
    username: &str,
    index_user: usize,
    config: &Arc<AppConfig>,
    max_age_session_cookie: i64,
) -> (String, String) {
    // `config: &Arc<AppConfig>` — `.clone()` here clones the `Arc`
    // itself (a cheap refcount bump), not the underlying `AppConfig`,
    // which doesn't implement `Clone` at all (only ever handled
    // behind an `Arc` throughout this codebase, never copied).
    let expiry = get_expiry_with_timezone(config.clone(), None);
    let id_token = generate_random_string(48);
    let expiry_ts = expiry.with_timezone(&Utc).timestamp().to_string();

    // Digest, obfuscation pass and sealing are all inside `issue_token`
    // now; `config.fast` still selects whether the pass runs, it is just
    // read once when the vault is built rather than here.

    // SECURITY/CORRECTNESS: `index_user` here is genuinely read back
    // by `token::security::validate_token` (`config.user_by_index(...)`)
    // to resolve *which account* this token belongs to — it is not a
    // cosmetic field. The caller must pass the matched user's real
    // position in `AppConfig::combined_users()`, not a placeholder;
    // getting this wrong doesn't fail loudly, it silently resolves a
    // valid session to the *wrong* user. Validation now also checks the
    // index and the name in the token agree, so a mismatch is refused
    // rather than served.
    let token_encrypt = match issue_token(username, index_user, &expiry_ts, &id_token) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("failed to issue session token for {username}: {e}");
            String::new()
        }
    };

    let session_max_age = max_age_session_cookie.min(config.token_expiry_seconds);
    let seconds = expiry
        .signed_duration_since(Utc::now())
        .num_seconds()
        .max(0) as u64;
    let max_age =
        actix_web::cookie::time::Duration::seconds(seconds.min(session_max_age as u64) as i64);

    let cookie = Cookie::build("session_token", token_encrypt.clone())
        .path("/")
        .max_age(max_age)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .finish();

    (token_encrypt, cookie.to_string())
}

pub fn generate_random_string(len: usize) -> String {
    let charset: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*()+-=";
    let mut rng = rand::rng();

    let base: Vec<u8> = (0..len)
        .map(|_| *charset.choose(&mut rng).unwrap())
        .collect();

    let now = Utc::now().timestamp() as u64;
    let shift: u8 = (now ^ (now >> 3) ^ (now << 1)).wrapping_rem(97) as u8;

    let random_char: Vec<u8> = base
        .into_iter()
        .map(|byte| {
            let idx = charset.iter().position(|&c| c == byte).unwrap_or(0);
            let new_idx = (idx as u8 + shift) as usize % charset.len();
            charset[new_idx]
        })
        .collect();

    let mut full_input = random_char.clone();
    full_input.extend_from_slice(&now.to_le_bytes());

    let hash = blake3::hash(&full_input);

    hex::encode(hash.as_bytes())
}

// SECURITY/RELIABILITY: previously `.expect("Invalid timezone in config")`.
// This runs on every successful login (token expiry computation) — a typo'd
// or non-IANA `timezone` value in config.json (e.g. "CET" instead of
// "Europe/Paris") would panic on every single login attempt. With
// `panic = "abort"` removed from the release profile, that panic no longer
// crashes and restarts the whole process — it just makes login fail with a
// clean 500 every time, forever, until the config is fixed. Falling back to
// UTC (and logging loudly) keeps the service usable and makes the
// misconfiguration visible in logs instead of as a silent total outage.
fn resolve_timezone(config: &AppConfig) -> Tz {
    config.timezone.parse().unwrap_or_else(|_| {
        error!(
            "Invalid timezone {:?} in config.json -- falling back to UTC. Fix the `timezone` field to a valid IANA name (e.g. Europe/Paris, UTC).",
               config.timezone
        );
        Tz::UTC
    })
}

pub fn get_expiry_with_timezone(
    config: Arc<AppConfig>,
    optional_timestamp: Option<i64>,
) -> DateTime<Tz> {
    let tz: Tz = resolve_timezone(&config);

    let utc_now = optional_timestamp
        .map(|ts| {
            Utc.timestamp_opt(ts, 0)
                .single()
                .expect("Invalid timestamp")
        })
        .unwrap_or_else(Utc::now);

    let utc_expiry = utc_now + Duration::seconds(config.token_expiry_seconds);
    utc_expiry.with_timezone(&tz)
}

pub fn get_expiry_with_timezone_format(
    config: Arc<AppConfig>,
    optional_timestamp: Option<i64>,
) -> String {
    let tz: Tz = resolve_timezone(&config);

    let utc_now = optional_timestamp
        .map(|ts| {
            Utc.timestamp_opt(ts, 0)
                .single()
                .expect("Invalid timestamp")
        })
        .unwrap_or_else(Utc::now);

    let utc_expiry = utc_now + Duration::seconds(config.token_expiry_seconds);

    let local_expiry: DateTime<Tz> = utc_expiry.with_timezone(&tz);

    local_expiry.format("%Y-%m-%d %H:%M:%S %:z").to_string()
}

pub async fn auth_options(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
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
            .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS"))
            .insert_header((
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Authorization, Content-Type, Accept",
            ))
            .insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
            .insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"))
            .finish()
    } else {
        HttpResponse::Forbidden().body("CORS origin not allowed")
    }
}

/// Shared by the POST /auth handler (`auth`) and the new GET /auth handler
/// (`auth_get`): if `session_cookie` is enabled and the request carries a
/// still-valid `session_token` cookie, returns a ready response — a
/// redirect straight to `login_redirect_url`, or an error page for an
/// expired/revoked cookie — instead of letting the caller continue.
/// Returns `None` when there's no session cookie to consider, meaning the
/// caller should proceed with its own logic (show the login form, or
/// process freshly submitted credentials).
///
/// UX/RELIABILITY: this used to live inline in `auth()` only, which meant
/// landing on `/auth` via GET (e.g. bounced back here after logout, or a
/// bookmark) with a still-valid cookie just showed the login form again —
/// confusing, since the visitor is actually still authenticated. Extracting
/// it lets `auth_get` apply the exact same "already logged in? skip
/// straight to the app" check.
pub async fn existing_session_response(
    req: &HttpRequest,
    data: &web::Data<AppState>,
    ip: &str,
) -> Option<HttpResponse> {
    // Resolved once per request: which vhost this is for (by Host
    // header), so session_cookie/login_redirect_url below can use
    // that vhost's own override if routes.yml sets one, falling back
    // to the global default otherwise. `/auth` isn't matched against
    // routes.yml by path/prefix the way a proxied request is — this
    // is what makes a per-vhost setting resolvable here at all.
    let vhost_route = crate::network::proxy::find_vhost_route(
        crate::network::proxy::request_host(req).as_deref(),
        &data.routes.routes,
    );

    let session_cookie_enabled = vhost_route
        .map(|r| r.session_cookie_enabled(&data.config))
        .unwrap_or(data.config.session_cookie);
    if !session_cookie_enabled {
        return None;
    }
    let redirect_target = vhost_route
        .and_then(|r| r.resolved_login_redirect_url(&data.config))
        .unwrap_or(data.config.login_redirect_url.as_deref().unwrap_or("/"));
    let existing_cookie = req.cookie("session_token")?;
    let session_token = existing_cookie.value();

    match validate_token(session_token, data, &data.config, ip).await {
        Ok((username, _token_id, time_expire)) if time_expire > 0 => {
            // Cookie encore valide → redirect direct, pas besoin de re-auth
            info!(
                "[{}] user {} already authenticated ({}s remaining), forwarding to {}",
                ip, username, time_expire, redirect_target
            );

            let mut resp = HttpResponse::SeeOther();
            resp.append_header(("server", "ProxyAuth"));
            resp.append_header(("location", redirect_target));

            if let Some(origin_header) = req.headers().get(header::ORIGIN) {
                if let Ok(origin_str) = origin_header.to_str() {
                    let cors_origins = vhost_route
                        .and_then(|r| r.resolved_cors_origins(&data.config))
                        .or(data.config.cors_origins.as_ref());
                    if let Some(cors_origins) = cors_origins {
                        let origin_normalized = origin_str.trim_end_matches('/');
                        if cors_origins
                            .iter()
                            .any(|allowed| allowed.trim_end_matches('/') == origin_normalized)
                        {
                            resp.append_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str));
                            resp.append_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
                        }
                    }
                }
            }

            Some(resp.finish())
        }
        Ok(_) => {
            // time_expire == 0 : session expirée côté serveur
            warn!("[{}] session token expired, notifying user", ip);
            Some(
                render_error_page(req, data.clone(), "Session expired, please re-authenticate")
                    .await,
            )
        }
        Err(e) => {
            // Token invalide ou révoqué
            warn!("[{}] session token invalid ({}), notifying user", ip, e);
            Some(
                render_error_page(
                    req,
                    data.clone(),
                    "Invalid credential, please re-authenticate",
                )
                .await,
            )
        }
    }
}

/// Validates a `return_to` value as safe to redirect a browser to
/// after a successful login — a same-origin relative path, nothing
/// else. This is the classic open-redirect vulnerability class:
/// without strict validation here, an attacker could craft a login
/// link with `return_to=https://evil.example.com` (an absolute URL)
/// or `return_to=//evil.example.com` (browsers treat a leading `//`
/// as protocol-relative — same practical effect as a full absolute
/// URL) and have a victim's browser sent off-site immediately after
/// they type their real password into a genuine ProxyAuth login form.
///
/// Deliberately strict rather than trying to enumerate every possible
/// bypass: only a value starting with exactly one `/` — not `//`, not
/// `/\` (some environments normalize a leading backslash into a
/// second forward slash, which browsers then also treat as
/// protocol-relative) — and containing no `:` at all (blocks
/// `javascript:`/`data:`/an embedded absolute URL, and does so without
/// needing to maintain a scheme blocklist that could miss one) is
/// accepted. Tested against a real, meaningful set of bypass payloads
/// before this was wired in anywhere — see the OIDC provider's
/// `/authorize` endpoint for the first real caller.
fn validate_return_to(value: &str) -> Option<&str> {
    if !value.starts_with('/') {
        return None;
    }
    if value.starts_with("//") || value.starts_with("/\\") {
        return None;
    }
    if value.contains(':') {
        return None;
    }
    Some(value)
}

pub async fn auth(
    req: HttpRequest,
    data: web::Data<AppState>,
    payload: EitherAuth,
) -> impl Responder {
    // Resolved once per request — see existing_session_response's own
    // copy of this comment for why `/auth` needs this at all, unlike
    // a proxied request.
    let vhost_route = crate::network::proxy::find_vhost_route(
        crate::network::proxy::request_host(&req).as_deref(),
        &data.routes.routes,
    );
    let session_cookie_enabled = vhost_route
        .map(|r| r.session_cookie_enabled(&data.config))
        .unwrap_or(data.config.session_cookie);
    let csrf_enabled = vhost_route
        .map(|r| r.csrf_enabled(&data.config))
        .unwrap_or(data.config.csrf_token);
    let login_redirect_target = vhost_route
        .and_then(|r| r.resolved_login_redirect_url(&data.config))
        .unwrap_or(data.config.login_redirect_url.as_deref().unwrap_or("/"));

    // `return_to` lets a caller ask to land somewhere specific after a
    // successful login instead of the vhost's own configured default
    // — used by the OIDC provider's `/authorize` endpoint to send the
    // browser back there once a session exists, completing the
    // authorization-code flow, without needing its own separate login
    // mechanism.
    //
    // SECURITY: this is user-supplied input (a query parameter),
    // unlike `login_redirect_target` above (admin-configured, in
    // config.json/routes.yml). Validated strictly as a same-origin
    // relative path — see `validate_return_to`'s own doc comment for
    // the open-redirect payloads this specifically guards against.
    // Falls back to the normal `login_redirect_target` if absent or
    // invalid; never silently ignored in a way that could look like
    // it worked when it didn't — an invalid `return_to` just means
    // "use the default," not an error, since a stale or tampered
    // `return_to` shouldn't block an otherwise-legitimate login.
    let login_redirect_target: String = req
        .uri()
        .query()
        .and_then(|q| {
            let pairs: Vec<(String, String)> = serde_urlencoded::from_str(q).ok()?;
            pairs
                .into_iter()
                .find(|(k, _)| k == "return_to")
                .map(|(_, v)| v)
        })
        .and_then(|v| validate_return_to(&v).map(|s| s.to_string()))
        .unwrap_or_else(|| login_redirect_target.to_string());
    let login_via_otp_enabled = vhost_route
        .map(|r| r.resolved_login_via_otp(&data.config))
        .unwrap_or(data.config.login_via_otp);
    let page_change_password = vhost_route
        .and_then(|r| r.resolved_page_change_password(&data.config))
        .or(data.config.page_change_password.as_deref());
    let max_age_session_cookie = vhost_route
        .map(|r| r.resolved_max_age_session_cookie(&data.config))
        .unwrap_or(data.config.max_age_session_cookie);

    if session_cookie_enabled && csrf_enabled && !validate_csrf(&req, &payload, &data.config.secret)
    {
        return render_error_page(&req, data.clone(), "invalid csrf request").await;
    }

    let auth = match payload {
        EitherAuth::Json(j) => j,
        EitherAuth::Form(f) => f,
    };

    let ip = client_ip(&req, &data.config)
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
                .or_else(|| {
                    req.connection_info()
                        .realip_remote_addr()
                        .map(|s| s.to_string())
                })
        })
        .unwrap_or_else(|| "-".to_string());

    if let Some(resp) = existing_session_response(&req, &data, &ip).await {
        return resp;
    }

    if session_cookie_enabled {
        let redirect_target = login_redirect_target.clone();
        if req.cookie("session_token").is_none() && !redirect_target.starts_with('/') {
            return HttpResponse::BadRequest()
                .append_header(("server", "ProxyAuth"))
                .body("Invalid redirect URL");
        }
    }

    // SECURITY: was `.find(|(_, user)| user.username == auth.username &&
    // verify_password(...))`, which short-circuits on the username check
    // and skips the expensive Argon2 verification entirely for unknown
    // usernames — an attacker could enumerate valid usernames purely by
    // measuring response latency. verify_credentials_constant_time always
    // burns the same Argon2 cost, against a dummy hash when no user
    // matches, so response time no longer reveals account existence.
    let combined_users = data.config.combined_users();
    if let Some(matched_user) =
        verify_credentials_constant_time(&combined_users, &auth.username, &auth.password)
    {
        let index_user = combined_users
            .iter()
            .position(|u| std::ptr::eq(u, matched_user))
            .expect("matched user must be present in combined_users");
        let user = &combined_users[index_user];

        if !is_ip_allowed(&ip, &user) {
            warn!("[{}] Access ip denied for user {}", ip, user.username);
            return render_error_page(&req, data.clone(), "Access denied").await;
        }

        // Vhost-wide login authorization — separate from, and earlier
        // than, any route-level username/groups/roles check: this
        // decides whether this vhost lets this user log in *at all*,
        // before a session or route access even enters the picture.
        // Checked against the SAME vhost_route resolved at the top of
        // this function. No vhost_route match (e.g. a bare-IP
        // connection, or a vhost with no routes.yml entry at all)
        // means there's nothing to authorize against — nothing is
        // denied here that wasn't already going to fail some other
        // way, so this only applies when a vhost is actually
        // resolved.
        if let Some(vr) = vhost_route {
            if !vr.login_authorized(&user.username, &data.config) {
                warn!(
                    "[{}] Login denied for user {} — not authorized for this vhost (allow_users/allow_groups/allow_roles/exclude_users)",
                    ip, user.username
                );
                return render_error_page(&req, data.clone(), "Access denied").await;
            }
        }

        // totp method
        if login_via_otp_enabled {
            let totp_code = match &auth.totp_code {
                Some(code) => code.trim(),
                None => {
                    warn!("[{}] Missing TOTP code for user {}", ip, user.username);
                    return render_error_page(&req, data.clone(), "Missing TOTP code").await;
                }
            };

            // Consult the live overlay before the startup snapshot:
            // `AppState.config` is an immutable Arc loaded once, so a
            // key enrolled or revoked since then only exists in
            // `otp_overrides`. Reading `user.otpkey` directly (as this
            // did) meant a revoked — e.g. compromised — secret kept
            // working until every worker restarted, defeating the
            // point of the reset endpoint. See
            // `AppState::otp_overrides`.
            let resolved_otpkey = crate::config::config::resolve_otpkey(
                &data,
                &user.username,
                user.otpkey.as_deref(),
            );

            let totp_key = match resolved_otpkey.as_deref() {
                Some(key) => key,
                None => {
                    warn!("[{}] Missing TOTP secret for user {}", ip, user.username);
                    return render_error_page(&req, data.clone(), "Missing TOTP secret").await;
                }
            };

            let decoded_secret =
                match base32::decode(base32::Alphabet::Rfc4648 { padding: false }, totp_key) {
                    Some(bytes) => bytes,
                    None => {
                        warn!("Invalid base32 TOTP secret for user {}", user.username);
                        return render_error_page(&req, data.clone(), "Internal TOTP error").await;
                    }
                };

            let totp = TOTP::new(Algorithm::SHA512, 6, 0, 30, decoded_secret)
                .expect("TOTP creation failed");

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let generated_code = totp.generate(now);

            // SECURITY: constant-time comparison — a plain `!=` on the
            // 6-digit code leaks timing information about how many
            // leading digits matched.
            if !bool::from(generated_code.as_bytes().ct_eq(totp_code.as_bytes())) {
                warn!("Invalid TOTP code for user {}", user.username);
                return render_error_page(&req, data.clone(), "Invalid TOTP code").await;
            }
        }

        // Credentials (and TOTP, if required) checked out — but if
        // this account is flagged must_change_password (a temporary
        // password an admin just set, or a not-yet-completed
        // reset-password), don't issue a normal session yet.
        let must_change = crate::config::config::resolve_must_change_password(
            &data,
            &user.username,
            user.must_change_password,
        );
        if must_change {
            let Some(page_change_password) = page_change_password else {
                warn!(
                    "[{}] user {} must change their password, but page_change_password isn't configured",
                    ip, user.username
                );
                return render_error_page(
                        &req,
                        data.clone(),
                                             "Password change required, but no change-password page is configured — contact an administrator.",
                    )
                    .await;
            };

            let token = match crate::reset::db::create_token(
                &user.username,
                crate::reset::db::ResetKind::FirstLogin,
                3600,
            ) {
                Ok(t) => t,
                Err(e) => {
                    warn!("[{}] failed to create a first-login reset token: {}", ip, e);
                    return render_error_page(&req, data.clone(), "Internal error").await;
                }
            };

            let separator = if page_change_password.contains('?') {
                '&'
            } else {
                '?'
            };
            let redirect_url = format!("{page_change_password}{separator}token={token}");

            info!("[{}] user {} must change their password", ip, user.username);

            // Only a real browser flow (session_cookie: true) can
            // meaningfully be sent an HTTP redirect and expected to
            // follow it. An API/JSON client (session_cookie: false)
            // wouldn't naturally follow a 303 from a fetch/curl call
            // — it needs the same information back as data it can
            // act on itself instead.
            if session_cookie_enabled {
                return HttpResponse::SeeOther()
                    .append_header(("server", "ProxyAuth"))
                    .append_header((header::LOCATION, redirect_url))
                    .finish();
            }

            return HttpResponse::Ok()
                .append_header(("server", "ProxyAuth"))
                .json(serde_json::json!({
                    "must_change_password": true,
                    "reset_link": redirect_url,
                }));
        }

        let expiry = get_expiry_with_timezone(data.config.clone(), None);

        let id_token = generate_random_string(48);

        let expiry_ts = expiry.with_timezone(&Utc).timestamp().to_string();
        let expires_at_str = get_expiry_with_timezone_format(data.config.clone(), None);

        // `config.fast` still selects whether the obfuscation pass runs;
        // it is read once when the vault is built rather than on every
        // login. Everything else — digest, sealing, encoding — is inside
        // `issue_token`.
        let token_encrypt = match issue_token(&auth.username, index_user, &expiry_ts, &id_token) {
            Ok(t) => t,
            Err(e) => {
                error!(
                    "[{}] failed to issue token for {}: {}",
                    ip, auth.username, e
                );
                return HttpResponse::InternalServerError().finish();
            }
        };

        info!(
            "[{}] new token generated for user {} expirated at {}",
            ip, user.username, expires_at_str
        );

        let mut resp = HttpResponse::Ok();
        resp.append_header(("server", "ProxyAuth"));

        if session_cookie_enabled {
            let session_max_age = max_age_session_cookie.min(data.config.token_expiry_seconds);

            let seconds = expiry
                .signed_duration_since(Utc::now())
                .num_seconds()
                .clamp(60, session_max_age);

            let cookie_expiry = Utc::now() + Duration::seconds(seconds);
            let cookie_expiry_time =
                OffsetDateTime::from_unix_timestamp(cookie_expiry.timestamp()).unwrap();

            if req.cookie("session_token").is_some() {
                let expired_cookie = Cookie::build("session_token", "")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .expires(OffsetDateTime::UNIX_EPOCH)
                    .finish();
                resp.cookie(expired_cookie);
            }

            let new_cookie = Cookie::build("session_token", token_encrypt.clone())
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::Strict)
                .expires(cookie_expiry_time)
                .finish();

            // check cors
            if let Some(origin_header) = req.headers().get(header::ORIGIN) {
                if let Ok(origin_str) = origin_header.to_str() {
                    let cors_origins = vhost_route
                        .and_then(|r| r.resolved_cors_origins(&data.config))
                        .or(data.config.cors_origins.as_ref());
                    if let Some(cors_origins) = cors_origins {
                        let origin_normalized = origin_str.trim_end_matches('/');

                        if cors_origins
                            .iter()
                            .any(|allowed| allowed.trim_end_matches('/') == origin_normalized)
                        {
                            resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str));
                            resp.insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
                            resp.insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
                        }
                    }
                }
            }

            resp.cookie(new_cookie);

            let redirect_target = login_redirect_target;

            if redirect_target.starts_with('/') {
                return resp
                    .insert_header(("location", redirect_target))
                    .insert_header(("server", "ProxyAuth"))
                    .status(StatusCode::SEE_OTHER)
                    .finish();
            }
        }

        resp.json(serde_json::json!({
            "token": token_encrypt,
            "expires_at": expires_at_str,
        }))
    } else {
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

        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");

        let method = req.method().as_str();
        let path = req.path();

        warn!(
            "[{}] - {} {} Invalid {} credentials provided {}",
            ip, path, method, auth.username, user_agent
        );

        return render_error_page(&req, data.clone(), "Invalid credentials").await;
    }
}

/// The real dispatch target registered for `POST /auth` — decides
/// whether this request is handled by ProxyAuth's own login logic
/// (`auth`, below) or proxied straight through to the backend.
///
/// A vhost with `oidc:` configured proxies *everything* not
/// explicitly part of the OIDC provider's own surface straight
/// through to the backend — see `RouteRule::oidc`'s own doc comment.
/// `/auth` and `/logout` are ordinarily registered as fixed,
/// always-matching routes ahead of any proxying at all (see
/// `main.rs`), which would otherwise make them the one exception to
/// that rule on every vhost, oidc-enabled or not. This dispatcher
/// closes that: on an oidc-enabled vhost, a request to `/auth` proxies
/// through like everything else (a relying party like Grafana has its
/// own native login/session handling; ProxyAuth's own `/auth` was
/// never meant to be reachable there at all). The OIDC provider's own
/// login step doesn't depend on this being reachable — it verifies
/// credentials directly via `check_login_credentials`/
/// `establish_session` from inside `POST /authorize` instead.
///
/// Manually replicates `EitherAuth`'s own `Content-Type`-based
/// Json/Form dispatch from `body: web::Bytes` rather than letting
/// actix extract it automatically, since the oidc-or-not decision has
/// to happen *before* the body is consumed one way or the other, and
/// `body: web::Bytes` (needed for the proxying path) and
/// `payload: EitherAuth` can't both be extractor parameters on the
/// same handler without one of them consuming what the other needs.
pub async fn auth_dispatch(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let vhost_route = crate::network::proxy::find_vhost_route(
        crate::network::proxy::request_host(&req).as_deref(),
        &data.routes.routes,
    );

    if vhost_route.map(|r| r.oidc.is_some()).unwrap_or(false) {
        return crate::network::proxy::global_proxy(req, body, data).await;
    }

    let content_type = req
        .headers()
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let payload = if content_type.contains("application/json") {
        match serde_json::from_slice::<AuthRequest>(&body) {
            Ok(v) => EitherAuth::Json(v),
            Err(_) => {
                return Ok(HttpResponse::BadRequest()
                    .append_header(("server", "ProxyAuth"))
                    .body("Invalid JSON body"));
            }
        }
    } else if content_type.contains("application/x-www-form-urlencoded") {
        match serde_urlencoded::from_bytes::<AuthRequest>(&body) {
            Ok(v) => EitherAuth::Form(v),
            Err(_) => {
                return Ok(HttpResponse::BadRequest()
                    .append_header(("server", "ProxyAuth"))
                    .body("Invalid form body"));
            }
        }
    } else {
        return Ok(HttpResponse::BadRequest()
            .append_header(("server", "ProxyAuth"))
            .body("Unsupported Content-Type"));
    };

    Ok(auth(req.clone(), data, payload)
        .await
        .respond_to(&req)
        .map_into_boxed_body())
}
