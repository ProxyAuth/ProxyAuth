use crate::AppConfig;
use crate::AppState;
use crate::config::config::{AuthRequest, User};
use crate::network::error::render_error_page;
use crate::network::proxy::client_ip;
use crate::token::crypto::{calcul_cipher, derive_key_from_secret, encrypt};
use crate::token::csrf::verify_csrf_token;
use crate::token::security::{generate_token, validate_token};
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
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
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

pub fn generate_random_string(len: usize) -> String {
    let charset: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*()+-=";
    let mut rng = OsRng;

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
    if !data.config.session_cookie {
        return None;
    }
    let redirect_target = data.config.login_redirect_url.as_deref().unwrap_or("/");
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
                    if let Some(cors_origins) = &data.config.cors_origins {
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

pub async fn auth(
    req: HttpRequest,
    data: web::Data<AppState>,
    payload: EitherAuth,
) -> impl Responder {
    if data.config.session_cookie
        && data.config.csrf_token
        && !validate_csrf(&req, &payload, &data.config.secret)
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

    if data.config.session_cookie {
        let redirect_target = data.config.login_redirect_url.as_deref().unwrap_or("/");
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

        // totp method
        if data.config.login_via_otp {
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
            let Some(page_change_password) = &data.config.page_change_password else {
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
            if data.config.session_cookie {
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

        let token = generate_token(&auth.username, &data.config, &expiry_ts, &id_token);
        let key = derive_key_from_secret(&data.config.secret);

        // mode fast token is more speed but less secure
        // and fast is false token is more secure but it's slower
        let token_generate = if data.config.fast {
            token.clone()
        } else {
            calcul_cipher(token.clone())
        };

        let cipher_token = format!(
            "{}|{}|{}|{}",
            token_generate, expiry_ts, index_user, id_token
        );

        let token_encrypt = encrypt(&cipher_token, &key);

        info!(
            "[{}] new token generated for user {} expirated at {}",
            ip, user.username, expires_at_str
        );

        let mut resp = HttpResponse::Ok();
        resp.append_header(("server", "ProxyAuth"));

        if data.config.session_cookie {
            let session_max_age = data
                .config
                .max_age_session_cookie
                .min(data.config.token_expiry_seconds);

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
                    if let Some(cors_origins) = &data.config.cors_origins {
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

            let redirect_target = data.config.login_redirect_url.as_deref().unwrap_or("/");

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
