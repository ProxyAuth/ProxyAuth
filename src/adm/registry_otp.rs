use crate::AppState;
use crate::adm::method_otp::generate_otpauth_uri;
use crate::adm::stats::is_valid_admin_token;
use crate::config::config::{add_otpkey, clear_otpkey};
use crate::token::auth::{is_ip_allowed, verify_credentials_constant_time};
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, Responder, http::header, web};
use serde::{Deserialize, Serialize};
use totp_rs::Algorithm;
use tracing::warn;

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
    let user =
    verify_credentials_constant_time(&data.config.users, &auth.username, &auth.password);

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
    // refuse instead of returning it again.
    if user.otpkey.is_some() {
        warn!(
            "[{}] Rejected OTP re-disclosure attempt for user {} (already enrolled)",
              ip, user.username
        );
        return HttpResponse::Conflict().body(
            "OTP is already enrolled for this account. Ask an administrator to reset it \
if you need to re-provision your authenticator app.",
        );
    }

    add_otpkey("/etc/proxyauth/config/config.json", &user.username);

let config_str = match std::fs::read_to_string("/etc/proxyauth/config/config.json") {
    Ok(s) => s,
    Err(e) => {
        warn!("Failed to reload config after provisioning OTP key: {e}");
        return HttpResponse::InternalServerError().body("OTP generation failed");
    }
};

let json: serde_json::Value = match serde_json::from_str(&config_str) {
    Ok(v) => v,
    Err(e) => {
        warn!("Invalid JSON while reloading config after provisioning OTP key: {e}");
        return HttpResponse::InternalServerError().body("OTP generation failed");
    }
};

let otpkey = json
.get("users")
.and_then(|users| users.as_array())
.and_then(|users| {
    users
    .iter()
    .find(|u| u.get("username").and_then(|n| n.as_str()) == Some(&auth.username))
})
.and_then(|u| u.get("otpkey").and_then(|v| v.as_str()))
.map(|s| s.to_string());

if let Some(secret) = otpkey {
    // CORRECTNESS: without this, the newly written otpkey only exists in
    // config.json on disk — the already-running AppState.config snapshot
    // still has otpkey = None for this user, so login would fail with
    // "Missing TOTP secret" until the whole service was restarted. See
    // AppState::otp_overrides / resolve_otpkey.
    data.otp_overrides
    .insert(auth.username.clone(), Some(secret.clone()));

    let uri = generate_otpauth_uri(
        &auth.username,
        "ProxyAuth",
        &secret,
        Algorithm::SHA512,
        6,
        30,
    );

    return cors_response(HttpResponse::Ok(), &req).json(OtpAuthUriResponse {
        otpauth_uri: uri,
        otpkey: secret,
    });
}

HttpResponse::InternalServerError().body("OTP generation failed")
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

    match clear_otpkey("/etc/proxyauth/config/config.json", &body.username) {
        Ok(true) => {
            // CORRECTNESS/SECURITY: this is the critical half of the fix —
            // without updating the live overlay too, the OLD (e.g.
            // compromised) OTP secret would keep working for login until
            // every worker process was restarted, defeating the entire
            // point of an incident-response reset endpoint. See
            // AppState::otp_overrides / resolve_otpkey.
            data.otp_overrides.insert(body.username.clone(), None);

            warn!(
                "OTP key reset for user {} by admin request",
                body.username
            );
            HttpResponse::Ok().body(format!(
                "OTP key cleared for '{}'. They can now re-enroll via /adm/auth/totp/get.",
                body.username
            ))
        }
        Ok(false) => HttpResponse::Ok().body(format!(
            "User '{}' had no OTP key set — nothing to reset.",
            body.username
        )),
        Err(e) => {
            warn!("Failed to reset OTP key for {}: {}", body.username, e);
            HttpResponse::InternalServerError().body("Failed to reset OTP key")
        }
    }
}
