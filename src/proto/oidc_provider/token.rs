//! `POST /token` — the OIDC token endpoint. Called server-to-server by
//! the relying party (never by the browser directly) to exchange an
//! authorization code for a real, signed `id_token`.
//!
//! # The full verification chain, in the order it actually matters
//!
//! Every one of these has to pass before a token gets signed — this
//! endpoint is the one place in the whole flow that turns "someone
//! has a code" into "here is cryptographic proof of who logged in",
//! so each check earns its place:
//!
//! 1. **Client authentication** — `client_id`/`client_secret` verified
//!    against this vhost's own `oidc:` config, Argon2, same function
//!    `token::auth::verify_password` already uses for real user
//!    passwords. Checked *before* even looking at the code — a wrong
//!    secret should never reveal whether the code itself was valid.
//! 2. **Code validation** — `authcode::validate_and_consume_code`,
//!    atomic, single-use. Once this call returns, the code is gone
//!    regardless of what happens next; there's no way to retry with
//!    the same code even if a later check in this same request fails.
//! 3. **`client_id` match** — the code's own stored `client_id` must
//!    match the one that just authenticated. Defense in depth: codes
//!    are already only ever issued for the client that requested
//!    them at `/oidc/authorize`, so this should never actually fire, but
//!    checking it costs nothing and closes off an entire class of
//!    "what if the store ever had a bug" concern.
//! 4. **`redirect_uri` match** — must be byte-for-byte identical to
//!    what `/oidc/authorize` received for this same code (RFC 6749 §4.1.3).
//!    Without this, a code obtained via one `redirect_uri` could be
//!    redeemed by presenting a *different* one — meaningful precisely
//!    when a client has more than one registered.
//! 5. **PKCE** — SHA256(`code_verifier`), base64url, constant-time
//!    compared against the `code_challenge` stored with the code.
//!    This is what proves the party redeeming the code is the same
//!    party that started the flow — without it, an authorization code
//!    intercepted in transit (a browser history entry, a referrer
//!    header, a compromised network hop) could be redeemed by
//!    whoever intercepted it.

use crate::config::config::AppState;
use crate::network::proxy::{find_vhost_route, request_host};
use crate::proto::oidc_provider::authcode;
use crate::proto::oidc_provider::jwt::signing_key;
use crate::token::auth::verify_password;
use actix_web::{HttpRequest, HttpResponse, web};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

const ID_TOKEN_TTL_SECS: i64 = 3600;
const ACCESS_TOKEN_TTL_SECS: i64 = 3600;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenErrorResponse {
    error: &'static str,
    error_description: String,
}

fn token_error(
    status: actix_web::http::StatusCode,
    error: &'static str,
    description: &str,
) -> HttpResponse {
    HttpResponse::build(status)
        .append_header(("server", "ProxyAuth"))
        .append_header(("cache-control", "no-store"))
        .content_type("application/json")
        .json(TokenErrorResponse {
            error,
            error_description: description.to_string(),
        })
}

#[derive(Debug, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

/// Claims carried by the `access_token` — deliberately minimal
/// compared to `IdTokenClaims`: no `aud` (this token is only ever
/// verified by ProxyAuth's own `/oidc/userinfo`, not an external relying
/// party — see `jwt::OidcSigningKey::validation_no_audience`), but
/// `scope` *is* included, since `/oidc/userinfo` needs to know what was
/// actually granted at `/oidc/authorize` to decide which claims it's
/// allowed to return (e.g. only include `email` if the `email` scope
/// was granted).
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub scope: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Serialize)]
struct TokenSuccessResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
}

/// Verifies a PKCE `code_verifier` against the `code_challenge`
/// stored with an authorization code — `code_challenge_method` is
/// always `"S256"` by the time an entry reaches this store (enforced
/// at `/oidc/authorize`, which refuses `plain` or a missing method
/// entirely), so this only ever needs to implement the one method.
///
/// Constant-time comparison: this is a security-relevant equality
/// check on secret-derived material, the same reasoning as every
/// other credential comparison in ProxyAuth's token handling.
fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
    computed.as_bytes().ct_eq(code_challenge.as_bytes()).into()
}

pub async fn token_handler(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> HttpResponse {
    let Some(host) = request_host(&req) else {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "could not determine the requested host",
        );
    };

    let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) else {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "unknown vhost",
        );
    };

    let Some(oidc) = &rule.oidc else {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "OIDC is not enabled for this vhost",
        );
    };

    let params: TokenRequest = match serde_urlencoded::from_bytes(&body) {
        Ok(p) => p,
        Err(_) => {
            return token_error(
                actix_web::http::StatusCode::BAD_REQUEST,
                "invalid_request",
                "malformed request body",
            );
        }
    };

    if params.grant_type.as_deref() != Some("authorization_code") {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only grant_type=authorization_code is supported",
        );
    }

    // --- 1. Client authentication — Basic auth header first (client_secret_basic),
    // falling back to body params (client_secret_post). Both were
    // advertised in discovery.rs's token_endpoint_auth_methods_supported.
    let (client_id, client_secret) = match basic_auth_credentials(&req) {
        Some((id, secret)) => (Some(id), Some(secret)),
        None => (params.client_id.clone(), params.client_secret.clone()),
    };

    let (Some(client_id), Some(client_secret)) = (client_id, client_secret) else {
        return token_error(
            actix_web::http::StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication is required",
        );
    };

    // Checked before the code itself is even looked at — a wrong
    // client secret should never leak information about whether the
    // presented code was otherwise valid.
    if client_id != oidc.client_id || !verify_password(&client_secret, &oidc.client_secret_hash) {
        return token_error(
            actix_web::http::StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
    }

    // --- 2. Code validation — atomic, single-use. Consumed here
    // regardless of what the remaining checks below decide; there is
    // no way to retry with the same code after this call returns,
    // even if this exact request ultimately fails a later check.
    let Some(code) = params.code.as_deref() else {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing code",
        );
    };

    let entry = match authcode::validate_and_consume_code(code) {
        Ok(e) => e,
        Err(_) => {
            return token_error(
                actix_web::http::StatusCode::BAD_REQUEST,
                "invalid_grant",
                "the authorization code is invalid, expired, or already used",
            );
        }
    };

    // --- 3. client_id match (defense in depth — see module doc comment).
    if entry.client_id != client_id {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this code was not issued to this client",
        );
    }

    // --- 4. redirect_uri match, byte-for-byte, against what /authorize
    // received for this exact code.
    let Some(redirect_uri) = params.redirect_uri.as_deref() else {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing redirect_uri",
        );
    };
    if redirect_uri != entry.redirect_uri {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri does not match the one used to obtain this code",
        );
    }

    // --- 5. PKCE.
    let Some(code_verifier) = params.code_verifier.as_deref() else {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing code_verifier",
        );
    };
    if !verify_pkce(code_verifier, &entry.code_challenge) {
        return token_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code_verifier does not match the code_challenge presented at /authorize",
        );
    }

    // Every check passed — sign the tokens.
    let issuer = format!("https://{host}");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let key = signing_key();

    let id_claims = IdTokenClaims {
        iss: issuer.clone(),
        sub: entry.username.clone(),
        aud: client_id.clone(),
        exp: now + ID_TOKEN_TTL_SECS,
        iat: now,
        nonce: entry.nonce.clone(),
    };
    let id_token = match jsonwebtoken::encode(&key.header(), &id_claims, &key.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to sign OIDC id_token: {e}");
            return token_error(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to sign id_token",
            );
        }
    };

    let access_claims = AccessTokenClaims {
        iss: issuer,
        sub: entry.username,
        scope: entry.scope,
        exp: now + ACCESS_TOKEN_TTL_SECS,
        iat: now,
    };
    let access_token = match jsonwebtoken::encode(&key.header(), &access_claims, &key.encoding_key)
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to sign OIDC access_token: {e}");
            return token_error(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to sign access_token",
            );
        }
    };

    HttpResponse::Ok()
        .append_header(("server", "ProxyAuth"))
        .append_header(("cache-control", "no-store"))
        .append_header(("pragma", "no-cache"))
        .json(TokenSuccessResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_TTL_SECS,
            id_token,
        })
}

/// Parses `Authorization: Basic base64(client_id:client_secret)` —
/// `client_secret_basic`, the other auth method advertised in
/// discovery.rs. Percent-decodes each half per RFC 6749 §2.3.1 (the
/// spec requires the client_id/secret to be application/x-www-form-
/// urlencoded *before* the colon-join-and-base64 step, not just
/// raw bytes).
fn basic_auth_credentials(req: &HttpRequest) -> Option<(String, String)> {
    let header = req.headers().get("Authorization")?.to_str().ok()?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let id = urlencoding::decode(id).ok()?.into_owned();
    let secret = urlencoding::decode(secret).ok()?.into_owned();
    Some((id, secret))
}
