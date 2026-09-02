//! `/.well-known/openid-configuration` and `/oidc/jwks.json` — the two
//! read-only, always-available OIDC provider endpoints. Both are
//! served by ProxyAuth itself for any vhost with `oidc:` configured,
//! intercepted ahead of normal routing — see
//! `network::proxy::global_proxy`'s own interception point, which
//! mirrors the same pattern already used there for ACME HTTP-01
//! challenge responses.
//!
//! Every other OIDC endpoint lives under `/oidc/` — `/oidc/authorize`,
//! `/oidc/token`, `/oidc/userinfo`, `/oidc/end-session` — keeping the
//! whole provider surface visually and structurally distinct from
//! whatever else a vhost's backend serves at its own root, rather than
//! scattering fixed names like `/token` across the same namespace a
//! backend's own routes live in. `/.well-known/openid-configuration`
//! is the one exception, fixed at the root by the discovery spec
//! itself (RFC 8414) — not something ProxyAuth gets to choose.

use crate::proto::oidc_provider::jwt;
use actix_web::{HttpResponse, http::header};

/// Builds the discovery document for `issuer` — the vhost's own
/// `https://{host}` identity, matching what `iss` in every id_token
/// this vhost issues also claims. Always `https://`: OIDC's own spec
/// treats a non-HTTPS issuer as invalid for anything beyond local
/// testing, so this doesn't attempt to reflect whether `tls` happens
/// to be off in a given deployment.
pub fn discovery_document(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oidc/authorize"),
        "token_endpoint": format!("{issuer}/oidc/token"),
        "userinfo_endpoint": format!("{issuer}/oidc/userinfo"),
        "jwks_uri": format!("{issuer}/oidc/jwks.json"),
        "end_session_endpoint": format!("{issuer}/oidc/end-session"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "name"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
    })
}

/// `GET /.well-known/openid-configuration` — `issuer` is this specific
/// vhost's own `https://{host}`, not a global constant, since each
/// oidc-enabled vhost is its own issuer identity (see
/// `config::OidcProviderConfig`'s own doc comment on why this is
/// one-client-per-vhost rather than a shared, multi-tenant issuer).
///
/// `Access-Control-Allow-Origin: *` — deliberately, unlike everything
/// else ProxyAuth serves. This document is metadata *about* the
/// provider, not anything scoped to a specific caller — any OIDC
/// client library, from any origin, needs to be able to fetch it to
/// configure itself. ProxyAuth's own `cors_origins` allow-list (see
/// `network::cors::CorsMiddleware`) exists to protect a vhost's
/// *backend* API, a different concern; applying that same restrictive
/// policy here would just break the one thing this endpoint exists
/// for, since a relying party's own domain is essentially never going
/// to be on its own vhost's `cors_origins` list.
pub fn discovery_handler(issuer: &str) -> HttpResponse {
    HttpResponse::Ok()
        .append_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .content_type("application/json")
        .body(discovery_document(issuer).to_string())
}

/// `GET /oidc/jwks.json` — the same document regardless of which
/// oidc-enabled vhost it's requested from, since every vhost currently
/// shares the one global signing key (see `jwt`'s own module doc
/// comment on that trade-off). Still served per-vhost rather than at
/// one fixed global path, matching what `jwks_uri` in each vhost's own
/// discovery document points at.
///
/// `Access-Control-Allow-Origin: *` for the same reason as
/// `discovery_handler` above — a public key is not a secret, and any
/// relying party's own token-verification code needs to be able to
/// fetch this from wherever it runs, browser-side or not.
pub fn jwks_handler() -> HttpResponse {
    HttpResponse::Ok()
        .append_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .content_type("application/json")
        .body(jwt::jwks_document().to_string())
}
