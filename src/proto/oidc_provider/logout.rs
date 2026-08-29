//! `GET /end-session` — RP-Initiated Logout. The relying party sends
//! the browser here (typically with `post_logout_redirect_uri`) when
//! its own user logs out, so ProxyAuth's session ends too rather than
//! silently outliving the backend's own.
//!
//! `id_token_hint`, the other parameter the spec defines for this
//! endpoint, is deliberately not accepted here at all — see this
//! module's own note on `end_session_handler` for why it wouldn't be
//! actionable even if it were.
//!
//! Deliberately a separate path from the global `/logout` — a vhost
//! with `oidc:` configured proxies `/logout` straight through to the
//! backend like everything else not explicitly part of the OIDC
//! provider surface (see `RouteRule::oidc`'s own doc comment and
//! `token::logout::logout_dispatch`), since the backend has its own
//! native logout ProxyAuth's `/logout` was never meant to intercept
//! there. This endpoint is the OIDC-specific replacement, advertised
//! as `end_session_endpoint` in the discovery document.

use crate::config::config::AppState;
use crate::network::proxy::{find_vhost_route, request_host};
use actix_web::{HttpRequest, HttpResponse, http::header, web};
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc2822};

#[derive(Debug, Deserialize)]
pub struct EndSessionParams {
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

/// Plain, unstyled confirmation page — shown whenever there's nowhere
/// valid to redirect back to: no `post_logout_redirect_uri` was
/// given, it wasn't on `logout_redirect_uris`'s exact-match list, or
/// the request didn't even resolve to an oidc-enabled vhost.
/// `set_cookie_header`, when present, clears the session — kept as a
/// parameter rather than always attaching it, since the three "didn't
/// even resolve" early exits below have nothing legitimate to clear.
fn logged_out_page(set_cookie_header: Option<String>) -> HttpResponse {
    let mut resp = HttpResponse::Ok();
    resp.append_header(("server", "ProxyAuth"));
    if let Some(c) = set_cookie_header {
        resp.append_header((header::SET_COOKIE, c));
    }
    resp.content_type("text/html; charset=utf-8")
        .body("<!DOCTYPE html><html><body>You have been signed out.</body></html>")
}

/// Builds the `Set-Cookie` header value that clears `session_token` —
/// same construction `token::logout::logout_session` itself uses
/// (`Expires=` in the past, rather than `Cookie::build`'s `Max-Age`
/// builder), kept consistent with that rather than introducing a
/// second way to express the same thing.
fn clear_session_cookie_header() -> String {
    let expires_str = OffsetDateTime::UNIX_EPOCH.format(&Rfc2822).unwrap();
    format!("session_token=; Expires={expires_str}; Path=/; HttpOnly; Secure; SameSite=Strict")
}

/// This clears the `session_token` cookie unconditionally, but does
/// **not** attempt to revoke a token server-side the way
/// `token::logout::logout_session` does — and doesn't even accept
/// `id_token_hint` (the spec parameter meant to identify which
/// session) to try: it's a relying party's own previously-issued
/// `id_token`, not a ProxyAuth bearer/session token, so there's
/// nothing here in the shape `revoke::load::revoke_token` expects,
/// and no reliable way to recover the actual ProxyAuth session token
/// this browser might be holding from it. A still-technically-valid
/// token that's simply no longer sent anywhere (the cookie is gone
/// either way) is the accepted trade-off here — the same class of gap
/// ordinary cookie expiry already has.
pub async fn end_session_handler(req: HttpRequest, data: web::Data<AppState>) -> HttpResponse {
    let Some(host) = request_host(&req) else {
        return logged_out_page(None);
    };
    let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) else {
        return logged_out_page(None);
    };
    let Some(oidc) = &rule.oidc else {
        return logged_out_page(None);
    };

    let params: EndSessionParams = serde_urlencoded::from_str(req.query_string()).unwrap_or(
        EndSessionParams {
            post_logout_redirect_uri: None,
            state: None,
        },
    );

    let set_cookie_header = clear_session_cookie_header();

    let Some(redirect_uri) = params.post_logout_redirect_uri.as_deref() else {
        return logged_out_page(Some(set_cookie_header));
    };

    // Exact match only — same discipline as `redirect_uris` at
    // `/oidc/authorize`, and for the identical reason: an unvalidated
    // post-logout redirect is exactly as capable of exfiltrating
    // something (here, whatever `state` carries) to an attacker-chosen
    // destination as an unvalidated authorization redirect_uri is.
    if !oidc
        .logout_redirect_uris
        .iter()
        .any(|allowed| allowed == redirect_uri)
    {
        tracing::warn!(
            "OIDC end-session: post_logout_redirect_uri {redirect_uri:?} is not on this vhost's logout_redirect_uris — showing the default confirmation page instead"
        );
        return logged_out_page(Some(set_cookie_header));
    }

    let mut location = redirect_uri.to_string();
    if let Some(s) = params.state.as_deref() {
        location.push_str(if location.contains('?') { "&" } else { "?" });
        location.push_str("state=");
        location.push_str(&urlencoding::encode(s));
    }

    HttpResponse::Found()
        .append_header(("server", "ProxyAuth"))
        .append_header((header::LOCATION, location))
        .append_header((header::SET_COOKIE, set_cookie_header))
        .finish()
}
