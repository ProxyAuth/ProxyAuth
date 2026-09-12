//! `GET /authorize` — the OIDC authorization endpoint. Reached by the
//! browser, redirected here by the backend (the relying party) when
//! it needs proof of the visitor's identity.
//!
//! # Error handling: two different failure modes, on purpose
//!
//! Per the OIDC/OAuth2 spec, an invalid `redirect_uri` must **never**
//! be redirected to — that's the exact mechanism a classic
//! open-redirect-via-OAuth attack relies on (register or find an
//! unvalidated `redirect_uri`, then use the provider itself to
//! "vouch" for a redirect to it). Every other validation failure
//! (bad `response_type`, missing PKCE, disallowed scope, ...) *is*
//! reported back to the relying party via a redirect to its own
//! (now-validated) `redirect_uri`, carrying `?error=...&state=...` —
//! this is what lets a well-behaved relying party show its own user a
//! sensible error instead of a dead end on ProxyAuth's own domain.
//!
//! Concretely: `client_id`/`redirect_uri` are checked first and
//! independently of everything else; only once both are confirmed
//! valid does any other check get a chance to redirect-with-error
//! instead of fail-directly.

use crate::config::config::{AppState, AuthRequest};
use crate::network::proxy::{
    find_vhost_route, is_secure_request, request_host, resolve_tag_csrf_token,
};
use crate::proto::oidc_provider::authcode::{self, AUTHCODE_TTL_SECS, AuthCodeEntry};
use actix_web::{HttpRequest, HttpResponse, http::header, web};
use serde::Deserialize;
use std::fs;
use time::OffsetDateTime;

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// A generic "something's wrong with this request itself, before we
/// even know a safe place to send you back to" page — only ever shown
/// for the `client_id`/`redirect_uri` failure mode described in this
/// module's own doc comment above. Deliberately plain: this is a
/// misconfiguration or a tampered link, not a normal user-facing flow
/// a relying party would want styled.
fn misconfigured_request_response(detail: &str) -> HttpResponse {
    HttpResponse::BadRequest()
        .append_header(("server", "ProxyAuth"))
        .content_type("text/plain")
        .body(format!("400 Bad Request — {detail}"))
}

/// Builds a `redirect_uri?error=...&error_description=...&state=...`
/// redirect — used for every validation failure *after*
/// `client_id`/`redirect_uri` are already confirmed valid. `state` is
/// echoed back exactly as received (even if empty/absent) — the
/// relying party needs it to match up this response with the request
/// it made, same as it would for a success.
fn error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> HttpResponse {
    let mut location = format!(
        "{redirect_uri}{sep}error={error}&error_description={desc}",
        sep = if redirect_uri.contains('?') { "&" } else { "?" },
        desc = urlencoding::encode(description),
    );
    if let Some(s) = state {
        location.push_str("&state=");
        location.push_str(&urlencoding::encode(s));
    }
    HttpResponse::Found()
        .append_header((header::LOCATION, location))
        .finish()
}

pub async fn authorize_handler(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> HttpResponse {
    let Some(host) = request_host(&req) else {
        return misconfigured_request_response("could not determine the requested host");
    };

    let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) else {
        return misconfigured_request_response("unknown vhost");
    };

    let Some(oidc) = &rule.oidc else {
        return misconfigured_request_response("OIDC is not enabled for this vhost");
    };

    let params: AuthorizeParams = match serde_urlencoded::from_str(req.query_string()) {
        Ok(p) => p,
        Err(_) => return misconfigured_request_response("malformed query parameters"),
    };

    // client_id / redirect_uri — validated first, independently of
    // everything else, and NEVER redirected to on failure. See this
    // module's own doc comment for why.
    let Some(client_id) = params.client_id.as_deref() else {
        return misconfigured_request_response("missing client_id");
    };
    if client_id != oidc.client_id {
        return misconfigured_request_response("unknown client_id");
    }

    let Some(redirect_uri) = params.redirect_uri.as_deref() else {
        return misconfigured_request_response("missing redirect_uri");
    };
    // Exact match only — see OidcProviderConfig::redirect_uris's own
    // doc comment for why this can never be prefix/wildcard matching.
    if !oidc
        .redirect_uris
        .iter()
        .any(|allowed| allowed == redirect_uri)
    {
        return misconfigured_request_response("redirect_uri is not registered for this client");
    }

    // Every check from here on can safely redirect-with-error, since
    // redirect_uri is now a confirmed-valid destination for this
    // client.
    let state = params.state.as_deref();

    if params.response_type.as_deref() != Some("code") {
        return error_redirect(
            redirect_uri,
            "unsupported_response_type",
            "only response_type=code is supported",
            state,
        );
    }

    let scopes: Vec<&str> = params.scope.split_whitespace().collect();
    if !scopes.contains(&"openid") {
        return error_redirect(
            redirect_uri,
            "invalid_scope",
            "the openid scope is required",
            state,
        );
    }

    // PKCE is mandatory, not optional — see this crate's own security
    // stance on this (no confidential-client exemption). S256 only;
    // "plain" is deliberately not accepted.
    let Some(code_challenge) = params.code_challenge.filter(|s| !s.is_empty()) else {
        return error_redirect(
            redirect_uri,
            "invalid_request",
            "code_challenge is required",
            state,
        );
    };
    if params.code_challenge_method.as_deref() != Some("S256") {
        return error_redirect(
            redirect_uri,
            "invalid_request",
            "code_challenge_method must be S256",
            state,
        );
    }

    // Determines who's logging in, and — for a successful POST login
    // — the `Set-Cookie` header to attach to the eventual redirect, so
    // a returning visit to this vhost's other routes (proxied
    // straight to the backend, but the backend itself may reuse
    // ProxyAuth session semantics elsewhere) and a repeat `/oidc/authorize`
    // both see the new session.
    let mut set_cookie: Option<String> = None;

    let username: Option<String> = if req.method() == actix_web::http::Method::POST {
        let form: AuthRequest = match serde_urlencoded::from_bytes(&body) {
            Ok(f) => f,
            Err(_) => return render_login_form(&req, &data, rule, Some("Malformed login request")),
        };

        let csrf_enabled = rule.csrf_enabled(&data.config);
        if csrf_enabled {
            let submitted = form.csrf_token.as_deref().unwrap_or("");
            if !crate::token::csrf::verify_csrf_token(&data.config.secret, submitted) {
                return render_login_form(
                    &req,
                    &data,
                    rule,
                    Some("Invalid or expired form — please try again"),
                );
            }
        }

        let ip = crate::network::proxy::client_ip(&req, &data.config)
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let combined_users = data.config.combined_users();

        match crate::token::auth::check_login_credentials(
            &data,
            &combined_users,
            Some(rule),
            &form.username,
            &form.password,
            form.totp_code.as_deref(),
            &ip,
        )
        .await
        {
            crate::token::auth::LoginResult::Ok(user) => {
                let index_user = combined_users
                    .iter()
                    .position(|u| std::ptr::eq(u, user))
                    .expect("matched user must be present in combined_users");
                let max_age = rule.resolved_max_age_session_cookie(&data.config);
                let (_bearer, cookie_header) = crate::token::auth::establish_session(
                    &user.username,
                    index_user,
                    &data.config,
                    max_age,
                );
                set_cookie = Some(cookie_header);
                Some(user.username.clone())
            }
            crate::token::auth::LoginResult::Denied(msg) => {
                return render_login_form(&req, &data, rule, Some(msg));
            }
            crate::token::auth::LoginResult::MustChangePassword(user) => {
                // Completing a password change mid-authorization-code
                // flow isn't wired up yet — see this branch's own
                // limitation noted in OidcProviderConfig's docs.
                // Logged with the username specifically so an
                // operator seeing repeated OIDC login failures for one
                // account has an actual lead, rather than just "some
                // login failed somewhere."
                tracing::warn!(
                    "OIDC login for {} blocked: password must be changed, but the OIDC provider's login step doesn't support completing that flow yet",
                    user.username
                );
                return render_login_form(
                    &req,
                    &data,
                    rule,
                    Some(
                        "Your password must be changed before you can sign in here — contact an administrator",
                    ),
                );
            }
        }
    } else {
        // GET — resolve any existing ProxyAuth session, same
        // Authorization-header-then-session-cookie resolution
        // `check_static_auth` already uses for a `required_login`
        // route.
        let token_header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string())
            .or_else(|| {
                if !is_secure_request(&req, &data.config) {
                    return None;
                }
                req.headers()
                    .get(header::COOKIE)
                    .and_then(|val| val.to_str().ok())
                    .and_then(|cookie_str| {
                        cookie_str.split(';').find_map(|cookie| {
                            let cookie = cookie.trim();
                            let (key, value) = cookie.split_once('=')?;
                            (key.trim() == "session_token").then(|| value.trim().to_string())
                        })
                    })
            });

        match token_header {
            Some(token) => {
                let ip = crate::network::proxy::client_ip(&req, &data.config)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                match crate::token::security::validate_token(&token, &data, &data.config, &ip).await
                {
                    Ok((username, _token_id, _expiry)) => Some(username),
                    Err(_) => None,
                }
            }
            None => None,
        }
    };

    let Some(username) = username else {
        // No session (GET) and not a POST login attempt — show the
        // login form. See this module's own doc comment for why
        // `/oidc/authorize` renders this itself rather than redirecting
        // anywhere: this vhost has `oidc:` configured, so "/" and
        // every other path (including the global `/auth`) proxy
        // straight through to the backend rather than being served by
        // ProxyAuth (see `RouteRule::oidc`'s own doc comment) — there
        // is no other ProxyAuth-served page reachable on this vhost to
        // redirect to.
        return render_login_form(&req, &data, rule, None);
    };

    // Authenticated — issue a code and send the browser back to the
    // relying party.
    let entry = AuthCodeEntry {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        username,
        scope: params.scope.clone(),
        nonce: params.nonce.clone(),
        code_challenge,
        code_challenge_method: "S256".to_string(),
        expires_at: OffsetDateTime::now_utc().unix_timestamp() + AUTHCODE_TTL_SECS,
    };

    let code = match authcode::create_code(entry) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create OIDC authorization code: {e}");
            return error_redirect(
                redirect_uri,
                "server_error",
                "failed to issue an authorization code",
                state,
            );
        }
    };

    let mut location = format!(
        "{redirect_uri}{sep}code={code}",
        sep = if redirect_uri.contains('?') { "&" } else { "?" },
    );
    if let Some(s) = state {
        location.push_str("&state=");
        location.push_str(&urlencoding::encode(s));
    }

    let mut resp = HttpResponse::Found();
    resp.append_header((header::LOCATION, location));
    if let Some(cookie_header) = set_cookie {
        resp.append_header((header::SET_COOKIE, cookie_header));
    }
    resp.finish()
}

/// Minimal HTML-entity escaping — this module only ever embeds two
/// kinds of values into raw HTML: a CSRF token (server-generated, not
/// attacker-controlled) and a URL built entirely from already-encoded
/// components. Neither is expected to contain anything needing
/// escaping in practice, but every value landing inside an HTML
/// attribute here goes through this regardless — cheap insurance
/// against ever reintroducing this function later for a genuinely
/// user-controlled value without remembering escaping is needed then.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The built-in login page shown when a vhost's `oidc:` block doesn't
/// set its own `login_page` — unstyled but fully functional,
/// specifically so getting OIDC working at all never depends on an
/// operator first building a custom page. `form` is the same
/// `{{ form }}` content a custom `login_page` would receive.
fn default_login_page(form: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0a0b0d; color: #e8eaf0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
form {{ background: #111318; border: 1px solid #2a2f3d; border-radius: 12px; padding: 32px; width: 320px; }}
h1 {{ font-size: 18px; margin: 0 0 20px; }}
label {{ display: block; margin-bottom: 14px; font-size: 13px; color: #9da3b8; }}
input {{ display: block; width: 100%; margin-top: 6px; padding: 9px 10px; background: #1a1d25; border: 1px solid #363d52; border-radius: 6px; color: #e8eaf0; font-size: 14px; box-sizing: border-box; }}
button {{ width: 100%; padding: 10px; background: #e8ff47; color: #0a0a0a; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; margin-top: 6px; }}
</style></head>
<body>
{form}
</body></html>"#
    )
}

/// Renders the login step — either the built-in default form, or an
/// operator-provided static page (`oidc.login_page`) with
/// `{{ form }}`/`{{ form_totp }}`/`{{ auth_action }}` substituted (see
/// `OidcProviderConfig`'s own doc comment for exactly what each
/// expands to). Called both when a `GET /authorize` finds no existing
/// session, and when a `POST /authorize` login attempt itself is
/// rejected (`error` carries why, shown above the form).
///
/// Submits to **`POST /authorize` itself** — not the global `/auth` —
/// carrying the exact same query string this request itself has, so
/// the full `client_id`/`redirect_uri`/`code_challenge`/etc. survive
/// the round trip. This vhost has `oidc:` configured, which means
/// every other path — including the global `/auth` and `/logout` —
/// proxies straight through to the backend rather than being served
/// by ProxyAuth (see `RouteRule::oidc`'s own doc comment on why
/// *everything* not explicitly part of the OIDC provider surface is
/// pass-through on such a vhost); `/oidc/authorize` handling its own login
/// step, rather than depending on `/auth` being reachable, is what
/// makes that rule have no exception.
fn render_login_form(
    req: &HttpRequest,
    data: &web::Data<AppState>,
    rule: &crate::config::config::RouteRule,
    error: Option<&str>,
) -> HttpResponse {
    let auth_action = format!("/oidc/authorize?{}", req.query_string());

    let csrf_token = resolve_tag_csrf_token(rule, &data.config);
    let csrf_field = csrf_token
        .as_deref()
        .map(|token| {
            format!(
                r#"<input type="hidden" name="csrf_token" value="{}">"#,
                html_escape(token)
            )
        })
        .unwrap_or_default();

    let form_totp = if rule.resolved_login_via_otp(&data.config) {
        r#"<label>TOTP code<input type="text" name="totp_code" inputmode="numeric" autocomplete="one-time-code"></label>"#
    } else {
        ""
    };

    let error_banner = error
        .map(|msg| {
            format!(
                r#"<p style="color:#ef4444;font-size:13px;margin:0 0 14px">{}</p>"#,
                html_escape(msg)
            )
        })
        .unwrap_or_default();

    // The complete, ready-to-use `{{ form }}` — everything needed to
    // log in wired up correctly, including `form_totp` already in
    // place. An operator using `{{ form }}` as-is never needs to
    // think about the submit target, CSRF, whether TOTP applies to
    // this vhost, or a failed-attempt error message; all of that is
    // already resolved by the time this string exists.
    let form = format!(
        r#"<form method="POST" action="{action}">
<h1>Sign in to continue</h1>
{error_banner}
{csrf_field}
<label>Username<input type="text" name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
{form_totp}
<button type="submit">Sign in</button>
</form>"#,
        action = html_escape(&auth_action),
    );

    let html = match rule.oidc.as_ref().and_then(|o| o.login_page.as_deref()) {
        Some(path) => match fs::read_to_string(path) {
            Ok(template) => {
                let mut page = template
                    .replace("{{ form }}", &form)
                    .replace("{{form}}", &form)
                    .replace("{{ form_totp }}", form_totp)
                    .replace("{{form_totp}}", form_totp)
                    .replace("{{ auth_action }}", &html_escape(&auth_action))
                    .replace("{{auth_action}}", &html_escape(&auth_action));
                // Reuses the same general-purpose substitution
                // `tag_proxyauth` static files already get, so a
                // custom login page hand-building its own form
                // instead of using `{{ form }}` wholesale can still
                // reach `{{ csrf_token }}` directly, plus
                // `{{ proxyauth_version }}`/`{{ proxyauth_id }}` for a
                // footer or similar. `username` is always `None` here
                // specifically — this function only ever runs before
                // anyone's authenticated.
                page = crate::network::proxy::substitute_proxyauth_tags(
                    &page,
                    None,
                    csrf_token.as_deref(),
                );
                page
            }
            Err(e) => {
                tracing::error!(
                    "OIDC login_page configured at {path:?} but could not be read: {e} — falling back to the built-in default login page"
                );
                default_login_page(&form)
            }
        },
        None => default_login_page(&form),
    };

    HttpResponse::Ok()
        .append_header(("server", "ProxyAuth"))
        .content_type("text/html; charset=utf-8")
        .body(html)
}
