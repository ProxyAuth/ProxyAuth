//! Per-vhost OIDC provider configuration — the `oidc:` block in
//! `routes.yml` (`RouteRule::oidc`/`VhostGroup::oidc`).

use serde::{Deserialize, Serialize};

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

/// Registers exactly one relying party (the backend sitting behind
/// this vhost) as allowed to use this vhost as its OIDC provider.
///
/// Deliberately one client per vhost, not a list — an OIDC provider
/// serving multiple relying parties per issuer is a real pattern
/// (Keycloak-style "realm with many clients"), but ProxyAuth's own
/// model is already "one vhost, one backend" everywhere else
/// (`target:`, `backends:`), and matching that here keeps the
/// `oidc:` block answering one question — "which backend, at which
/// callback URL, is allowed to receive tokens for this vhost's
/// identity" — rather than becoming its own nested client registry.
/// A deployment that genuinely needs several relying parties per
/// issuer can still do so with several vhosts sharing the same
/// backend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcProviderConfig {
    /// The identifier the backend presents at `/oidc/token` (and that
    /// shows up in tokens as the `aud` claim). Not secret — this is
    /// the OAuth2 `client_id`, meant to be public, the same way a
    /// browser's own `client_id` in a public OAuth flow is.
    pub client_id: String,

    /// Argon2id hash of the client secret, verified the same way a
    /// user password is (`argon2::PasswordHash`) — never stored or
    /// compared as plaintext, never logged. Generated once when the
    /// client is registered; there's no user-facing "login" for a
    /// client secret to be typed into repeatedly, so the usual
    /// password UX concerns (must-remember, forgot-password) don't
    /// apply — treat it as a long random token, not something a human
    /// picks.
    pub client_secret_hash: String,

    /// Exact-match allow-list of URIs an authorization code may be
    /// redirected to. **No prefix or wildcard matching** — the
    /// classic OIDC/OAuth2 vulnerability this guards against is an
    /// attacker registering (or finding) an open-redirect-adjacent
    /// path under a trusted host and using it to exfiltrate a
    /// legitimate authorization code. Every `redirect_uri` a client
    /// sends to `/oidc/authorize` must appear in this list byte-for-byte.
    pub redirect_uris: Vec<String>,

    /// Exact-match allow-list of URIs RP-Initiated Logout may send the
    /// browser to after clearing this instance's session — same
    /// reasoning and same discipline as `redirect_uris`: no prefix or
    /// wildcard matching, every `post_logout_redirect_uri` a client
    /// sends to the logout endpoint must appear here byte-for-byte.
    /// Empty (the default) means logout still clears the session but
    /// never redirects anywhere afterward regardless of what a caller
    /// asks for.
    #[serde(default)]
    pub logout_redirect_uris: Vec<String>,

    /// Scopes this client may request. `openid` is always implicitly
    /// required by the protocol itself regardless of what's listed
    /// here; this list controls which of `profile`/`email`/any custom
    /// scopes ProxyAuth will actually honor for this specific client
    /// even if requested.
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,

    /// Path to a static HTML file to serve as the login page
    /// `/oidc/authorize` shows an unauthenticated visitor, instead of the
    /// built-in default form. Rendered with three tags specific to
    /// this context, substituted before the general `tag_proxyauth`
    /// set (`{{ csrf_token }}`, `{{ proxyauth_version }}`, …, all
    /// still available here too):
    ///
    /// - `{{ form }}` — a complete, ready-to-use `<form>`: the
    ///   correct dynamic `action` (carrying `return_to` back to this
    ///   exact `/oidc/authorize` request), a CSRF field if CSRF is enabled
    ///   for this vhost, username/password inputs, the TOTP field if
    ///   `login_via_otp` resolves to true for this vhost, and a
    ///   submit button. Drop it in and it works.
    /// - `{{ form_totp }}` — just the TOTP input on its own (empty
    ///   string if `login_via_otp` is off) — for building a custom
    ///   form by hand instead of using `{{ form }}` wholesale, e.g. a
    ///   two-step UX that hides this behind a "next" click/reveals it
    ///   with a few lines of JS after username/password are entered.
    ///   Still submits in the same request as everything else in
    ///   whatever `<form>` it ends up inside — TOTP has always been
    ///   verified alongside username/password in one request, not a
    ///   separate step server-side, so this is presentation only.
    /// - `{{ auth_action }}` — just the dynamic form `action` URL, for
    ///   building the `<form method="POST" action="{{ auth_action }}">`
    ///   wrapper by hand.
    ///
    /// `None` (the default) uses a built-in, unstyled but fully
    /// functional form — nothing to configure to get OIDC working,
    /// this is purely for operators who want their own branding.
    #[serde(default)]
    pub login_page: Option<String>,
}
