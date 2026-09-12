use crate::adm::method_otp::generate_base32_secret;
use crate::network::stats::RequestStats;
use crate::revoke::db::RevokedTokenMap;
use crate::smtp::smtp::SmtpConfig;
use crate::stats::tokencount::CounterToken;
use crate::token::auth::generate_random_string;
use arc_swap::ArcSwap;
use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher};
use dashmap::DashMap;
use ipnet::IpNet;
use regex::Regex;
use serde::Deserializer;
use serde::de::MapAccess;
use serde::de::Visitor;
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;

// Re-exported here so the rest of the codebase keeps importing every
// config type from a single path (`crate::config::config::*`), as it
// already did before these two blocks were split into their own
// modules to keep this file from growing further.
pub use crate::config::acme::AcmeConfig;
pub use crate::config::compression::CompressionConfig;
pub use crate::config::logging::LoggingConfig;

#[derive(Debug, Clone)]
pub struct CompiledAllow {
    pub default_allow: bool,
    pub allow: Vec<RegexCond>,
}

#[derive(Debug, Clone)]
pub enum RegexCond {
    Method { re: Regex },
    Path { re: Regex },
    Header { name_re: Regex, re: Regex },
    Query { name_re: Regex, re: Regex },
    BodyRaw { re: Regex },
    BodyJson { key: String, re: Regex },
}

/// Maintenance-mode style gate: every visitor whose IP is *not* on
/// `allow_ip` gets served the static file at `path` — whatever it is,
/// HTML page, image, anything `guess_content_type` can identify —
/// instead of this route's normal content, with a `503 Service
/// Unavailable` status (the correct HTTP semantics for "temporarily
/// unavailable," as opposed to `200`, which would tell caches/crawlers
/// this *is* the real content). A visitor whose IP *is* on `allow_ip`
/// is completely unaffected — normal routing, proxying, and auth all
/// continue exactly as configured. Leaving `allow_ip` empty (the
/// default) is genuine "maintenance mode for everyone," rather than
/// needing to spell out a `"0.0.0.0/0"`-style catch-all.
///
/// Checked as early as possible in `network::proxy::global_proxy` —
/// after IP blocklisting and ACME challenge handling (a certificate
/// renewal must never be blocked by this), but before everything else,
/// including OIDC discovery and normal routing — so nothing else this
/// route would otherwise do (auth, CSRF, proxying) gets a chance to
/// run for a visitor this gate turns away.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RedirectProtectConfig {
    /// The only IPs/CIDR ranges allowed normal access to this route —
    /// every visitor whose IP isn't in here gets `path` instead, with
    /// a `503 Service Unavailable` status. Empty (the default) allows
    /// nobody through, meaning every visitor is redirected — the
    /// simplest way to write "maintenance mode for everyone" is just
    /// leaving this empty, rather than having to spell out a
    /// `"0.0.0.0/0"`-style catch-all. Same `IpNet`-based matching
    /// `User::allow`/`is_ip_allowed` already uses elsewhere in this
    /// codebase, not a separate implementation.
    pub allow_ip: Vec<String>,

    /// A remote/local source — same shape as `AppConfig.ip_blocklists`'
    /// own entries (plain text or CSV, gzip or not, auto-detected) —
    /// fetched and merged into the effective allow-list alongside
    /// `allow_ip`. Refetched on `redirect_protect_refresh_interval_secs`
    /// (in `AppConfig`), the same "cache the last good fetch, degrade
    /// rather than fail on a transient outage" behavior
    /// `network::ipblocklist` already has for the abuse-blocklist
    /// feature — reused here rather than reimplemented, since the
    /// operational shape (a third-party feed an admin doesn't control)
    /// is identical.
    #[serde(default)]
    pub allow_url_ips: Option<IpBlocklistSource>,

    /// Same source shape as `allow_url_ips`, but the opposite
    /// direction: an IP matching this list is redirected even if
    /// `allow_ip`/`allow_url_ips` would otherwise have let it through
    /// — checked first, deny always wins. Useful for "allow this whole
    /// office CIDR range except the one machine that's separately
    /// known-compromised," published as its own feed.
    #[serde(default)]
    pub deny_url_ips: Option<IpBlocklistSource>,

    /// Extra, path-scoped gates layered on top of the `allow_ip`/
    /// `allow_url_ips` check above — not a replacement for it. A
    /// visitor already on the allow-list still has to satisfy every
    /// `ProtectedPathRule` whose `regex` matches the request path, on
    /// top of being IP-allowed in the first place. Meant for a
    /// sensitive sub-path (an admin panel, an internal dashboard)
    /// living under an otherwise-normal route: the rest of the route
    /// only needs the IP check, this one path also needs a genuine,
    /// currently-valid ProxyAuth login.
    #[serde(default)]
    pub paths: Vec<ProtectedPathRule>,

    /// A URL to send a visitor to with a real `303 See Other` — not a
    /// proxied response, an actual `Location` header the browser
    /// itself navigates to — when any `paths` rule's
    /// session check fails. Shared across every rule in
    /// `paths`; there's one place a blocked visitor gets
    /// sent, not a different one per rule. Distinct from `target`
    /// below, which is a genuinely different mechanism used for the
    /// `allow_ip`/`allow_url_ips` check instead: that one forwards
    /// the *entire* request through to another backend and returns
    /// its response directly, this one just says "go here instead,"
    /// the same as pointing someone at a login page. Optional — when
    /// unset, a failed `paths` check falls through to
    /// `target`/`path` below instead, exactly as before this field
    /// existed.
    #[serde(default)]
    pub redirect_url: Option<String>,

    /// Absolute path to the static file to serve for a visitor not on
    /// `allow_ip`. Read fresh on every matching request rather than
    /// cached — a maintenance page is exactly the kind of content an
    /// operator expects to be able to edit and see reflected
    /// immediately, without restarting ProxyAuth. Optional; the
    /// fallback if `target` below is either unset or unreachable. If
    /// neither `path` nor `target` resolves to anything usable — both
    /// unset, `target` failing with no `path` configured to fall back
    /// to, or `path` itself unreadable — the visitor gets a bare
    /// `503` with no body, rather than this gate silently letting the
    /// request through to the route's real content.
    #[serde(default)]
    pub path: Option<String>,

    /// Backend URL to proxy a blocked request to instead of serving
    /// `path` — the original method, headers, and body all forwarded,
    /// same as a normal proxied route would. Optional; when set, this
    /// is tried first, and only falls back to `path` (if that's also
    /// set) if reaching `target` itself fails (connection error,
    /// timeout, or an invalid URL). Useful for pointing a blocked
    /// visitor at a real maintenance-page service or status page
    /// hosted somewhere else entirely, rather than a file that has to
    /// live on this exact machine. At least one of `path`/`target`
    /// should normally be set — see `path`'s own doc comment for what
    /// happens if neither is.
    #[serde(default)]
    pub target: Option<String>,

    /// `allow_ip` parsed into `IpNet` once at startup — see
    /// `compile_ip_lists_on_routes`'s own doc comment for why (a fatal
    /// error on a bad entry, and no re-parsing on every request).
    #[serde(skip)]
    pub allow_ip_compiled: Vec<IpNet>,
}

/// One path-scoped session gate under `RedirectProtectConfig.paths`
/// — a request whose path matches `regex` must prove its session is
/// genuinely valid, on top of the `allow_ip`/`allow_url_ips` check
/// above, or it's redirected the same way an IP not on the allow-list
/// would be. Verified by asking the backend itself (see `check_path`
/// below) rather than checking ProxyAuth's own `session_token` — this
/// is genuine authentication, delegated to whatever the backend's own
/// auth scheme actually is, not a hidden bypass value.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProtectedPathRule {
    /// Matched against the request path the same way `RouteRule.regex`
    /// is — searched anywhere in the path by default; add `^`/`$`
    /// yourself for an exact match.
    pub regex: String,

    #[serde(skip)]
    pub regex_compiled: Option<Regex>,

    /// A path on this route's own backend to probe, e.g. `"/api/user"`
    /// — appended to `target` (the leading `/` is expected as part of
    /// this value). ProxyAuth issues a real request there, forwarding
    /// the original request's `Cookie` header unchanged, and checks
    /// the response the way `type_return` says to. This is
    /// deliberately not tied to `session_token` or any
    /// ProxyAuth-specific mechanism: the backend decides what
    /// "authenticated" means for its own session, the same as it
    /// always does for every normal request that actually reaches it
    /// — including on an `oidc:`-enabled vhost, where ProxyAuth's own
    /// session cookie isn't the authority to begin with. A short
    /// timeout applies (see where this is used in `network/proxy.rs`)
    /// — a slow or unreachable backend fails the check rather than
    /// holding the request open.
    pub check_path: String,

    /// How to decide whether `check_path`'s response means "session
    /// valid" — `"status_code"` (the default) or `"json"`. Most
    /// backends already answer this question in their status code
    /// alone: a session-protected endpoint typically already returns
    /// `401`, or redirects to a login page (`302`/`303`) — neither is
    /// `2xx`, so status-code checking already gets the right answer
    /// with nothing further to configure. Reach for `"json"` only
    /// when a `2xx` alone isn't precise enough — e.g. `check_path`
    /// might land on something that returns success for reasons
    /// unrelated to this specific session being valid, and a known
    /// field's value is what actually proves it.
    #[serde(default)]
    pub type_return: CheckReturnType,

    /// Only used when `type_return` is `"status_code"`. The exact
    /// status this response must have to count as "valid" — `None`
    /// (the default) accepts any `2xx`. Set this when the success
    /// case is a specific code (e.g. exactly `200`, not `204`), or
    /// when being explicit is simply preferred over "any success
    /// code" — either way, anything else, including a redirect to a
    /// login page, fails the check.
    #[serde(default)]
    pub expected_status: Option<u16>,

    /// Only used when `type_return` is `"json"`. A field to look up
    /// in `check_path`'s response body, parsed as JSON — top-level
    /// only, e.g. `"authenticated"` for a body like
    /// `{"authenticated": true}`. Required in `"json"` mode; a rule
    /// set to `"json"` with no `expected_field` never passes, since
    /// there'd be nothing left to actually check.
    #[serde(default)]
    pub expected_field: Option<String>,

    /// Only used when `type_return` is `"json"`, alongside
    /// `expected_field`. The value that field must equal — compared
    /// against the JSON value's natural string form (a JSON string
    /// compares by its own content with no added quotes, a
    /// bool/number by its usual display form, e.g. `"true"`/`"200"`).
    /// Left unset, the field's mere presence with a scalar value is
    /// enough on its own.
    #[serde(default)]
    pub expected_value: Option<String>,

    /// Elements to conditionally strip from this section's own HTML
    /// output — using the exact same check result as this `paths`
    /// entry's own `check_path`/`type_return` above, not a separate
    /// check per element. Setting `hidden_blocks` changes what that
    /// check actually does, though: a `paths` entry with at least one
    /// `hidden_blocks` rule no longer redirects or blocks the path at
    /// all on a failed check — the request goes through normally, and
    /// the check result is applied to the response HTML instead,
    /// hiding or replacing the targeted element(s). A `paths` entry
    /// with no `hidden_blocks` keeps its original job of gating the
    /// whole path. Runs independently of `tag_proxyauth` — this and
    /// `{{ }}` tag substitution happen to share the same
    /// response-scanning pass for efficiency, but a route with
    /// `hidden_blocks` configured gets that pass regardless of
    /// whether `tag_proxyauth` is set at all (see
    /// `RouteRule::has_hidden_blocks`). Each rule targets one element
    /// by pasting its exact opening tag verbatim — see
    /// `HiddenBlockRule::html_tag` — and removes the whole element,
    /// opening tag through its matching closing tag, nesting handled.
    /// Empty by default: no content is ever removed, and the path
    /// keeps gating normally, unless explicitly configured here.
    #[serde(default)]
    pub hidden_blocks: Vec<HiddenBlockRule>,
}

/// One conditional HTML block under `ProtectedPathRule.hidden_blocks`
/// — see that field's own doc comment for how it's applied. Carries
/// no check of its own on purpose: the session check already ran
/// once for the enclosing `paths` entry (its own `check_path`/
/// `type_return`/etc.), and that single result is reused for every
/// `hidden_blocks` rule under it, rather than triggering a separate
/// backend request per element.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HiddenBlockRule {
    /// The exact opening tag to search for, copied verbatim from the
    /// page's own HTML — e.g. `<div id="toto" class="admin-only">`.
    /// ProxyAuth searches for this literal text, works out the tag
    /// name from it (`div` here, but any tag name works — `<section
    /// id="panel">`, `<span class="warn">`, anything), and finds the
    /// matching closing tag itself, nesting of the same tag name
    /// handled correctly along the way. No need to separately specify
    /// which attribute identifies the element — whatever's pasted
    /// here, attributes and all, is searched for as-is. If this exact
    /// text isn't found in the response, the rule is a silent no-op —
    /// the page simply doesn't have anything for it to act on, not a
    /// configuration error.
    pub html_tag: String,

    /// HTML to put in the element's place when the enclosing `paths`
    /// entry's check fails, instead of removing it outright — e.g. a
    /// "you don't have permission to view this" message. Left unset,
    /// a failed check simply removes the whole element with nothing
    /// left behind.
    #[serde(default)]
    pub fallback_html: Option<String>,
}

/// How `ProtectedPathRule.check_path`'s response is interpreted.
/// `StatusCode` (the default) is the common case and needs nothing
/// further configured; `Json` is the narrower, more precise
/// alternative for the routes where a bare `2xx` genuinely isn't
/// enough to trust. See `ProtectedPathRule::type_return`'s own doc
/// comment for when to reach for which.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckReturnType {
    #[default]
    StatusCode,
    Json,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RouteRule {
    /// Virtual hosts this route answers on, matched against the
    /// incoming request's `Host` header (port stripped, compared
    /// case-insensitively) — e.g. `["app.example.com"]`.
    ///
    /// Left empty (the default), the route is a catch-all: it matches
    /// on *any* host, exactly like before `vhost` existed. This keeps
    /// every pre-existing `routes.yml` working unchanged.
    ///
    /// Several routes can share the same `prefix` as long as they list
    /// different `vhost`s — the request's `Host` header picks which
    /// one applies before the usual longest-prefix matching happens.
    /// This is what lets one ProxyAuth instance front several
    /// frontend domains, each proxying its own set of prefixes to its
    /// own backend(s).
    #[serde(default = "default_vhost")]
    pub vhost: Vec<String>,

    /// Optional TLS certificate/key ProxyAuth should present when a
    /// client connects for one of the hostnames listed in `vhost`
    /// (Server Name Indication) — lets each vhost serve its own
    /// certificate instead of the single global one configured for
    /// the server. Two keys are recognized:
    ///   - `cert`: path to the PEM certificate (chain)
    ///   - `key`:  path to the PEM private key
    ///
    /// Left empty (the default), connections for these hostnames fall
    /// back to the server's global TLS certificate — exactly as if
    /// `vhost_cert` had never been set. Ignored entirely when `vhost`
    /// is empty, and when the server isn't running with `tls: true`.
    /// Like the global certificate, files listed here are watched and
    /// hot-reloaded without restarting the server.
    #[serde(default = "default_vhost_cert")]
    pub vhost_cert: HashMap<String, String>,

    /// Extra response headers to add for this route — CSP
    /// (`Content-Security-Policy`), HSTS, `X-Frame-Options`,
    /// `Referrer-Policy`, `Permissions-Policy`, or any other header
    /// you want set. Each entry is `"Header-Name": "value"`; the
    /// value is used verbatim (a CSP policy's semicolon-separated
    /// directives all go in the one string, exactly as the header
    /// itself is written on the wire — ProxyAuth doesn't parse or
    /// validate CSP syntax, just sets what you give it). Applied to
    /// every response this route produces — proxied, static, and
    /// error/redirect responses alike. If this route belongs to a
    /// `vhosts:` group that also sets `headers`, the two are merged;
    /// this route's own value wins on a key both define.
    #[serde(default = "default_headers")]
    pub headers: HashMap<String, String>,

    /// Enables automatic Let's Encrypt certificate renewal for this
    /// vhost — see the `acme` module and `AppConfig.acme` for the
    /// full mechanism. Requires `vhost` to be set (the certificate is
    /// issued for those hostnames) and `vhost_cert` to already point
    /// at `/etc/proxyauth/cert/{vhost}/fullchain.pem` and
    /// `.../privkey.pem` — ACME writes to those exact paths, and the
    /// *existing* `vhost_cert` file-watcher (the same one that
    /// already hot-reloads a manually-replaced certificate) is what
    /// actually picks up the renewed certificate; nothing new is
    /// introduced for that part. If more than one route shares a
    /// `vhost`, setting this on any one of them is enough — it's
    /// treated as a per-vhost switch, not a per-route one.
    ///
    /// `certbot_rew` is also still accepted as an alias for this key,
    /// matching this feature's original (misspelled) name.
    #[serde(default, alias = "certbot_rew")]
    pub certbot_renew: bool,

    /// IP/CIDR allow-list for this route (e.g. `["192.168.1.0/24",
    /// "10.0.0.5"]`) — when non-empty, only clients whose resolved IP
    /// (same trusted-proxy-aware resolution the rate limiter and
    /// `X-Forwarded-For` handling already use) falls inside one of these
    /// networks may reach this route; everyone else gets a 403, before
    /// any auth/CSRF/backend work happens. Empty (the default) means no
    /// restriction — identical to every route's behavior before this
    /// field existed.
    #[serde(default)]
    pub allow_ips: Vec<String>,

    /// IP/CIDR deny-list, checked before `allow_ips` — a client matching
    /// an entry here is always rejected, even if `allow_ips` would
    /// otherwise let them through. Useful for "everyone in this range
    /// except this one host". Empty (the default) denies nobody.
    #[serde(default)]
    pub deny_ips: Vec<String>,

    #[serde(skip)]
    pub allow_ips_compiled: Vec<IpNet>,

    #[serde(skip)]
    pub deny_ips_compiled: Vec<IpNet>,

    /// Serves file(s) straight from disk instead of proxying to
    /// `target` — ProxyAuth's equivalent of nginx's `root`/`alias`.
    /// Point it at a **directory** to serve everything under it (the
    /// remainder of the request path, after this route's `prefix`, is
    /// resolved inside it — `..`/symlink escapes are rejected, and a
    /// directory-shaped request falls back to `static_index`); or at a
    /// single **file** to have this route always serve that one file
    /// regardless of the request path (handy for a fixed endpoint like
    /// `/robots.txt` or `/favicon.ico`). Which one it is is detected
    /// from what's actually on disk — no separate mode to configure.
    /// When set, `target`/`proxy`/`backends`/`cert` are simply ignored
    /// for this route; only `required_login`/`username`/`groups`/`roles`,
    /// `allow_ips`/`deny_ips` and `vhost` still apply, and only
    /// `GET`/`HEAD` are served. The YAML key is `static` (the Rust field
    /// is named `static_path` since `static` is a reserved word).
    #[serde(default, rename = "static")]
    pub static_path: Option<String>,

    /// File served when `static` points at a directory and a request
    /// resolves to a directory-shaped path within it (e.g. the route's
    /// own prefix, or any path ending in `/`). Ignored when `static`
    /// points at a single file, or isn't set at all.
    #[serde(default = "default_static_index")]
    pub static_index: String,

    /// Full regex the request path must match for this route to apply,
    /// instead of the plain-prefix matching every other route uses —
    /// ProxyAuth's equivalent of nginx's `location ~ pattern { ... }`.
    /// Searched anywhere in the path by default (add `^`/`$` yourself
    /// for an exact match, same convention as nginx/PCRE). Regex routes
    /// are always tried before every plain-prefix route; among several,
    /// the first one in `routes.yml` that matches wins.
    ///
    /// Use named capture groups (`(?<name>...)`) and reference them as
    /// `{name}` in `target` (proxy routes) or `static_rewrite` (static
    /// routes) to rewrite the upstream/file path from what was
    /// captured — nginx's `$name` equivalent. A proxy route's `target`
    /// with no `{...}` placeholder just gets the full original request
    /// path appended, unchanged (nginx's behavior for a `proxy_pass`
    /// with no URI part).
    #[serde(default)]
    pub regex: Option<String>,

    #[serde(skip)]
    pub regex_compiled: Option<Regex>,

    /// For a regex route whose `static` points at a directory: since
    /// there's no `prefix` to strip off to get a file path, this
    /// template (filled in from the regex's named captures, e.g.
    /// `"{major}.{minor}.x/{file}"`) supplies the path *under* `static`
    /// instead — same traversal protection as plain directory mode
    /// still applies to the result. Ignored for non-regex routes, and
    /// when `static` points at a single file.
    #[serde(default)]
    pub static_rewrite: Option<String>,

    pub prefix: String,

    /// Backend URL for proxied routes. Not required when `static` is
    /// set (a purely static route can omit it, or leave it empty).
    #[serde(default)]
    pub target: String,

    /// Usernames allowed to access this route (when `required_login`
    /// is `true`) — one of three ways in, alongside `groups`/`roles`
    /// below; see the doc comment on `roles` for how the three combine,
    /// including what an empty list means here.
    #[serde(default = "default_username")]
    pub username: Vec<String>,

    /// Groups allowed to access this route — checked against each
    /// user's `User.groups` via `AppConfig::groups_for_username`; see
    /// `roles` below for how `username`/`groups`/`roles` combine.
    /// Meant to avoid maintaining a per-route username list by hand —
    /// add/remove a user from a group in one place instead of editing
    /// every route they should reach.
    #[serde(default)]
    pub groups: Vec<String>,

    /// Roles allowed to access this route, checked against `User.roles`
    /// via `AppConfig::roles_for_username` — the same lookup that
    /// already feeds the `X-User-Roles` header, now also usable to
    /// gate access rather than being purely informational.
    ///
    /// `username`, `groups`, and `roles` combine as an OR: a request
    /// gets through if it matches *any* of the three — an explicitly
    /// listed username, membership in an allowed group, or possession
    /// of an allowed role.
    ///
    /// If all three are left empty, that's read as a deliberate
    /// choice — "any authenticated account may use this route" — not
    /// a misconfiguration to fail closed on; `required_login` (a
    /// valid session in the first place) still applies regardless.
    /// The moment even one of the three is non-empty, this route goes
    /// back to being allow-listed: only requests matching
    /// username/groups/roles get through.
    #[serde(default)]
    pub roles: Vec<String>,

    #[serde(default = "default_required_login")]
    pub required_login: bool,

    #[serde(default = "default_proxy")]
    pub proxy: bool,

    #[serde(default = "default_proxy_config")]
    pub proxy_config: String,

    #[serde(default = "default_cert")]
    pub cert: HashMap<String, String>,

    #[serde(default = "default_backends")]
    pub backends: Vec<BackendInput>,

    /// Whether this route requires a valid CSRF token — `None` (the
    /// default: not specified) means "inherit from the vhost group
    /// this route belongs to (if any), otherwise the global default
    /// (`true`)". An explicit `true`/`false` here always wins over the
    /// group's own `need_csrf`. Use `RouteRule::requires_csrf` to
    /// resolve the final value rather than reading this field
    /// directly — it still needs `AppConfig.csrf_token` and
    /// `session_cookie` to actually be enforced either way.
    #[serde(default)]
    pub need_csrf: Option<bool>,

    /// Whether CSRF protection is enabled *at all* for this vhost — both
    /// the server-side check on `/auth` submissions and every automatic
    /// token injection (the older `inject_csrf_token` mechanism on
    /// proxied responses, and the `tag_proxyauth` mechanism's own
    /// `{{ csrf_token }}` substitution alike) — independent of the
    /// global `AppConfig.csrf_token` default, and unlike `need_csrf`
    /// (which only decides whether *this specific route* participates
    /// once CSRF is already enabled somewhere).
    ///
    /// Named `tag_csrf_token` rather than reusing `csrf_token` (which
    /// the global `AppConfig` field is already called) specifically to
    /// avoid the two being confused for each other — this one is the
    /// full on/off switch for CSRF on this route, not just a
    /// tag-substitution detail despite the name's `tag_` prefix
    /// (kept for consistency with `tag_proxyauth`, since setting this
    /// to `false` is most often done alongside `tag_proxyauth: false`
    /// on the same static/proxied route).
    ///
    /// `None` (the default) inherits from the `vhosts:` group, then
    /// the global `csrf_token`. An explicit `true`/`false` here always
    /// wins, in either direction — this can turn CSRF ON for one vhost
    /// even while the global default is off, or OFF for one vhost
    /// while every other vhost keeps it on. Use
    /// `RouteRule::csrf_enabled` to resolve the final value.
    #[serde(default, alias = "csrf_token")]
    pub tag_csrf_token: Option<bool>,

    /// Per-vhost override of `AppConfig.session_cookie` (whether
    /// ProxyAuth issues/checks a `session_token` cookie at all, vs.
    /// bearer-token-only auth). `None` inherits from the `vhosts:`
    /// group, then the global default. Same override rules as
    /// `need_csrf`.
    #[serde(default)]
    pub session_cookie: Option<bool>,

    /// Per-vhost override of `AppConfig.max_age_session_cookie` (the
    /// session cookie's `Max-Age`, in seconds). `None` inherits from
    /// the `vhosts:` group, then the global default.
    #[serde(default)]
    pub max_age_session_cookie: Option<i64>,

    /// Per-vhost override of `AppConfig.login_redirect_url` — where an
    /// already-authenticated visitor (a still-valid `session_token`
    /// cookie) gets sent instead of the login form, and where a fresh
    /// login redirects to on success. `None` inherits from the
    /// `vhosts:` group, then the global default (`"/"` if that's also
    /// unset).
    #[serde(default)]
    pub login_redirect_url: Option<String>,

    /// Per-vhost override of `AppConfig.logout_redirect_url` — where
    /// `/logout` sends the visitor afterward. `None` inherits from the
    /// `vhosts:` group, then the global default.
    #[serde(default)]
    pub logout_redirect_url: Option<String>,

    /// Per-vhost override of `AppConfig.login_via_otp` (whether a TOTP
    /// code is required at login, in addition to username/password).
    /// `None` inherits from the `vhosts:` group, then the global
    /// default.
    #[serde(default)]
    pub login_via_otp: Option<bool>,

    /// Per-vhost override of `AppConfig.page_change_password` — the
    /// external page a password-reset link points visitors at. `None`
    /// inherits from the `vhosts:` group, then the global default (and
    /// if that's also unset, `proxyauth reset-password`/the
    /// `/reset-password` flow is unavailable for this vhost, same as
    /// today when it's unset globally).
    #[serde(default)]
    pub page_change_password: Option<String>,

    /// Per-vhost override of `AppConfig.cors_origins` — the list of
    /// origins allowed to make cross-origin requests to this vhost.
    /// `None` inherits from the `vhosts:` group, then the global
    /// default. Whole-list replacement, not merged with the global
    /// list — set every origin this vhost should allow here if you
    /// override it at all.
    #[serde(default)]
    pub cors_origins: Option<Vec<String>>,

    /// Per-vhost override of `AppConfig.smtp` — lets different
    /// domains send password-reset emails through different SMTP
    /// servers. `None` inherits from the `vhosts:` group, then the
    /// global default. Whole-object replacement (a vhost's own `smtp`
    /// block must be complete on its own — host, port, credentials,
    /// `from`, timeout — not merged field-by-field with the global
    /// block). Only read by `proxyauth reset-password --vhost
    /// <hostname>` today — see that command's own docs for why the
    /// CLI needs the vhost named explicitly rather than resolving it
    /// automatically the way a live HTTP request can.
    #[serde(default)]
    pub smtp: Option<crate::smtp::smtp::SmtpConfig>,

    /// Turns this vhost into a genuine OIDC provider for the backend
    /// sitting behind it — the backend (Grafana, Nextcloud, or
    /// anything else that natively speaks OIDC as a relying party)
    /// receives a real, independently-verifiable `id_token` via the
    /// standard authorization code flow, instead of relying on
    /// ProxyAuth's own header injection (`X-User`, `X-User-Roles`,
    /// ...) or session cookie.
    ///
    /// **When this is set, ProxyAuth's own `required_login`/session
    /// enforcement is bypassed for this vhost's proxied routes** — the
    /// backend is responsible for its own auth decision via OIDC now,
    /// the same way it would be if it sat behind any other OIDC
    /// provider. What ProxyAuth *does* still do on this vhost: serve
    /// `/.well-known/openid-configuration`, `/jwks.json`,
    /// `/authorize`, `/token`, and `/userinfo` — intercepted ahead of
    /// normal routing (see `global_proxy`) — using this vhost's own
    /// `oidc.client_id`/`redirect_uris` to decide which requests are
    /// legitimate. The rest of the vhost's traffic proxies straight
    /// through, unauthenticated by ProxyAuth itself, exactly as if
    /// `required_login` were never set.
    ///
    /// A user still authenticates against ProxyAuth's own account
    /// store (file or database, same credential/TOTP verification as
    /// everywhere else) — that happens *at* `/authorize`, packaged as
    /// the OIDC login step, not via a separate mechanism. This field
    /// changes how the *backend* receives proof of that login, not
    /// how ProxyAuth itself verifies who's logging in.
    ///
    /// No global fallback, no per-route override — this is a
    /// vhost-wide identity decision, set once on the `vhosts:` group.
    #[serde(default)]
    pub oidc: Option<crate::proto::oidc_provider::config::OidcProviderConfig>,

    /// Enables `{{ username }}`/`{{ csrf_token }}` tag substitution in
    /// this route's static files (and the shared error/logout page —
    /// see `network::error::render_error_page`). `None`/unset means
    /// `false` — deliberately conservative, not inherited-then-on:
    /// scanning every response for tags has a real cost (reading the
    /// whole body as text, running the substitution pass) that a
    /// route with no ProxyAuth tags in its content shouldn't pay for
    /// nothing. Turn it on explicitly per route or per `vhosts:`
    /// group for exactly the content that actually uses these tags.
    #[serde(default)]
    pub tag_proxyauth: Option<bool>,

    /// Adds `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`,
    /// `X-Real-IP`, and `X-Forwarded-For` to every request this route
    /// forwards to its backend — the standard reverse-proxy headers a
    /// backend needs to know the original client's real host/scheme/IP,
    /// the same information `proxy_set_header` directives provide in
    /// an nginx config. `Host` is rewritten to the original vhost's
    /// hostname (matching `proxy_set_header Host $host;`), not left as
    /// whatever the backend's own address happens to be — real
    /// end-to-end testing (a raw TCP listener on the receiving end, no
    /// HTTP library involved to introduce ambiguity about what's
    /// really on the wire) confirmed the underlying HTTP client
    /// genuinely respects an explicitly-set `Host` header rather than
    /// silently overriding it with the connection target.
    ///
    /// `X-Real-IP`/`X-Forwarded-For` are always built from ProxyAuth's
    /// own already-resolved, trusted client IP (`network::proxy::client_ip`,
    /// which itself respects `trust_proxy_forward_for`) — never a
    /// blind copy of whatever a client sent, which would let any
    /// visitor simply claim to be a different IP. More generally: a
    /// client-supplied version of any of these five headers is always
    /// excluded from the ordinary header copy-through, regardless of
    /// this setting — see `network::proxy`'s own comment on exactly
    /// why (`http::request::Builder::header` appends rather than
    /// replaces, so leaving a client's own copy in place would have
    /// sent the backend two values for the same header instead of
    /// substituting ProxyAuth's trusted one).
    ///
    /// `None`/unset means `false` — off by default, the same
    /// conservative reasoning as `tag_proxyauth`: a backend that
    /// doesn't care about these headers shouldn't have them added
    /// unconditionally, and a backend that already receives correct
    /// values some other way (e.g. from a TLS-terminating load
    /// balancer in front of ProxyAuth itself) shouldn't have this
    /// silently override that.
    #[serde(default)]
    pub forward_proxy_headers: Option<bool>,

    /// Usernames allowed to *log in* via this vhost's `/auth` — a
    /// different, earlier gate than `RouteRule::username`/`groups`/
    /// `roles` above, which only govern access to *this specific
    /// route's content* for someone already logged in. This one
    /// decides whether a login attempt on this vhost succeeds in the
    /// first place, before any session or route access even enters
    /// the picture.
    ///
    /// `allow_users`, `allow_groups`, and `allow_roles` combine as an
    /// OR, same as the route-level fields — but **the default is the
    /// opposite**: when all three are empty, login is **denied** for
    /// this vhost, not allowed. A vhost grants no login access at all
    /// until at least one of the three names someone in. This is
    /// deliberate — an operator who forgets to set any of these on a
    /// new vhost gets a vhost nobody can log into (safe, if
    /// inconvenient) rather than one anyone with valid credentials
    /// anywhere in the system can suddenly reach (unsafe by omission).
    /// See `RouteRule::login_authorized` to resolve the final
    /// decision rather than reading these fields directly.
    #[serde(default)]
    pub allow_users: Vec<String>,

    /// See `allow_users` just above for how this combines with
    /// `allow_users`/`allow_roles` and why the empty-means-denied
    /// default is intentional here specifically, unlike the
    /// route-level `groups` field.
    #[serde(default)]
    pub allow_groups: Vec<String>,

    /// See `allow_users` above for how this combines with
    /// `allow_users`/`allow_groups` and why the empty-means-denied
    /// default is intentional here specifically, unlike the
    /// route-level `roles` field.
    #[serde(default)]
    pub allow_roles: Vec<String>,

    /// Usernames explicitly denied login on this vhost, regardless of
    /// `allow_users`/`allow_groups`/`allow_roles` — an exclusion
    /// always wins over an allow rule, even if the same username is
    /// also separately allow-listed or belongs to an allowed group or
    /// role. For carving out an exception without having to restructure
    /// the allow lists themselves — e.g. every member of an allowed
    /// group *except* one specific account.
    #[serde(default)]
    pub exclude_users: Vec<String>,

    /// ⚠️ **Security trade-off, opt-in and off by default.** When
    /// `true`, a user who already has a TOTP secret enrolled can
    /// re-enroll — getting a brand-new secret and QR/URI, silently
    /// replacing the old one — via `/adm/auth/totp/get` using nothing
    /// but their username and password, the same way first-time
    /// enrollment already works. Normally that endpoint refuses with
    /// `409 Conflict` once a secret already exists specifically to
    /// prevent this: without this flag, only an admin can clear an
    /// existing secret (`proxyauth reset-otp` /
    /// `/adm/auth/totp/reset`, gated by `token_admin`) before
    /// re-enrollment is possible again.
    ///
    /// Turning this on means **anyone who obtains a user's password
    /// can also take over their TOTP factor** — no admin, no
    /// possession of the old authenticator app, no separate approval
    /// step. For an account this is true for, TOTP no longer protects
    /// against a stolen/guessed password the way two-factor
    /// authentication is meant to; it only continues to protect
    /// against an attacker who has the password but doesn't yet want
    /// to be noticed replacing the victim's TOTP device. Understand
    /// that trade-off for the specific accounts/vhost this applies to
    /// before enabling it — this is not a general-purpose
    /// self-service convenience toggle, it's a deliberate, narrow
    /// exception to how ProxyAuth's TOTP re-enrollment is designed to
    /// require admin involvement.
    ///
    /// No global fallback — like `tag_proxyauth`, unset means `false`
    /// with nothing to inherit from beyond this route's own
    /// `vhosts:` group. See `RouteRule::totp_reenroll_allowed`.
    #[serde(default)]
    pub allow_totp_reenroll: Option<bool>,

    /// Access logging for this route. `None` means "inherit from the
    /// `vhosts:` group this route belongs to (if any), otherwise the
    /// global `logging.enabled`" — same override rules as `need_csrf`.
    /// `false` silences the per-request access-log line for this route
    /// only; `warn!`/`error!` diagnostics are unaffected, which is
    /// usually what "disable logging on this noisy endpoint" actually
    /// means — drop one line per request, without going blind to real
    /// failures.
    ///
    /// `None` vs `Some(_)` is load-bearing, so this field is read
    /// directly rather than through an accessor: the resolution order
    /// is route `log` → `logging.routes[prefix]` → `logging.enabled`,
    /// and only an unset route can fall through to the next level. See
    /// `network::accesslog::route_logging_enabled`.
    #[serde(default)]
    pub log: Option<bool>,

    /// Per-route log file override.  When set, access-log lines for
    /// this route are written to `/var/log/proxyauth/<log_file>` in
    /// addition to the global access log.  `None` means "inherit from
    /// the vhost group or the global `logging.log_file`".  Path-
    /// traversal and absolute paths are rejected at startup.
    #[serde(default)]
    pub log_file: Option<String>,

    /// Response compression for this route. `None` inherits from the
    /// group, then from the global `compression` block in
    /// `config.json`. Every field inside is itself optional, so a route
    /// can override just `enabled: false` (or just `algorithm`) and
    /// inherit the rest — see `CompressionConfig::merged_over`.
    #[serde(default)]
    pub compression: Option<CompressionConfig>,

    /// Whether responses from this route may be cached at all
    /// (`Cache-Control: public, max-age=<N>` is only ever added when
    /// this resolves to `true` — see `cache_enabled`). `None`/unset
    /// means `true` — deliberately the opposite default from
    /// `tag_proxyauth`: caching being *on* unless a route explicitly
    /// opts out matches what most proxied content actually wants,
    /// where scanning for ProxyAuth's own tags does not.
    ///
    /// No global fallback (`AppConfig` has no equivalent toggle, only
    /// `cache_duration_secs`) — this is a per-vhost-group/per-route
    /// decision, same shape as `tag_proxyauth`. Previously a plain
    /// `bool` rather than `Option<bool>`, which meant a `cache: false`
    /// set on a `vhosts:` group had no field to propagate *from* on
    /// `VhostGroup` at all (it didn't exist there) and silently had no
    /// effect on any route in that group — every route just kept
    /// deserializing its own default. `Option<bool>` here, matched by
    /// `VhostGroup::cache` and the same `is_none()`-gated propagation
    /// every other per-vhost setting already uses, fixes that.
    #[serde(default)]
    pub cache: Option<bool>,

    /// Relays the backend's response as a stream instead of loading it
    /// entirely into memory first. Needed for large transfers — git
    /// packfiles, downloads, SSE — where buffering pins as much RAM as
    /// the response weighs, per concurrent request, and delays the
    /// first byte until the last one has arrived.
    ///
    /// Incompatible by construction with `tag_proxyauth`,
    /// `hidden_blocks` and CSRF injection: all three rewrite the whole
    /// body and therefore need to see it in full. When one of them is
    /// active on this route it wins and the response is buffered as
    /// before; `validate_streaming_on_routes` logs that at startup
    /// rather than silently disabling a rewrite the operator
    /// explicitly configured.
    ///
    /// `None`/unset means inherit from the vhost group, then `false` —
    /// so no existing route changes behaviour.
    #[serde(default)]
    pub streaming: Option<bool>,

    /// Maintenance-mode gate for this route — see
    /// `RedirectProtectConfig`'s own doc comment for the full
    /// semantics. `None`/unset (the default) means no gate at all,
    /// every visitor gets this route's normal content.
    #[serde(default)]
    pub redirect_protect: Option<RedirectProtectConfig>,

    /// Per-route cache duration override.  When `Some(N)`, the
    /// response will carry `Cache-Control: public, max-age=<N>` (if
    /// `cache` is `true`).  `None` means "inherit from the vhost
    /// group or the global `cache_duration_secs`".
    #[serde(default)]
    pub cache_duration_secs: Option<u64>,

    #[serde(default = "default_secure_path")]
    pub secure_path: bool,

    #[serde(default = "default_preserve_prefix")]
    pub preserve_prefix: bool,

    #[serde(default)]
    pub allow_methods: Option<Vec<String>>,

    #[serde(default)]
    pub filters: Option<AllowRegexCfg>,

    #[serde(skip)]
    pub filters_compiled: Option<CompiledAllow>,
}

impl RouteRule {
    /// Resolves the final CSRF requirement for this route: its own
    /// explicit `need_csrf` if set (whether inherited from a `vhosts:`
    /// group by `expand_vhost_groups` or set directly on the route —
    /// both look the same by the time this runs), otherwise `true`,
    /// matching this field's behavior before per-route/per-group
    /// override existed. Callers should use this instead of reading
    /// `need_csrf` directly. Combine with `csrf_enabled` — this only
    /// decides whether *this specific route* participates once CSRF is
    /// enabled for the vhost at all.
    pub fn requires_csrf(&self) -> bool {
        self.need_csrf.unwrap_or(true)
    }

    /// Resolves whether CSRF is enabled *at all* for this vhost: its
    /// own `csrf_token` if set, otherwise `global.csrf_token`. Unlike
    /// `requires_csrf`, this is genuinely independent per vhost — an
    /// explicit `true`/`false` here overrides the global default in
    /// either direction, not just opts out of an already-enabled
    /// default.
    pub fn csrf_enabled(&self, global: &AppConfig) -> bool {
        self.tag_csrf_token.unwrap_or(global.csrf_token)
    }

    /// Resolves `AppConfig.session_cookie` for this vhost: its own
    /// `session_cookie` if set, otherwise the global default.
    pub fn session_cookie_enabled(&self, global: &AppConfig) -> bool {
        self.session_cookie.unwrap_or(global.session_cookie)
    }

    /// Resolves `AppConfig.max_age_session_cookie` for this vhost: its
    /// own value if set, otherwise the global default.
    pub fn resolved_max_age_session_cookie(&self, global: &AppConfig) -> i64 {
        self.max_age_session_cookie
            .unwrap_or(global.max_age_session_cookie)
    }

    /// Resolves `AppConfig.login_redirect_url` for this vhost: its own
    /// value if set, otherwise the global default (which may itself be
    /// unset — callers already handle that with their own
    /// `.unwrap_or("/")`-style fallback).
    pub fn resolved_login_redirect_url<'a>(&'a self, global: &'a AppConfig) -> Option<&'a str> {
        self.login_redirect_url
            .as_deref()
            .or(global.login_redirect_url.as_deref())
    }

    /// Resolves `AppConfig.logout_redirect_url` for this vhost: its
    /// own value if set, otherwise the global default.
    pub fn resolved_logout_redirect_url<'a>(&'a self, global: &'a AppConfig) -> Option<&'a str> {
        self.logout_redirect_url
            .as_deref()
            .or(global.logout_redirect_url.as_deref())
    }

    /// Resolves `AppConfig.login_via_otp` for this vhost: its own
    /// value if set, otherwise the global default.
    pub fn resolved_login_via_otp(&self, global: &AppConfig) -> bool {
        self.login_via_otp.unwrap_or(global.login_via_otp)
    }

    /// Resolves `AppConfig.page_change_password` for this vhost: its
    /// own value if set, otherwise the global default.
    pub fn resolved_page_change_password<'a>(&'a self, global: &'a AppConfig) -> Option<&'a str> {
        self.page_change_password
            .as_deref()
            .or(global.page_change_password.as_deref())
    }

    /// Resolves `AppConfig.cors_origins` for this vhost: its own list
    /// if set, otherwise the global default. Whole-list — see the
    /// field's own doc comment for why this doesn't merge the two.
    pub fn resolved_cors_origins<'a>(&'a self, global: &'a AppConfig) -> Option<&'a Vec<String>> {
        self.cors_origins.as_ref().or(global.cors_origins.as_ref())
    }

    /// Resolves `AppConfig.smtp` for this vhost: its own block if set,
    /// otherwise the global default. Whole-object — see the field's
    /// own doc comment for why this doesn't merge the two.
    pub fn resolved_smtp<'a>(
        &'a self,
        global: &'a AppConfig,
    ) -> Option<&'a crate::smtp::smtp::SmtpConfig> {
        self.smtp.as_ref().or(global.smtp.as_ref())
    }

    /// Resolves whether `{{ username }}`/`{{ csrf_token }}` tag
    /// substitution is enabled for this route. No global fallback —
    /// unlike every other resolver here, this has no
    /// `AppConfig`-level default to inherit from at all; unset means
    /// `false`, full stop. See the field's own doc comment for why
    /// that's the deliberately conservative choice.
    pub fn tag_proxyauth_enabled(&self) -> bool {
        self.tag_proxyauth.unwrap_or(false)
    }

    /// Whether this route has at least one `redirect_protect.paths`
    /// entry with a non-empty `hidden_blocks` list — independent of
    /// `tag_proxyauth_enabled`, on purpose. The two features happen
    /// to share the same "scan this HTML response" pass for
    /// efficiency, but they're unrelated otherwise: a route can want
    /// `hidden_blocks` without wanting `{{ }}` tag substitution at
    /// all, so this is checked on its own rather than folded into
    /// `tag_proxyauth`'s own flag.
    pub fn has_hidden_blocks(&self) -> bool {
        self.redirect_protect
            .as_ref()
            .is_some_and(|rp| rp.paths.iter().any(|pp| !pp.hidden_blocks.is_empty()))
    }

    /// Resolves `RouteRule.cache` — no global fallback (same shape as
    /// `tag_proxyauth_enabled`), but the opposite default: unset means
    /// `true`, matching what this field always defaulted to back when
    /// it was a plain, always-`true`-unless-set `bool`.
    pub fn cache_enabled(&self) -> bool {
        self.cache.unwrap_or(true)
    }

    /// Resolves `RouteRule.streaming` — route value, else the vhost
    /// group's (already propagated above), else `false`. Defaulting to
    /// `false` keeps every pre-existing route on the buffering path it
    /// has always used.
    pub fn streaming_enabled(&self) -> bool {
        self.streaming.unwrap_or(false)
    }

    /// A stable-enough identifier for this route, used only as a
    /// `redirect_protect_url_ips` DashMap key — not persisted, not
    /// exposed anywhere a person would see it. `vhost` (joined) plus
    /// `prefix` distinguishes routes the same way actual request
    /// routing already does; two routes sharing both would already be
    /// ambiguous to route to in the first place, so collisions here
    /// aren't a new concern this introduces.
    pub fn redirect_protect_route_key(&self) -> String {
        format!("{}|{}", self.vhost.join(","), self.prefix)
    }

    /// Resolves `RouteRule.forward_proxy_headers` — same
    /// no-global-fallback shape as `tag_proxyauth_enabled` just above,
    /// for the same reason: unset means `false`, not inherited-then-on.
    pub fn forward_proxy_headers_enabled(&self) -> bool {
        self.forward_proxy_headers.unwrap_or(false)
    }

    /// Resolves whether `username` is allowed to log in via this
    /// vhost — see `allow_users`'s own doc comment for the full
    /// semantics. Checked once, at login time in `token::auth::auth`,
    /// before any session gets issued; unrelated to
    /// `requires_csrf`/`csrf_enabled`/etc. above, which all govern
    /// what happens to an *already-authenticated* session, not
    /// whether logging in succeeds in the first place.
    pub fn login_authorized(&self, username: &str, config: &AppConfig) -> bool {
        if self.exclude_users.iter().any(|u| u == username) {
            return false;
        }

        if self.allow_users.is_empty()
            && self.allow_groups.is_empty()
            && self.allow_roles.is_empty()
        {
            return false;
        }

        if self.allow_users.iter().any(|u| u == username) {
            return true;
        }

        if !self.allow_groups.is_empty() {
            if let Some(user_groups) = config.groups_for_username(username) {
                if user_groups.iter().any(|g| self.allow_groups.contains(g)) {
                    return true;
                }
            }
        }

        if !self.allow_roles.is_empty() {
            if let Some(user_roles) = config.roles_for_username(username) {
                if user_roles.iter().any(|r| self.allow_roles.contains(r)) {
                    return true;
                }
            }
        }

        false
    }

    /// Resolves whether self-service TOTP re-enrollment (username +
    /// password alone, no admin, no clearing the old secret first) is
    /// allowed for this vhost — see `allow_totp_reenroll`'s own doc
    /// comment for the full security trade-off before turning this
    /// on. No global fallback, same reasoning as
    /// `tag_proxyauth_enabled`: unset means `false`, full stop.
    pub fn totp_reenroll_allowed(&self) -> bool {
        self.allow_totp_reenroll.unwrap_or(false)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackendConfig {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: i16,
}

fn default_weight() -> i16 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BackendInput {
    Simple(String),
    Detailed(BackendConfig),
}

/// One `blakegate` entry — see `AppConfig.blakegate`'s doc comment for
/// the accepted JSON shapes.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BlakegateEndpoint {
    Simple(String),
    Detailed {
        url: String,

        /// If `true`, this connection accepts **any** TLS
        /// certificate the endpoint presents — including self-signed
        /// or otherwise untrusted ones — instead of the normal
        /// trusted-CA verification every other connection ProxyAuth
        /// makes uses. Meant for pointing at a local/internal test
        /// Blakegate endpoint that doesn't have a certificate from a
        /// trusted CA, not for production use: with this on, a
        /// network attacker able to intercept the connection can
        /// present *any* certificate and be accepted, defeating TLS's
        /// whole purpose for that connection. `false` (verify
        /// normally) unless explicitly set. A loud warning is logged
        /// on startup for every endpoint using it, precisely so this
        /// can't end up silently enabled in a production config
        /// nobody's looked at closely.
        #[serde(default)]
        selfcert: bool,
    },
}

impl BlakegateEndpoint {
    pub fn url(&self) -> &str {
        match self {
            BlakegateEndpoint::Simple(url) => url,
            BlakegateEndpoint::Detailed { url, .. } => url,
        }
    }

    pub fn accept_self_signed(&self) -> bool {
        match self {
            BlakegateEndpoint::Simple(_) => false,
            BlakegateEndpoint::Detailed { selfcert, .. } => *selfcert,
        }
    }
}

/// One entry in `AppConfig.ip_blocklists` — see that field's doc
/// comment. `source` is either an `http(s)://` URL or a local file
/// path; format (plain text vs CSV, gzip or not) is handled the same
/// way regardless of which.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpBlocklistSource {
    pub source: String,

    /// Friendly name used for this source's local cache file
    /// (`/etc/proxyauth/abuse/<name>.txt`) instead of one derived from
    /// `source` itself. Purely cosmetic — doesn't affect matching.
    #[serde(default)]
    pub name: Option<String>,

    /// Treat each non-comment line as CSV and take the IP/CIDR from
    /// `csv_column` (0-indexed) instead of the first
    /// whitespace-separated token on the line.
    #[serde(default)]
    pub csv: bool,

    #[serde(default)]
    pub csv_column: usize,
}

#[derive(Default, Debug, Deserialize)]
pub struct RouteConfig {
    #[serde(default)]
    pub routes: Vec<RouteRule>,

    /// Alternative, less repetitive way to write `routes.yml`: group
    /// routes under a shared `vhost`/`vhost_cert` declared once, instead
    /// of repeating them on every single route. Purely an authoring
    /// convenience — `expand_vhost_groups` flattens every group into
    /// `routes` right after parsing, so nothing downstream (routing, TLS
    /// SNI resolution, the CLI audit tools) needs to know this form
    /// exists. Mixing both styles in one file is fine; a route inside a
    /// group can still set its own `vhost`/`vhost_cert` to override the
    /// group's.
    #[serde(default)]
    pub vhosts: Vec<VhostGroup>,
}

/// One `vhosts:` entry in `routes.yml` — a `vhost`/`vhost_cert` applied
/// to every route listed under it. See `RouteConfig::vhosts` and
/// `RouteConfig::expand_vhost_groups`.
#[derive(Debug, Default, Deserialize)]
pub struct VhostGroup {
    #[serde(default = "default_vhost")]
    pub vhost: Vec<String>,

    #[serde(default = "default_vhost_cert")]
    pub vhost_cert: HashMap<String, String>,

    /// Extra response headers applied to every route in this group —
    /// see `RouteRule.headers` for the format and full semantics.
    /// Merged with (not replaced by) each route's own `headers`; the
    /// route's own value wins on a key both define.
    #[serde(default = "default_headers")]
    pub headers: HashMap<String, String>,

    /// CSRF requirement applied to every route in this group that
    /// doesn't set its own `need_csrf` — same override rules as
    /// `RouteRule::need_csrf`/`requires_csrf`. `None` (not set at the
    /// group level either) leaves each route to fall back to the
    /// global default.
    #[serde(default)]
    pub need_csrf: Option<bool>,

    /// Whether CSRF protection — injection and validation alike — is
    /// enabled at all for every route in this group that doesn't set
    /// its own `tag_csrf_token`. Same override rules as
    /// `RouteRule::tag_csrf_token`. Independent of `need_csrf` above:
    /// this controls whether CSRF applies to the vhost at all,
    /// `need_csrf` controls whether one specific route within it
    /// participates once it's on.
    #[serde(default, alias = "csrf_token")]
    pub tag_csrf_token: Option<bool>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::session_cookie`.
    #[serde(default)]
    pub session_cookie: Option<bool>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::max_age_session_cookie`.
    #[serde(default)]
    pub max_age_session_cookie: Option<i64>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::login_redirect_url`.
    #[serde(default)]
    pub login_redirect_url: Option<String>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::logout_redirect_url`.
    #[serde(default)]
    pub logout_redirect_url: Option<String>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::login_via_otp`.
    #[serde(default)]
    pub login_via_otp: Option<bool>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::page_change_password`.
    #[serde(default)]
    pub page_change_password: Option<String>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::cors_origins`.
    #[serde(default)]
    pub cors_origins: Option<Vec<String>>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::smtp`.
    #[serde(default)]
    pub smtp: Option<crate::smtp::smtp::SmtpConfig>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::oidc`. In practice this is where it belongs:
    /// OIDC provider identity is a vhost-wide decision, not something
    /// that makes sense to vary route-by-route within the same vhost.
    #[serde(default)]
    pub oidc: Option<crate::proto::oidc_provider::config::OidcProviderConfig>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::tag_proxyauth`.
    #[serde(default)]
    pub tag_proxyauth: Option<bool>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::cache`. This is the field a group-level
    /// `cache: false` actually needs to exist on to have any effect at
    /// all — see `RouteRule::cache`'s own doc comment for the bug this
    /// fixes.
    #[serde(default)]
    pub cache: Option<bool>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::streaming`.
    #[serde(default)]
    pub streaming: Option<bool>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::redirect_protect`. Setting this directly on a
    /// `vhosts:` group (rather than on each individual route) is the
    /// normal way to use it: a maintenance-mode gate almost always
    /// needs to cover an entire vhost, not one specific route prefix
    /// within it.
    #[serde(default)]
    pub redirect_protect: Option<RedirectProtectConfig>,

    /// Applied to every route in this group that doesn't set its own —
    /// see `RouteRule::forward_proxy_headers`.
    #[serde(default)]
    pub forward_proxy_headers: Option<bool>,

    /// The vhost-wide login authorization lists — see
    /// `RouteRule::allow_users` for the full semantics (OR-combined
    /// with `allow_groups`/`allow_roles`, empty-means-denied default,
    /// `exclude_users` always wins). This is genuinely the intended
    /// place to set these, not the per-route fields: login happens
    /// once for the whole vhost, not per route, so setting these here
    /// (rather than repeating them on every route under `routes:`) is
    /// both less error-prone and more clearly expresses "this is a
    /// vhost-wide policy".
    #[serde(default)]
    pub allow_users: Vec<String>,
    #[serde(default)]
    pub allow_groups: Vec<String>,
    #[serde(default)]
    pub allow_roles: Vec<String>,
    #[serde(default)]
    pub exclude_users: Vec<String>,

    /// ⚠️ Applied to every route in this group that doesn't set its
    /// own — see `RouteRule::allow_totp_reenroll` for the full
    /// security trade-off this opts into. Same as everywhere else on
    /// this group: usually the right place to set it, since TOTP
    /// enrollment is a vhost-wide concern, not a per-route one.
    #[serde(default)]
    pub allow_totp_reenroll: Option<bool>,

    /// Access logging applied to every route in this group that doesn't
    /// set its own `log` — same override rules as `need_csrf`.
    #[serde(default)]
    pub log: Option<bool>,

    /// Log file applied to every route in this group that doesn't set
    /// its own `log_file`.  Written into `/var/log/proxyauth/`
    /// automatically — only the filename should be provided.
    #[serde(default)]
    pub log_file: Option<String>,

    /// Compression applied to every route in this group that doesn't
    /// set its own `compression` — same override rules as `need_csrf`.
    #[serde(default)]
    pub compression: Option<CompressionConfig>,

    /// Per-route cache duration override.  `None` means "use the
    /// global `cache_duration_secs` from `config.json`".
    #[serde(default)]
    pub cache_duration_secs: Option<u64>,

    /// Automatic Let's Encrypt renewal applied to every route in this
    /// group that doesn't explicitly set its own `certbot_renew` —
    /// same override rules as `need_csrf`/`log`, except this is a
    /// plain `bool` (not `Option<bool>`) matching `RouteRule`'s own
    /// field, so "inherit unless overridden" here specifically means
    /// "unless the route itself is `true`, not group vs. individually
    /// disabling within a group. `certbot_rew` also still accepted as
    /// an alias, matching `RouteRule.certbot_renew`.
    #[serde(default, alias = "certbot_rew")]
    pub certbot_renew: bool,

    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

impl RouteConfig {
    /// Moves every route out of `vhosts` groups and into `routes`,
    /// stamping each one with its group's `vhost`/`vhost_cert`/
    /// `need_csrf` unless the route already set its own (individual
    /// routes can still override a group's default this way). Called
    /// once, right after parsing `routes.yml`, so every other piece of
    /// code — matching, the SNI certificate resolver, `proxyauth
    /// routes-audit`/`check-access` — only ever sees the flat `routes`
    /// list it already understands.
    pub fn expand_vhost_groups(mut self) -> Self {
        for group in self.vhosts.drain(..) {
            for mut route in group.routes {
                if route.vhost.is_empty() {
                    route.vhost = group.vhost.clone();
                }
                if route.vhost_cert.is_empty() {
                    route.vhost_cert = group.vhost_cert.clone();
                }
                // Merged, not "only if empty" like the fields above —
                // a route commonly wants the group's baseline headers
                // (e.g. HSTS set once for the whole vhost) *plus* one
                // or two of its own on top, not a strict either/or.
                // The route's own entries are inserted last, so they
                // win on a key both define.
                for (k, v) in &group.headers {
                    route.headers.entry(k.clone()).or_insert_with(|| v.clone());
                }
                if !route.certbot_renew {
                    route.certbot_renew = group.certbot_renew;
                }
                if route.need_csrf.is_none() {
                    route.need_csrf = group.need_csrf;
                }
                if route.tag_csrf_token.is_none() {
                    route.tag_csrf_token = group.tag_csrf_token;
                }
                if route.session_cookie.is_none() {
                    route.session_cookie = group.session_cookie;
                }
                if route.max_age_session_cookie.is_none() {
                    route.max_age_session_cookie = group.max_age_session_cookie;
                }
                if route.login_redirect_url.is_none() {
                    route.login_redirect_url = group.login_redirect_url.clone();
                }
                if route.logout_redirect_url.is_none() {
                    route.logout_redirect_url = group.logout_redirect_url.clone();
                }
                if route.login_via_otp.is_none() {
                    route.login_via_otp = group.login_via_otp;
                }
                if route.page_change_password.is_none() {
                    route.page_change_password = group.page_change_password.clone();
                }
                if route.cors_origins.is_none() {
                    route.cors_origins = group.cors_origins.clone();
                }
                if route.smtp.is_none() {
                    route.smtp = group.smtp.clone();
                }
                if route.oidc.is_none() {
                    route.oidc = group.oidc.clone();
                }
                if route.tag_proxyauth.is_none() {
                    route.tag_proxyauth = group.tag_proxyauth;
                }
                if route.cache.is_none() {
                    route.cache = group.cache;
                }
                if route.streaming.is_none() {
                    route.streaming = group.streaming;
                }
                if route.redirect_protect.is_none() {
                    route.redirect_protect = group.redirect_protect.clone();
                }
                if route.forward_proxy_headers.is_none() {
                    route.forward_proxy_headers = group.forward_proxy_headers;
                }
                if route.allow_users.is_empty() {
                    route.allow_users = group.allow_users.clone();
                }
                if route.allow_groups.is_empty() {
                    route.allow_groups = group.allow_groups.clone();
                }
                if route.allow_roles.is_empty() {
                    route.allow_roles = group.allow_roles.clone();
                }
                if route.exclude_users.is_empty() {
                    route.exclude_users = group.exclude_users.clone();
                }
                if route.allow_totp_reenroll.is_none() {
                    route.allow_totp_reenroll = group.allow_totp_reenroll;
                }
                if route.log.is_none() {
                    route.log = group.log;
                }
                if route.log_file.is_none() {
                    route.log_file = group.log_file.clone();
                }
                if route.compression.is_none() {
                    // Cloned, not moved: the group applies to every
                    // route under it, not just the first.
                    route.compression = group.compression.clone();
                }
                if route.cache_duration_secs.is_none() {
                    route.cache_duration_secs = group.cache_duration_secs;
                }
                self.routes.push(route);
            }
        }
        self
    }
}

/// One email address on file for a user, with an explicit `primary`
/// flag — rather than relying on "whichever one happens to be first in
/// the list", which is fragile (flips depending on argument/insertion
/// order, easy to get wrong on an update). Exactly one entry should be
/// `primary: true` per user; if more than one is (or none is), the
/// first one marked primary wins — see `find_user_email`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EmailEntry {
    pub address: String,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
    pub otpkey: Option<String>,
    pub allow: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,

    /// Group memberships for this account — an alternative to
    /// `roles` specifically for route access control (`roles` is
    /// only ever forwarded to the backend as the `X-User-Roles`
    /// header; it never gates access by itself). A route lists
    /// allowed groups via `RouteRule.groups` in `routes.yml`; a user
    /// gets in if they're in at least one of them, without needing
    /// their username individually added to every such route — see
    /// `AppConfig::groups_for_username`.
    #[serde(default)]
    pub groups: Option<Vec<String>>,

    pub email: Option<Vec<EmailEntry>>,

    /// If true, the next successful login redirects to
    /// `page_change_password` instead of issuing a normal session —
    /// used for a temporary password an admin just set (first login)
    /// as well as right after `proxyauth reset-password`. Cleared
    /// automatically once the user successfully sets a new password.
    #[serde(default)]
    pub must_change_password: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AllowRegexCfg {
    #[serde(default = "default_allow_true")]
    pub default_allow: bool,

    #[serde(default)]
    pub allow: Vec<RegexCondCfg>,
}

fn default_allow_true() -> bool {
    true
}

impl Serialize for User {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Length hint was wrong (2, should match the actual field count)
        // and `roles` was serializing `self.allow`'s value instead of
        // `self.roles`'s — meaning every config.json rewrite (e.g. on
        // first-run password hashing) silently duplicated `allow` into
        // `roles` and dropped the real roles. Fixed here; also now
        // includes `email` for completeness.
        let mut state = serializer.serialize_struct("User", 8)?;
        state.serialize_field("username", &self.username)?;
        state.serialize_field("password", &self.password)?;
        state.serialize_field("otpkey", &self.otpkey)?;
        state.serialize_field("allow", &self.allow)?;
        state.serialize_field("roles", &self.roles)?;
        state.serialize_field("groups", &self.groups)?;
        state.serialize_field("email", &self.email)?;
        state.serialize_field("must_change_password", &self.must_change_password)?;
        state.end()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// "postgres" or "mysql"
    #[serde(rename = "type")]
    pub db_type: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub db_name: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,

    /// How long (in seconds) a connection attempt is allowed to take
    /// before giving up. Bounds the worst case for every blocking
    /// database call in the process — without this, a database that
    /// accepts a TCP connection but never responds (or is behind a
    /// firewall silently dropping packets) can hang for the OS's
    /// default TCP timeout, which is often 30s-130s+. That worst case
    /// matters beyond just "logins are slow": it's also how long a
    /// `service proxyauth restart` can appear to hang, since a
    /// connection attempt already in flight when SIGTERM arrives keeps
    /// running (see `connect`'s implementation for why). Defaults to 5.
    #[serde(default = "default_db_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// How often (in seconds) the *incremental* scan runs — a cheap,
    /// indexed query that only reads users changed within
    /// `incremental_window_secs`. This is what keeps freshly
    /// created/edited DB users usable quickly, without the cost of a
    /// full table read on every tick. Defaults to 30s. Set to 0 to
    /// disable it (falls back to relying solely on the slower full
    /// scan below).
    #[serde(default = "default_db_refresh_interval")]
    pub refresh_interval_secs: u64,

    /// The lookback window (in seconds) used by the incremental scan —
    /// i.e. "users changed in the last N seconds". Must be at least as
    /// long as `refresh_interval_secs` (ideally longer, with some
    /// overlap) so a change can never fall in the gap between two scans
    /// and be missed entirely. Defaults to 300 (5 minutes).
    #[serde(default = "default_db_incremental_window")]
    pub incremental_window_secs: i64,

    /// How often (in seconds) the *full* scan runs — reads the entire
    /// `users` table. Slower and more expensive at scale than the
    /// incremental scan above, but it's the only way to detect a user
    /// that was hard-deleted from the database without going through
    /// `deleted_users_log` (e.g. a `TRUNCATE TABLE users`, which
    /// bypasses row-level `DELETE` triggers entirely). Defaults to 300
    /// (5 minutes). Set to 0 to disable (deletions then only take
    /// effect on the next restart).
    #[serde(default = "default_db_full_refresh_interval")]
    pub full_refresh_interval_secs: u64,

    /// How long (in seconds) a soft-deleted user (`deleted = TRUE`,
    /// see `db-delete-user`) — and its `deleted_users_log` entry, for a
    /// hard-deleted one — stays in the database before being
    /// permanently purged. Keeping the row/log entry around for a while
    /// gives every instance's incremental scan a chance to see and
    /// revoke it, and leaves an audit trail. Defaults to 86400 (24
    /// hours). Set to 0 to disable automatic purging (rows/log entries
    /// are kept forever, until removed manually).
    #[serde(default = "default_db_deleted_retention")]
    pub deleted_retention_secs: i64,

    /// How often (in seconds) to run the purge of soft-deleted users
    /// past `deleted_retention_secs`. Any single connected instance
    /// running this is enough — deleting already-purged rows on another
    /// instance is a harmless no-op, so this is safe to leave enabled
    /// on every instance. Defaults to 3600 (hourly). Set to 0 to
    /// disable.
    #[serde(default = "default_db_purge_interval")]
    pub purge_interval_secs: u64,
}

fn default_db_refresh_interval() -> u64 {
    30
}

fn default_db_connect_timeout() -> u64 {
    5
}

fn default_db_incremental_window() -> i64 {
    300
}

fn default_db_full_refresh_interval() -> u64 {
    300
}

fn default_db_deleted_retention() -> i64 {
    86400
}

fn default_db_purge_interval() -> u64 {
    3600
}

impl DatabaseConfig {
    /// Returns the configured port, or the standard default port for
    /// `type` (3306 for mysql/mariadb, 5432 otherwise/postgres) when
    /// `port` wasn't set.
    pub fn effective_port(&self) -> u16 {
        self.port
            .unwrap_or_else(|| match self.db_type.to_lowercase().as_str() {
                "mysql" | "mariadb" => 3306,
                _ => 5432,
            })
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct AppConfig {
    pub token_expiry_seconds: i64,
    pub secret: String,
    pub users: Vec<User>,

    #[serde(default)]
    pub token_admin: String,

    /// Address(es) to listen on. Accepts either a single string
    /// (`"host": "0.0.0.0"`, the pre-existing format — still fully
    /// supported) or an array (`"host": ["0.0.0.0", "::1"]`) to bind
    /// more than one at once, e.g. IPv4 + IPv6 together. Every entry
    /// is bound with its own listening socket, all served by the same
    /// actix HttpServer instance — one shared worker pool, not a
    /// separate server per address.
    #[serde(default = "default_hosts", deserialize_with = "deserialize_host")]
    pub host: Vec<String>,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_worker")]
    pub worker: u8,

    #[serde(default = "default_ratelimit_proxy")]
    pub ratelimit_proxy: HashMap<String, u64>,

    #[serde(default = "default_ratelimit_auth")]
    pub ratelimit_auth: HashMap<String, u64>,

    #[serde(deserialize_with = "deserialize_log_map")]
    pub log: HashMap<String, String>,

    /// Access log: line format plus the global / per-vhost / per-route
    /// on-off switches. Deliberately separate from `log` above, which
    /// configures the `tracing` *transport* (`local`/`loki`/`http`/
    /// `disabled`) for every log line, access and diagnostic alike.
    ///
    /// The practical consequence of keeping them apart: setting
    /// `logging.enabled` to false drops the per-request access lines
    /// while leaving `warn!`/`error!` intact — almost always what
    /// "turn off logging on this endpoint" is meant to achieve.
    /// `log.type: "disabled"` remains the way to silence everything.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Response compression, global defaults. Overridden per route or
    /// per `vhosts:` group in `routes.yml`; see `CompressionConfig`.
    #[serde(default)]
    pub compression: CompressionConfig,

    /// Settings for automatic Let's Encrypt certificate renewal (see
    /// `RouteRule.certbot_renew`). Global — every ACME-managed vhost
    /// shares the same check interval, renewal threshold, and ACME
    /// account. The JSON key is `letsencrypt` (not `acme`) — this
    /// still uses `AcmeConfig`/`acme` internally since the underlying
    /// protocol is ACME (Let's Encrypt is just its most common
    /// provider), but the user-facing config key names the thing
    /// operators actually care about. `acme` is still accepted as an
    /// alias, matching this feature's original key name.
    #[serde(default, rename = "letsencrypt", alias = "acme")]
    pub acme: AcmeConfig,

    /// Default `Cache-Control: public, max-age=<N>` duration (in
    /// seconds) applied to every response whose route has `cache: true`
    /// and no per-route `cache_duration_secs` override.  `0` disables
    /// caching at the HTTP layer even when `cache` is `true` (the
    /// header becomes `max-age=0`).  Defaults to 300 (5 minutes).
    #[serde(default = "default_cache_duration_secs")]
    pub cache_duration_secs: u64,

    #[serde(default = "default_stats")]
    pub stats: bool,

    #[serde(default)]
    pub trust_proxy_forward_for: Option<Vec<String>>,

    /// System user the server process runs as, once startup's
    /// privileged phase (binding low ports, reading root-only TLS
    /// certs) is done — see `main.rs`'s startup ordering. Defaults to
    /// `"proxyauth"`, the account `proxyauth prepare` sets up
    /// automatically. Setting this to an existing user instead (e.g.
    /// `"www-data"`/`"nginx"`) is a way to let ProxyAuth read that
    /// user's files (a `static` route's directory, say) without
    /// touching those files' permissions at all — it just runs as
    /// whoever already has access. `prepare` only *verifies* a
    /// non-default `run_user` exists rather than creating it, since an
    /// account like `www-data` belongs to some other package.
    #[serde(default = "default_run_user")]
    pub run_user: String,

    /// Group to run as instead of `run_user`'s own primary group.
    /// `None` (the default) just uses that primary group.
    #[serde(default)]
    pub run_group: Option<String>,

    /// External IP/CIDR abuse-blocklists (Spamhaus DROP, FireHOL,
    /// AbuseIPDB exports, ...) checked against every request's
    /// resolved client IP — reject on match, before any route
    /// matching or auth work. Each source is a plain-text or CSV
    /// list, gzip-compressed or not (auto-detected). Refreshed on the
    /// interval below; empty means the feature is off, same as
    /// before it existed.
    #[serde(default)]
    pub ip_blocklists: Vec<IpBlocklistSource>,

    /// How often every `ip_blocklists` source is re-fetched, in
    /// seconds. `0` fetches once at startup and never refreshes
    /// again. Ignored when `ip_blocklists` is empty.
    #[serde(default = "default_ip_blocklist_refresh_interval")]
    pub ip_blocklist_refresh_interval_secs: u64,

    /// How often every `redirect_protect.allow_url_ips`/`deny_url_ips`
    /// source, across every route, is re-fetched — same shape and
    /// same default as `ip_blocklist_refresh_interval_secs`, kept as
    /// its own separate setting rather than reusing that one directly
    /// since an operator may reasonably want a maintenance-mode allow
    /// list refreshed on a different cadence than a general abuse
    /// feed. `0` fetches once at startup and never refreshes again.
    /// Ignored when no route has either field configured.
    #[serde(default = "default_ip_blocklist_refresh_interval")]
    pub redirect_protect_refresh_interval_secs: u64,

    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// How long a proxied request may take before it is abandoned, in
    /// milliseconds.
    ///
    /// With `streaming` off this bounds the whole exchange, since the
    /// response is collected before anything is sent on. With
    /// `streaming` on it bounds only the arrival of the response
    /// *headers* — the body then flows for as long as it takes, which
    /// is the point of streaming a large transfer in the first place.
    ///
    /// Replaces a value that used to be hardcoded at both upstream
    /// call sites, so a slow backend no longer requires a rebuild to
    /// accommodate.
    #[serde(default = "default_backend_timeout")]
    pub backend_timeout: u64,

    #[serde(default = "default_max_idle_per_host")]
    pub max_idle_per_host: u16,

    #[serde(default = "default_timezone")]
    pub timezone: String,

    #[serde(default = "default_login_via_otp")]
    pub login_via_otp: bool,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_pending_connections_limit")]
    pub pending_connections_limit: u32,

    #[serde(default = "default_socket_listen")]
    pub socket_listen: u32,

    #[serde(default = "default_client_timeout")]
    pub client_timeout: u64,

    #[serde(default = "default_keep_alive")]
    pub keep_alive: u64,

    #[serde(default = "default_num_instances")]
    pub num_instances: u8,

    #[serde(default)]
    pub redis: Option<String>,

    #[serde(default)]
    pub cors_origins: Option<Vec<String>>,

    #[serde(default)]
    pub databases: Option<DatabaseConfig>,

    #[serde(default = "default_session_cookie")]
    pub session_cookie: bool,

    #[serde(default = "default_max_age_session_cookie")]
    pub max_age_session_cookie: i64,

    #[serde(default)]
    pub login_redirect_url: Option<String>,

    #[serde(default)]
    pub logout_redirect_url: Option<String>,

    #[serde(default = "default_tls")]
    pub tls: bool,

    /// Whether a route configured with a client certificate (`cert:`
    /// in `routes.yml`, for mTLS to a backend) must actually use it.
    ///
    /// `false` (default, unchanged from prior behavior): if the
    /// configured cert/key can't be read or fails to pair, the backend
    /// connection silently falls back to no client authentication at
    /// all — logged (`tracing::warn!`) but otherwise invisible from
    /// ProxyAuth's own external behavior. A backend that relies on
    /// mTLS to authenticate ProxyAuth as a legitimate caller has no
    /// way to tell "mTLS is working" from "mTLS silently isn't" in
    /// that case.
    ///
    /// `true`: the same failures instead fail the request outright
    /// (502 Bad Gateway) rather than connecting without client
    /// authentication. A broken certificate path becomes a loud,
    /// visible failure instead of a quiet downgrade.
    #[serde(default)]
    pub strict_mtls: bool,

    #[serde(default = "default_csrf_token")]
    pub csrf_token: bool,

    #[serde(default = "default_fast")]
    pub fast: bool,

    /// External "Blakegate" endpoints ProxyAuth pushes its live
    /// in-memory configuration to over WebSocket, near real-time —
    /// every time something in this in-memory state actually changes
    /// (a database user/role/group refresh, a revocation, ...), an
    /// updated snapshot is pushed to every connected endpoint. See
    /// `proto::blakegate::spawn_clients` for the client itself and
    /// exactly what gets sent (a *redacted* snapshot — `secret` and
    /// every user's `password`/`otpkey`/`anti_replay_secret` are
    /// stripped before anything leaves this process; see that
    /// module's doc comment for why).
    ///
    /// Two accepted shapes, matching `backends`' own `BackendInput`
    /// convention — a plain URL string, or an object when you need
    /// `selfcert`:
    ///
    /// ```json
    /// "blakegate": [
    ///   "https://blakegate-1.example.com",
    ///   { "url": "https://blakegate-2.internal.test", "selfcert": true }
    /// ]
    /// ```
    ///
    /// Entries are accepted as `https://`/`http://` for convenience
    /// (easier to type/paste than a raw `wss://` URL) but are always
    /// connected to as `wss://`/`ws://` — the scheme is rewritten, not
    /// read literally. ProxyAuth never speaks plain HTTP to these
    /// endpoints.
    #[serde(default)]
    pub blakegate: Vec<BlakegateEndpoint>,

    pub smtp: Option<SmtpConfig>,

    /// URL the user's browser is redirected to (303, when
    /// `session_cookie` is true) to set a new password — after
    /// `proxyauth reset-password` sends them a link, or automatically
    /// on their first login with a temporary password
    /// (`must_change_password: true`). When `session_cookie` is false
    /// (API/JSON client, no browser cookie flow), the same information
    /// is returned as JSON instead of a redirect — see
    /// `token::auth::maybe_force_password_change`. ProxyAuth appends
    /// `?token=<reset_token>` itself; the page there is expected to
    /// submit `token`, `password`, and `verif_password` as a POST to
    /// `/reset-password` on this instance. Required for the
    /// `reset-password` CLI command and the `must_change_password`
    /// gate — both are refused with a clear error if this isn't set.
    #[serde(default)]
    pub page_change_password: Option<String>,

    /// Users loaded from `databases` (if configured), refreshed
    /// periodically by a background task so DB-side changes (users
    /// added/edited directly in the database) eventually take effect
    /// without a restart. Not deserialized from config.json — populated
    /// at startup and kept in sync afterwards. Combine with `users` via
    /// `combined_users()` rather than reading either list alone.
    #[serde(skip)]
    pub db_users: std::sync::RwLock<Vec<User>>,

    /// Raw indices (positions within `db_users`) that were removed from
    /// the database on the last refresh. The slot itself is never
    /// deleted/reordered (that would shift the index of every entry
    /// after it, embedded in already-issued tokens) — instead its
    /// password is poisoned (see `refresh_db_users`) so it can never
    /// log in again, and `user_by_index` rejects any token pointing at
    /// a revoked index outright, invalidating it immediately.
    #[serde(skip)]
    pub db_revoked: std::sync::RwLock<std::collections::HashSet<usize>>,

    /// username -> roles fast index, kept in sync with `users`/`db_users`
    /// (populated once at startup for `users`, since it's immutable
    /// after load, and updated on every `refresh_db_users()` for
    /// database users). Exists purely so `roles_for_username` — called
    /// on every proxied request via `inject_header` — is an O(1)
    /// average-case HashMap lookup instead of an O(n) scan over every
    /// user.
    #[serde(skip)]
    pub roles_index: std::sync::RwLock<HashMap<String, Vec<String>>>,

    /// username -> groups fast index — same purpose and lifecycle as
    /// `roles_index`, kept separate rather than reusing it because
    /// `groups` and `roles` mean different things: `roles` is purely
    /// informational (forwarded to the backend as `X-User-Roles`,
    /// never checked by ProxyAuth itself), while `groups` is what
    /// `RouteRule.groups` actually gates access against.
    #[serde(skip)]
    pub groups_index: std::sync::RwLock<HashMap<String, Vec<String>>>,

    /// Bumped by every function that mutates this instance's in-memory
    /// state (`refresh_db_users`, `refresh_db_users_incremental`,
    /// `revoke_username_now`, ...) — the signal the Blakegate client
    /// task polls to know a fresh snapshot needs pushing, without
    /// threading a broadcast channel through every one of those call
    /// sites individually. `Relaxed` ordering is enough: this is a
    /// "did *anything* change since I last looked" counter, not a
    /// value anything is read alongside for consistency.
    #[serde(skip)]
    pub generation: std::sync::atomic::AtomicU64,

    /// How many `blakegate` connections are currently established —
    /// incremented/decremented by `proto::blakegate::run_client` for
    /// the lifetime of each live connection. Used purely to answer
    /// "is Blakegate backup mode actually in effect right now" — see
    /// `should_use_database_as_fallback`.
    #[serde(skip)]
    pub blakegate_connected: std::sync::atomic::AtomicUsize,
}

impl Serialize for AppConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AppConfig", 7)?;
        state.serialize_field("blakegate", &self.blakegate)?;
        state.serialize_field("client_timeout", &self.client_timeout)?;
        state.serialize_field("compression", &self.compression)?;
        state.serialize_field("cors_origins", &self.cors_origins)?;
        state.serialize_field("databases", &self.databases)?;
        state.serialize_field("fast", &self.fast)?;
        state.serialize_field("host", &self.host)?;
        state.serialize_field("keep_alive", &self.keep_alive)?;
        state.serialize_field("letsencrypt", &self.acme)?;
        state.serialize_field("log", &self.log)?;
        state.serialize_field("logging", &self.logging)?;
        state.serialize_field("max_age_session_cookie", &self.max_age_session_cookie)?;
        state.serialize_field("max_connections", &self.max_connections)?;
        state.serialize_field("max_idle_per_host", &self.max_idle_per_host)?;
        state.serialize_field("num_instances", &self.num_instances)?;
        state.serialize_field("pending_connections_limit", &self.pending_connections_limit)?;
        state.serialize_field("port", &self.port)?;
        state.serialize_field("ratelimit_auth", &self.ratelimit_auth)?;
        state.serialize_field("ratelimit_proxy", &self.ratelimit_proxy)?;
        state.serialize_field("redis", &self.redis)?;
        state.serialize_field("secret", &self.secret)?;
        state.serialize_field("session_cookie", &self.session_cookie)?;
        state.serialize_field("socket_listen", &self.socket_listen)?;
        state.serialize_field("stats", &self.stats)?;
        state.serialize_field("tls", &self.tls)?;
        state.serialize_field("timezone", &self.timezone)?;
        state.serialize_field("token_admin", &self.token_admin)?;
        state.serialize_field("token_expiry_seconds", &self.token_expiry_seconds)?;
        state.serialize_field("login_redirect_url", &self.login_redirect_url)?;
        state.serialize_field("login_via_otp", &self.login_via_otp)?;
        state.serialize_field("logout_redirect_url", &self.logout_redirect_url)?;
        state.serialize_field("users", &self.users)?;
        state.serialize_field("worker", &self.worker)?;
        state.end()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub routes: Arc<RouteConfig>,
    pub counter: Arc<CounterToken>,
    pub revoked_tokens: RevokedTokenMap,
    pub stats: Arc<RequestStats>,

    /// Merged, deduplicated set of every `ip_blocklists` source,
    /// hot-swapped by a background task on
    /// `ip_blocklist_refresh_interval_secs` — see
    /// `network::ipblocklist`. Empty (the default, no allocation of
    /// note) when `ip_blocklists` isn't configured, so the per-request
    /// check is just an empty-slice scan.
    pub ip_blocklist: Arc<ArcSwap<Vec<IpNet>>>,

    /// Fetched `redirect_protect.allow_url_ips`/`deny_url_ips` results,
    /// per route — `(allow_compiled, deny_compiled)`, hot-updated by a
    /// background task on `redirect_protect_refresh_interval_secs`.
    /// Keyed by `redirect_protect_route_key` rather than swapped as one
    /// whole map (unlike `ip_blocklist`, which has exactly one global
    /// list): a `DashMap`, matching `otp_overrides`/`password_overrides`'
    /// own per-key-update shape, lets one route's refresh land without
    /// waiting on or blocking every other route's. A route with neither
    /// field configured simply never gets an entry here at all.
    pub redirect_protect_url_ips: Arc<DashMap<String, (Vec<IpNet>, Vec<IpNet>)>>,

    /// Hot-reloadable overlay for per-user TOTP secrets. `AppState.config`
    /// is an immutable `Arc<AppConfig>` snapshot loaded once at startup —
    /// writing a new/cleared `otpkey` to config.json on disk (via
    /// `add_otpkey`/`clear_otpkey`, used by `/adm/auth/totp/get` and
    /// `/adm/auth/totp/reset`) does NOT update that snapshot in any
    /// already-running worker. Without this overlay: a freshly enrolled
    /// user couldn't log in, and — worse — a freshly *reset* (e.g.
    /// compromised) OTP key would keep working, until every worker
    /// process was restarted. `None` means "explicitly cleared"; a
    /// missing entry means "use whatever config.json said at startup".
    /// See `resolve_otpkey`.
    pub otp_overrides: Arc<DashMap<String, Option<String>>>,

    /// Same idea as `otp_overrides`, for a password just set via
    /// `/reset-password`: the new Argon2 hash for a file-based user, so
    /// it's usable immediately without a restart. (Database-backed
    /// users don't need this — the change goes through
    /// `databases::db::update_password`, and the in-memory `db_users`
    /// snapshot is updated directly at the same time.) See
    /// `resolve_password_override`.
    pub password_overrides: Arc<DashMap<String, String>>,

    /// Same idea again, for `must_change_password`: true when set by
    /// an admin (temporary password) and cleared the moment the user
    /// successfully sets a real one — without waiting for a restart to
    /// stop redirecting them to `page_change_password` on every login.
    /// A missing entry means "use whatever config.json/the database
    /// said". See `resolve_must_change_password`.
    pub must_change_overrides: Arc<DashMap<String, bool>>,
}

/// Resolves the OTP secret to actually use for `username`, checking the
/// live `otp_overrides` overlay before falling back to whatever
/// `AppConfig` loaded from disk at startup. See `AppState::otp_overrides`
/// for why this indirection exists.
pub fn resolve_otpkey(
    state: &AppState,
    username: &str,
    config_otpkey: Option<&str>,
) -> Option<String> {
    if let Some(entry) = state.otp_overrides.get(username) {
        return entry.clone();
    }
    config_otpkey.map(|s| s.to_string())
}

/// Resolves the password hash to actually use for a file-based
/// `username`, checking `password_overrides` before falling back to
/// `config_password`. See `AppState::password_overrides`.
pub fn resolve_password_override(
    state: &AppState,
    username: &str,
    config_password: &str,
) -> String {
    state
        .password_overrides
        .get(username)
        .map(|entry| entry.clone())
        .unwrap_or_else(|| config_password.to_string())
}

/// Resolves whether `username` currently must change their password,
/// checking `must_change_overrides` before falling back to whatever
/// `config_value` (from config.json/the database) said. See
/// `AppState::must_change_overrides`.
pub fn resolve_must_change_password(state: &AppState, username: &str, config_value: bool) -> bool {
    state
        .must_change_overrides
        .get(username)
        .map(|entry| *entry)
        .unwrap_or(config_value)
}

/// Writes a new Argon2 password hash for a file-based user directly
/// into `config.json`, and clears `must_change_password` for them at
/// the same time (a completed password change always satisfies it,
/// whichever flow triggered it). Mirrors `clear_otpkey`'s approach —
/// raw JSON manipulation, since `AppConfig`'s own (de)serialization
/// isn't in scope for a single-field update. Returns `Ok(true)` if the
/// user was found and updated, `Ok(false)` if not found (so this can
/// be tried against file-based storage first, then database storage,
/// without erroring out just because the user lives in the other one).
pub fn set_user_password(
    config_path: &str,
    username: &str,
    new_password_hash: &str,
) -> Result<bool, String> {
    if !Path::new(config_path).exists() {
        return Err(format!("Config file not found: {}", config_path));
    }

    let config_str = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read the configuration file: {e}"))?;
    let mut json: Value = serde_json::from_str(&config_str)
        .map_err(|e| format!("Invalid JSON format in configuration file: {e}"))?;

    let users = json
        .get_mut("users")
        .and_then(|u| u.as_array_mut())
        .ok_or_else(|| "Missing 'users' field in configuration file.".to_string())?;

    let mut found = false;

    for user in users.iter_mut() {
        let name = user.get("username").and_then(|u| u.as_str());
        if name == Some(username) {
            found = true;
            if let Some(obj) = user.as_object_mut() {
                obj.insert(
                    "password".to_string(),
                    Value::String(new_password_hash.to_string()),
                );
                obj.insert("must_change_password".to_string(), Value::Bool(false));
            }
            break;
        }
    }

    if !found {
        return Ok(false);
    }

    let updated_str = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("Failed to serialize the updated configuration: {e}"))?;
    fs::write(config_path, updated_str)
        .map_err(|e| format!("Failed to write the updated configuration file: {e}"))?;

    Ok(true)
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
    pub csrf_token: Option<String>,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_hosts() -> Vec<String> {
    vec![default_host()]
}

/// Accepts `"host": "0.0.0.0"` (a bare string, the pre-existing
/// format) or `"host": ["0.0.0.0", "::1"]` (an array), normalizing
/// either into `Vec<String>` — so existing `config.json` files with
/// the old single-string form keep working unmodified.
fn deserialize_host<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum HostField {
        Single(String),
        Multiple(Vec<String>),
    }
    match HostField::deserialize(deserializer)? {
        HostField::Single(s) => Ok(vec![s]),
        HostField::Multiple(v) => Ok(v),
    }
}

fn default_timezone() -> String {
    "Europe/Paris".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_cache_duration_secs() -> u64 {
    300
}

fn default_secure_path() -> bool {
    false
}

fn default_preserve_prefix() -> bool {
    false
}

fn default_username() -> Vec<String> {
    [].to_vec()
}

fn default_max_connections() -> usize {
    50_000
}

fn default_keep_alive() -> u64 {
    5000
}

fn default_num_instances() -> u8 {
    2
}

fn default_client_timeout() -> u64 {
    5000
}

fn default_pending_connections_limit() -> u32 {
    65535
}

fn default_socket_listen() -> u32 {
    1024
}

fn default_backends() -> Vec<BackendInput> {
    Vec::new()
}

fn default_tls() -> bool {
    true
}

fn default_csrf_token() -> bool {
    true
}

fn default_required_login() -> bool {
    false
}

fn default_fast() -> bool {
    false
}

fn default_worker() -> u8 {
    4
}

fn default_proxy() -> bool {
    false
}

fn default_stats() -> bool {
    false
}

fn default_proxy_config() -> String {
    "".to_string()
}

fn default_max_idle_per_host() -> u16 {
    50
}

fn default_max_age_session_cookie() -> i64 {
    3600
}

fn default_login_via_otp() -> bool {
    false
}

fn default_session_cookie() -> bool {
    false
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10 MB default if not set in config file
}

fn default_backend_timeout() -> u64 {
    10_000 // 10 s, the value both upstream call sites used to hardcode
}

fn default_log() -> HashMap<String, String> {
    let mut log = HashMap::new();
    log.insert("type".to_string(), "local".to_string());
    log.insert("write_max_logs".to_string(), "1000".into());
    log
}

fn default_ratelimit_proxy() -> HashMap<String, u64> {
    let mut ratelimit = HashMap::new();
    ratelimit.insert("requests_per_second".to_string(), 0);
    ratelimit.insert("burst".to_string(), 1);
    ratelimit.insert("block_delay".to_string(), 500);
    ratelimit
}

fn default_ratelimit_auth() -> HashMap<String, u64> {
    let mut ratelimit = HashMap::new();
    ratelimit.insert("requests_per_second".to_string(), 0);
    ratelimit.insert("burst".to_string(), 1);
    ratelimit.insert("block_delay".to_string(), 500);
    ratelimit
}

fn default_cert() -> HashMap<String, String> {
    let cert = HashMap::new();
    cert
}

fn default_vhost() -> Vec<String> {
    Vec::new()
}

fn default_vhost_cert() -> HashMap<String, String> {
    HashMap::new()
}

fn default_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn default_static_index() -> String {
    "index.html".to_string()
}

fn default_ip_blocklist_refresh_interval() -> u64 {
    3600
}

fn default_run_user() -> String {
    "proxyauth".to_string()
}

/// Checks a raw `routes.yml` for the deprecated `secure` key, which was
/// renamed to `required_login`. Unlike a normal unknown field, `secure`
/// used to control whether a route required authentication — silently
/// ignoring it would leave routes unauthenticated without warning anyone,
/// so we fail loudly instead of falling back to the `required_login`
/// default.
pub fn check_deprecated_secure_key(routes_str: &str) -> Result<(), String> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(routes_str).map_err(|e| format!("Failed to parse routes.yml: {e}"))?;

    let routes = doc
        .get("routes")
        .and_then(|r| r.as_sequence())
        .cloned()
        .unwrap_or_default();

    let offenders: Vec<String> = routes
        .iter()
        .filter_map(|route| {
            let map = route.as_mapping()?;
            if map.contains_key(serde_yaml::Value::String("secure".to_string())) {
                let prefix = map
                    .get(serde_yaml::Value::String("prefix".to_string()))
                    .and_then(|p| p.as_str())
                    .unwrap_or("<unknown prefix>");
                Some(prefix.to_string())
            } else {
                None
            }
        })
        .collect();

    if offenders.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "routes.yml: 'secure' key is deprecated, rename it to 'required_login' (route(s): {}).",
            offenders.join(", ")
        ))
    }
}

/// What let (or would let) a given username through a route, given its
/// `username`/`groups`/`roles` configuration — see
/// `AppConfig::route_access_decision`. Kept as a real enum rather than
/// a bare `bool` specifically so `proxyauth routes-audit`/`check-access`
/// (see `cli::audit`) can report *why*, not just whether — and so that
/// tool is guaranteed to reflect the exact same logic
/// `network::proxy`'s access check enforces, both calling this one
/// function, rather than two implementations that could quietly drift
/// apart over time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAccessDecision {
    /// The username is explicitly listed in `RouteRule.username`.
    AllowedByUsername,
    /// Not listed by username, but a member of this allowed group.
    AllowedByGroup(String),
    /// Not listed by username or group, but holds this allowed role.
    AllowedByRole(String),
    /// `username`, `groups`, and `roles` were all left empty on this
    /// route — read as "any authenticated account may use this
    /// route", not a misconfiguration (see the doc comment on
    /// `RouteRule.roles`).
    AllowedNoRestrictionConfigured,
    /// None of the above — the request would be rejected.
    Denied,
}

impl RouteAccessDecision {
    pub fn is_allowed(&self) -> bool {
        !matches!(self, RouteAccessDecision::Denied)
    }
}

impl AppConfig {
    /// `backend_timeout` as a `Duration`, with `0` restored to the
    /// default rather than taken literally.
    ///
    /// A zero-length timeout is never what an operator means: it would
    /// abandon every proxied request the instant it is issued, turning
    /// the whole instance into a `503` generator. Elsewhere in this
    /// config a `0` legitimately means "off" — `ratelimit_*`,
    /// `ip_blocklist_refresh_interval_secs` — so the value has to stay
    /// accepted at parse time and be guarded here, at the point of use,
    /// instead.
    pub fn backend_timeout_duration(&self) -> std::time::Duration {
        let ms = if self.backend_timeout == 0 {
            default_backend_timeout()
        } else {
            self.backend_timeout
        };
        std::time::Duration::from_millis(ms)
    }

    /// The address(es) to bind to — `address` (a list) if it's set and
    /// non-empty, otherwise the single `host` for backward
    /// compatibility. Always returns at least one entry.
    pub fn bind_addresses(&self) -> Vec<String> {
        if self.host.is_empty() {
            // Defends against an explicit `"host": []` in config.json
            // — always bind to *something* rather than silently
            // listening nowhere.
            vec![default_host()]
        } else {
            self.host.clone()
        }
    }

    /// Decides whether `username` may access a route with these
    /// `username`/`groups`/`roles` settings — the single source of
    /// truth both `network::proxy`'s live access check and
    /// `proxyauth routes-audit`/`check-access` call, so the CLI audit
    /// tool can never silently disagree with what the running proxy
    /// actually enforces.
    pub fn route_access_decision(&self, rule: &RouteRule, username: &str) -> RouteAccessDecision {
        if rule.username.iter().any(|u| u == username) {
            return RouteAccessDecision::AllowedByUsername;
        }

        if !rule.groups.is_empty() {
            let user_groups = self.groups_for_username(username).unwrap_or_default();
            if let Some(g) = rule.groups.iter().find(|g| user_groups.contains(g)) {
                return RouteAccessDecision::AllowedByGroup(g.clone());
            }
        }

        if !rule.roles.is_empty() {
            let user_roles = self.roles_for_username(username).unwrap_or_default();
            if let Some(r) = rule.roles.iter().find(|r| user_roles.contains(r)) {
                return RouteAccessDecision::AllowedByRole(r.clone());
            }
        }

        if rule.username.is_empty() && rule.groups.is_empty() && rule.roles.is_empty() {
            return RouteAccessDecision::AllowedNoRestrictionConfigured;
        }

        RouteAccessDecision::Denied
    }

    /// `run_user`, treating an explicitly empty string
    /// (`"run_user": ""` in `config.json`) the same as the field being
    /// absent entirely — `#[serde(default = ...)]` only kicks in when
    /// a field is *missing*, not when it's present but empty, so
    /// without this an explicit `""` would otherwise be used verbatim
    /// as a literal (nonexistent) username to switch to.
    pub fn effective_run_user(&self) -> &str {
        if self.run_user.trim().is_empty() {
            "proxyauth"
        } else {
            self.run_user.trim()
        }
    }

    /// Same normalization as `effective_run_user`, for `run_group`:
    /// an explicit empty string is treated as `None` (use
    /// `effective_run_user`'s own primary group), not as a literal
    /// empty-named group to look up.
    pub fn effective_run_group(&self) -> Option<&str> {
        self.run_group
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty())
    }
}

impl AppConfig {
    /// Returns a snapshot combining file-based `users` with the current
    /// database-loaded users (if `databases` is configured), in a stable
    /// concatenation: `users` first (unchanged order), then `db_users`
    /// (unchanged order). This order matters — issued tokens embed a
    /// numeric index into this combined list (see `user_by_index`), so
    /// nothing here may ever reorder or remove entries, only append or
    /// update in place (see `refresh_db_users`).
    pub fn combined_users(&self) -> Vec<User> {
        let mut combined = self.users.clone();
        if let Ok(db_users) = self.db_users.read() {
            combined.extend(db_users.iter().cloned());
        }
        combined
    }

    /// Returns a single user's `roles`, looked up by username, via
    /// `roles_index` — an O(1) average-case HashMap lookup, not a scan
    /// over every user. Used on the proxied-request hot path
    /// (`inject_header`), which only ever needs one user's roles per
    /// request — a linear scan (or worse, `combined_users()`'s full
    /// clone) doesn't scale with the user count.
    pub fn roles_for_username(&self, username: &str) -> Option<Vec<String>> {
        self.roles_index.read().ok()?.get(username).cloned()
    }

    /// Same as `roles_for_username`, for `groups_index` — the lookup
    /// `RouteRule.groups` access checks use, on the same proxied-request
    /// hot path.
    pub fn groups_for_username(&self, username: &str) -> Option<Vec<String>> {
        self.groups_index.read().ok()?.get(username).cloned()
    }

    /// Marks this instance's in-memory state as changed — called from
    /// every function that actually mutates it. See `generation`'s doc
    /// comment: the Blakegate client task polls `current_generation()`
    /// to know when to push a fresh snapshot.
    pub fn bump_generation(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Current value of `generation` — changes whenever
    /// `bump_generation()` has been called since this instance
    /// started. Not meaningful on its own, only as "did this go up
    /// since I last checked".
    pub fn current_generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `true` when `blakegate` has at least one entry configured —
    /// meaning this instance is meant to be running in Blakegate
    /// "backup mode": Blakegate is the source of truth for users,
    /// pushed over the websocket (`proto::blakegate::apply_users_sync`),
    /// not the local database. Doesn't reflect whether any connection
    /// is actually *up* right now — see `should_use_database_as_fallback`
    /// for that.
    pub fn blakegate_backup_mode_active(&self) -> bool {
        !self.blakegate.is_empty()
    }

    /// Whether the periodic database-refresh tasks
    /// (`refresh_db_users`/`refresh_db_users_incremental`, scheduled in
    /// `main.rs`) should actually run right now.
    ///
    /// `true` in two cases: backup mode isn't active at all (`blakegate`
    /// is empty — the normal, pre-existing behavior, unaffected by any
    /// of this), or backup mode *is* active but every configured
    /// endpoint is currently unreachable. That second case is the
    /// fallback this whole mode exists to provide: if Blakegate goes
    /// away, this instance still has a locally-backed-up copy of its
    /// users (kept up to date by `apply_users_sync`'s own write to the
    /// database every time Blakegate pushes a fresh list) to fall back
    /// on, rather than being stuck with whatever was last pushed
    /// indefinitely or unable to authenticate anyone new.
    ///
    /// `false` — meaning the periodic refresh is skipped — only when
    /// backup mode is active AND at least one Blakegate connection is
    /// currently up: in that case Blakegate is actively supplying user
    /// data, and the database must not also be syncing into memory at
    /// the same time, or the two sources could fight each other over
    /// which one 'wins' on any given refresh tick.
    pub fn should_use_database_as_fallback(&self) -> bool {
        !self.blakegate_backup_mode_active()
            || self
                .blakegate_connected
                .load(std::sync::atomic::Ordering::Relaxed)
                == 0
    }

    /// Applies a full, authoritative user list pushed by Blakegate —
    /// see `proto::blakegate::apply_users_sync`. Same semantics as a
    /// full database reload (`refresh_db_users`): any account *not* in
    /// `fresh` is treated as removed and revoked (password poisoned,
    /// dropped from the roles/groups indices) — this mirrors that
    /// exact mechanism, just sourced from a Blakegate push instead of
    /// a database query, since a `users_sync` message is meant to be
    /// the complete, current list, not an incremental diff.
    pub fn apply_blakegate_users(&self, fresh: &[User]) {
        let fresh_usernames: std::collections::HashSet<&str> =
            fresh.iter().map(|u| u.username.as_str()).collect();

        let Some(mut guard) = self.apply_upserts(fresh) else {
            return;
        };

        let Ok(mut revoked) = self.db_revoked.write() else {
            eprintln!("[blakegate] failed to acquire db_revoked lock while applying users_sync");
            return;
        };

        for (idx, user) in guard.iter_mut().enumerate() {
            if fresh_usernames.contains(user.username.as_str()) {
                revoked.remove(&idx);
            } else if revoked.insert(idx) {
                user.password = "!revoked!".to_string();
                self.index_roles(&user.username, &None);
                self.index_groups(&user.username, &None);
            }
        }
        drop(revoked);
        drop(guard);

        self.bump_generation();
    }

    /// Inserts or removes a single entry in `roles_index`, keeping it in
    /// sync with a user's current `roles`. `None`/empty roles removes
    /// the entry entirely (a HashMap miss and "no roles" both correctly
    /// resolve to `roles_for_username` returning `None`).
    fn index_roles(&self, username: &str, roles: &Option<Vec<String>>) {
        let Ok(mut index) = self.roles_index.write() else {
            return;
        };
        match roles {
            Some(r) if !r.is_empty() => {
                index.insert(username.to_string(), r.clone());
            }
            _ => {
                index.remove(username);
            }
        }
    }

    /// Same as `index_roles`, for `groups_index`/`User.groups`.
    fn index_groups(&self, username: &str, groups: &Option<Vec<String>>) {
        let Ok(mut index) = self.groups_index.write() else {
            return;
        };
        match groups {
            Some(g) if !g.is_empty() => {
                index.insert(username.to_string(), g.clone());
            }
            _ => {
                index.remove(username);
            }
        }
    }

    /// Resolves a user by its position in the same index space
    /// `combined_users()` produces, without cloning the whole list.
    /// Indices `0..self.users.len()` map to file users; indices at or
    /// past that map into `db_users`. Used when validating a token's
    /// embedded user index. Returns `None` — rejecting the token — for
    /// an index whose database user was since deleted (see
    /// `refresh_db_users`), even though the slot itself still exists.
    pub fn user_by_index(&self, index: usize) -> Option<User> {
        if let Some(u) = self.users.get(index) {
            return Some(u.clone());
        }
        let db_index = index.checked_sub(self.users.len())?;

        if let Ok(revoked) = self.db_revoked.read() {
            if revoked.contains(&db_index) {
                return None;
            }
        }

        self.db_users.read().ok()?.get(db_index).cloned()
    }

    /// Re-reads `databases` (if configured) and refreshes the in-memory
    /// `db_users` snapshot. Never panics — a DB outage just leaves the
    /// previous snapshot in place.
    ///
    /// SECURITY: existing users are updated *in place* and new users are
    /// only ever *appended* — never removed or reordered — so a
    /// previously issued token's embedded index (see `user_by_index`)
    /// keeps resolving to the same slot across refreshes.
    ///
    /// A user removed from the database is detected here (its username
    /// is no longer present in `fresh`) and its slot is *revoked*
    /// in place, without ever deleting/reordering it:
    /// - its `password` is overwritten with a sentinel that can never
    ///   verify, so it immediately stops being able to log in again;
    /// - its raw index is recorded in `db_revoked`, so `user_by_index`
    ///   rejects any token already issued for it, invalidating that
    ///   session immediately rather than waiting for it to expire.
    ///
    /// If a username reappears later (re-created), the slot is reused
    /// and un-revoked automatically.
    ///
    /// SECURITY: if the database can't be reached at all right now, and
    /// there's no usable local cache either
    /// (`load_users_from_config` returns `None`), this returns
    /// immediately without touching `db_users`/`db_revoked` — a
    /// transient outage must never be misread as "every database user
    /// was deleted."
    ///
    /// If the only thing available is the local LMDB cache
    /// (`UsersSource::Cache`) rather than a fresh database read
    /// (`UsersSource::Database`), the revoke-by-absence comparison below
    /// is skipped entirely — only upserts are applied. The cache is
    /// only refreshed on a successful *full* scan, so it can lag behind
    /// a user created moments ago via the more frequent incremental
    /// scan; comparing that user's presence against a stale cached
    /// snapshot would incorrectly revoke them for simply not having
    /// existed yet in that older snapshot. Only a genuinely current
    /// database read is trustworthy enough to conclude "this username
    /// is really gone."
    pub fn refresh_db_users(&self) {
        let Some(db_cfg) = &self.databases else {
            return;
        };

        let Some(source) = crate::databases::db::load_users_from_config(db_cfg) else {
            return;
        };

        let fresh = source.users();

        if let crate::databases::db::UsersSource::Cache(_) = &source {
            self.apply_upserts(fresh);
            self.bump_generation();
            return;
        }

        let fresh_usernames: std::collections::HashSet<&str> =
            fresh.iter().map(|u| u.username.as_str()).collect();

        let Some(mut guard) = self.apply_upserts(fresh) else {
            return;
        };

        let Ok(mut revoked) = self.db_revoked.write() else {
            eprintln!("[databases] failed to acquire db_revoked lock");
            return;
        };

        for (idx, user) in guard.iter_mut().enumerate() {
            if fresh_usernames.contains(user.username.as_str()) {
                revoked.remove(&idx);
            } else if revoked.insert(idx) {
                // Not a valid argon2 hash — PasswordHash::verify_password
                // will fail to parse it and always return an error, so
                // this account can never authenticate again.
                user.password = "!revoked!".to_string();
                self.index_roles(&user.username, &None);
                self.index_groups(&user.username, &None);
            }
        }

        self.bump_generation();
    }

    /// Lightweight sibling of `refresh_db_users`: reads only the users
    /// changed in the last `incremental_window_secs` (see
    /// `DatabaseConfig`) instead of the whole table — the query cost
    /// scales with recent changes, not total row count.
    ///
    /// Unlike the previous design, this *can* revoke users now: a
    /// soft-deletion (`db::mark_user_deleted`) is itself a
    /// `modified_at`-bumping UPDATE, so it naturally falls inside the
    /// scanned window and comes back as `DbUserChange::Deleted` — no
    /// need to wait for the slower full scan to notice it. The full
    /// scan (`refresh_db_users`) remains a safety net for anything that
    /// bypassed the soft-delete convention (e.g. a manual hard `DELETE`
    /// run directly against the database).
    pub fn refresh_db_users_incremental(&self) {
        let Some(db_cfg) = &self.databases else {
            return;
        };

        let changes = crate::databases::db::load_recently_changed_from_config(
            db_cfg,
            db_cfg.incremental_window_secs,
        );
        if changes.is_empty() {
            return;
        }

        let mut upserts = Vec::new();
        let mut deletions = Vec::new();
        for change in changes {
            match change {
                crate::databases::db::DbUserChange::Upserted(u) => upserts.push(u),
                crate::databases::db::DbUserChange::Deleted { username } => {
                    deletions.push(username)
                }
            }
        }

        if !upserts.is_empty() {
            self.apply_upserts(&upserts);
        }

        for username in &deletions {
            self.revoke_username_now(username);
        }

        self.bump_generation();
    }

    /// Revokes a single user immediately, by username, without scanning
    /// the whole `db_users` list for absentees like `refresh_db_users`
    /// does. Same poisoning mechanism (password sentinel + `db_revoked`
    /// index) — just triggered by an explicit soft-deletion event
    /// instead of "missing from a full reload". A no-op if the username
    /// isn't currently known.
    fn revoke_username_now(&self, username: &str) {
        let mut guard = match self.db_users.write() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[databases] failed to acquire db_users lock: {e}");
                return;
            }
        };

        let Some(idx) = guard.iter().position(|u| u.username == username) else {
            return;
        };

        let Ok(mut revoked) = self.db_revoked.write() else {
            eprintln!("[databases] failed to acquire db_revoked lock");
            return;
        };

        if revoked.insert(idx) {
            guard[idx].password = "!revoked!".to_string();
            self.index_roles(username, &None);
            self.index_groups(username, &None);
        }
    }

    /// Immediately reflects a single database user's fresh data (e.g.
    /// right after a password change via `/reset-password`) into the
    /// in-memory `db_users` snapshot, without waiting for the next
    /// scan tick. Thin public wrapper around the same `apply_upserts`
    /// the periodic scans use.
    pub fn upsert_db_user_now(&self, user: User) {
        self.apply_upserts(&[user]);
    }

    /// Shared upsert-in-place-or-append step used by both
    /// `refresh_db_users` and `refresh_db_users_incremental`. Returns
    /// the write guard (still held) so `refresh_db_users` can continue
    /// straight on to its deletion-detection pass without re-locking.
    ///
    /// Also un-revokes every touched index: a user reappearing via
    /// upsert (soft-delete undone, or re-created with the same
    /// username) must stop being rejected by `user_by_index` — without
    /// this, a previously revoked slot would stay revoked forever even
    /// after being upserted with fresh, valid data.
    fn apply_upserts<'a>(
        &'a self,
        fresh: &[User],
    ) -> Option<std::sync::RwLockWriteGuard<'a, Vec<User>>> {
        let mut guard = match self.db_users.write() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[databases] failed to acquire db_users lock: {e}");
                return None;
            }
        };

        let mut touched_indices = Vec::with_capacity(fresh.len());

        for new_user in fresh {
            if let Some(idx) = guard.iter().position(|u| u.username == new_user.username) {
                guard[idx] = new_user.clone();
                touched_indices.push(idx);
            } else {
                guard.push(new_user.clone());
                touched_indices.push(guard.len() - 1);
            }
            self.index_roles(&new_user.username, &new_user.roles);
            self.index_groups(&new_user.username, &new_user.groups);
        }

        if let Ok(mut revoked) = self.db_revoked.write() {
            for idx in touched_indices {
                revoked.remove(&idx);
            }
        } else {
            eprintln!("[databases] failed to acquire db_revoked lock while un-revoking");
        }

        Some(guard)
    }
}

pub fn load_config(path: &str) -> Arc<AppConfig> {
    let config_str = fs::read_to_string(path).expect("Could not read config.json file");
    let mut config: AppConfig =
        serde_json::from_str(&config_str).expect("Invalid config format config.json");

    let mut updated = false;

    for user in &mut config.users {
        if !user.password.starts_with("$argon2") {
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(user.password.as_bytes(), &salt)
                .expect(&format!(
                    "Password hashing failed for user {}",
                    user.username
                ))
                .to_string();
            user.password = hash;
            updated = true;
        }
    }

    let original_order: Vec<String> = config.users.iter().map(|u| u.username.clone()).collect();
    config
        .users
        .sort_by(|a, b| a.username.to_lowercase().cmp(&b.username.to_lowercase()));

    let sorted_order: Vec<String> = config.users.iter().map(|u| u.username.clone()).collect();
    if original_order != sorted_order {
        updated = true;
    }

    if config.token_admin.trim().is_empty() {
        config.token_admin = generate_random_string(64);
        updated = true;
    }

    if updated {
        let updated_str = serde_json::to_string_pretty(&config).expect("Serialization failed");
        fs::write(path, updated_str).expect("Failed to write updated config");
    }

    // Seed roles_index for file-based users once — `users` never changes
    // after this point, so this never needs to run again (unlike the
    // periodic refresh below, for database users).
    let app_config = Arc::new(config);
    for user in &app_config.users {
        app_config.index_roles(&user.username, &user.roles);
        app_config.index_groups(&user.username, &user.groups);
    }

    // Load users stored in the database (if `databases` is configured)
    // into `db_users`, refreshed periodically afterwards by a background
    // task (see main.rs). Done *after* the file write-back above so
    // DB-sourced users are never persisted into config.json.
    app_config.refresh_db_users();
    app_config
}

/// Clears a user's TOTP secret, so they can re-enroll via
/// `/adm/auth/totp/get`. This is the counterpart admins are told to use
/// (see the 409 response in `adm/registry_otp.rs::get_otpauth_uri`) when a
/// user is locked out of an already-provisioned OTP key (lost device,
/// botched enrollment, suspected compromise, etc.).
///
/// Returns `Ok(true)` if a key was cleared, `Ok(false)` if the user had no
/// key set (nothing to do), and `Err(_)` on I/O/parse failure or an
/// unknown username. Never panics — this is reachable from a network
/// request (`/adm/auth/totp/reset`), and a panic anywhere in a request
/// path is worth avoiding regardless of the release profile's panic
/// strategy.
pub fn clear_otpkey(config_path: &str, username: &str) -> Result<bool, String> {
    if !Path::new(config_path).exists() {
        return Err(format!("Config file not found: {}", config_path));
    }

    let config_str = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read the configuration file: {e}"))?;
    let mut json: Value = serde_json::from_str(&config_str)
        .map_err(|e| format!("Invalid JSON format in configuration file: {e}"))?;

    let users = json
        .get_mut("users")
        .and_then(|u| u.as_array_mut())
        .ok_or_else(|| "Missing 'users' field in configuration file.".to_string())?;

    let mut found = false;
    let mut cleared = false;

    for user in users.iter_mut() {
        let name = user.get("username").and_then(|u| u.as_str());
        if name == Some(username) {
            found = true;
            if let Some(obj) = user.as_object_mut() {
                if obj.remove("otpkey").is_some() {
                    cleared = true;
                }
            }
            break;
        }
    }

    if !found {
        return Err(format!(
            "User '{}' not found in the configuration file.",
            username
        ));
    }

    if cleared {
        let updated_str = serde_json::to_string_pretty(&json)
            .map_err(|e| format!("Failed to serialize the updated configuration: {e}"))?;
        fs::write(config_path, updated_str)
            .map_err(|e| format!("Failed to write the updated configuration file: {e}"))?;
    }

    Ok(cleared)
}

#[allow(dead_code)]
/// Generates and stores a new OTP key for `username` in `config.json`,
/// unless one is already set (returns `Ok(false)` in that case — not
/// an error, this endpoint's caller decides what "already enrolled"
/// means for its own flow).
///
/// Returns `Ok(true)` if a key was generated and written, `Ok(false)`
/// if the user already had one (nothing changed), and `Err(_)` on
/// I/O/parse failure or an unknown username — the same `Result`-based
/// pattern `clear_otpkey` already uses, and for the same reason: this
/// is reachable from a live HTTP route (`/adm/auth/totp/get`), and
/// this used to `.expect()` on every file read/parse/write step,
/// panicking the request on a transiently unreadable or malformed
/// config file. Also no longer prints the generated secret to stdout —
/// a raw TOTP secret ending up in a captured log (systemd/journald, a
/// redirected stdout, ...) is exactly the kind of exposure enrollment
/// is supposed to protect against in the first place; the caller
/// already gets the secret back through the normal `Ok(true)` /
/// re-read path, nothing needs it printed here too.
pub fn add_otpkey(config_path: &str, username: &str) -> Result<bool, String> {
    if !Path::new(config_path).exists() {
        return Err(format!("Config file not found: {}", config_path));
    }

    let config_str = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read the configuration file: {e}"))?;
    let mut json: Value = serde_json::from_str(&config_str)
        .map_err(|e| format!("Invalid JSON format in configuration file: {e}"))?;

    let users = json
        .get_mut("users")
        .and_then(|u| u.as_array_mut())
        .ok_or_else(|| "Missing 'users' field in configuration file.".to_string())?;

    let mut found = false;
    let mut updated = false;

    for user in users.iter_mut() {
        let name = user.get("username").and_then(|u| u.as_str());
        if name == Some(username) {
            found = true;
            if user.get("otpkey").is_some() {
                // Already enrolled — not this function's job to decide
                // whether that's fine or not (see `allow_totp_reenroll`
                // for the vhost-level policy on that); just report
                // nothing changed.
            } else {
                let otpkey = generate_base32_secret(32);
                user.as_object_mut()
                    .ok_or_else(|| format!("User '{}' is not a JSON object.", username))?
                    .insert("otpkey".to_string(), Value::String(otpkey));
                updated = true;
            }
            break;
        }
    }

    if !found {
        return Err(format!(
            "User '{}' not found in the configuration file.",
            username
        ));
    }

    if updated {
        let updated_str = serde_json::to_string_pretty(&json)
            .map_err(|e| format!("Failed to serialize the updated configuration: {e}"))?;
        fs::write(config_path, updated_str)
            .map_err(|e| format!("Failed to write the updated configuration file: {e}"))?;
    }

    Ok(updated)
}

fn deserialize_log_map<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct LogMapVisitor;

    impl<'de> Visitor<'de> for LogMapVisitor {
        type Value = HashMap<String, String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a map with string keys and string/int/bool values")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = HashMap::new();
            while let Some((k, v)) = access.next_entry::<String, serde_json::Value>()? {
                let stringified = match v {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => continue,
                };
                map.insert(k, stringified);
            }
            Ok(map)
        }
    }

    let value = deserializer.deserialize_map(LogMapVisitor);
    match value {
        Ok(v) => Ok(v),
        Err(_) => Ok(default_log()),
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "field", rename_all = "snake_case")]
pub enum RegexCondCfg {
    Method { pattern: String },
    Path { pattern: String },
    Header { name: String, pattern: String },
    Query { name: String, pattern: String },
    BodyRaw { pattern: String },
    BodyJson { key: String, pattern: String },
}

impl AllowRegexCfg {
    pub fn compile(&self) -> Result<CompiledAllow, regex::Error> {
        fn conv(c: &RegexCondCfg) -> Result<RegexCond, regex::Error> {
            match c {
                RegexCondCfg::Method { pattern } => Ok(RegexCond::Method {
                    re: Regex::new(pattern)?,
                }),
                RegexCondCfg::Path { pattern } => Ok(RegexCond::Path {
                    re: Regex::new(pattern)?,
                }),
                RegexCondCfg::Header { name, pattern } => Ok(RegexCond::Header {
                    name_re: Regex::new(name)?,
                    re: Regex::new(pattern)?,
                }),
                RegexCondCfg::Query { name, pattern } => Ok(RegexCond::Query {
                    name_re: Regex::new(name)?,
                    re: Regex::new(pattern)?,
                }),
                RegexCondCfg::BodyRaw { pattern } => Ok(RegexCond::BodyRaw {
                    re: Regex::new(pattern)?,
                }),
                RegexCondCfg::BodyJson { key, pattern } => Ok(RegexCond::BodyJson {
                    key: key.clone(),
                    re: Regex::new(pattern)?,
                }),
            }
        }
        let mut allow = Vec::with_capacity(self.allow.len());
        for c in &self.allow {
            allow.push(conv(c)?);
        }
        Ok(CompiledAllow {
            default_allow: self.default_allow,
            allow,
        })
    }
}
