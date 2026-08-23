use crate::adm::method_otp::generate_base32_secret;
use crate::network::shared_client::BoxBody;
use crate::network::stats::RequestStats;
use crate::revoke::db::RevokedTokenMap;
use crate::smtp::smtp::SmtpConfig;
use crate::stats::tokencount::CounterToken;
use crate::token::auth::generate_random_string;
use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher};
use dashmap::DashMap;
use hyper_http_proxy::ProxyConnector;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
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

    #[serde(default = "default_need_csrf")]
    pub need_csrf: bool,

    #[serde(default = "default_cache")]
    pub cache: bool,

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

    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

impl RouteConfig {
    /// Moves every route out of `vhosts` groups and into `routes`,
    /// stamping each one with its group's `vhost`/`vhost_cert` unless the
    /// route already set its own (individual routes can still override a
    /// group's default this way). Called once, right after parsing
    /// `routes.yml`, so every other piece of code — matching, the SNI
    /// certificate resolver, `proxyauth routes-audit`/`check-access` —
    /// only ever sees the flat `routes` list it already understands.
    pub fn expand_vhost_groups(mut self) -> Self {
        for group in self.vhosts.drain(..) {
            for mut route in group.routes {
                if route.vhost.is_empty() {
                    route.vhost = group.vhost.clone();
                }
                if route.vhost_cert.is_empty() {
                    route.vhost_cert = group.vhost_cert.clone();
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
        self.port.unwrap_or_else(|| match self.db_type.to_lowercase().as_str() {
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

    #[serde(default = "default_host")]
    pub host: String,

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

    #[serde(default = "default_stats")]
    pub stats: bool,

    #[serde(default)]
    pub trust_proxy_forward_for: Option<Vec<String>>,

    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

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
        state.serialize_field("cors_origins", &self.cors_origins)?;
        state.serialize_field("databases", &self.databases)?;
        state.serialize_field("fast", &self.fast)?;
        state.serialize_field("host", &self.host)?;
        state.serialize_field("keep_alive", &self.keep_alive)?;
        state.serialize_field("log", &self.log)?;
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
    #[allow(dead_code)]
    pub client_normal: Client<HttpsConnector<HttpConnector>, BoxBody>,
    #[allow(dead_code)]
    pub client_with_cert: Client<HttpsConnector<HttpConnector>, BoxBody>,
    #[allow(dead_code)]
    pub client_with_proxy: Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody>,
    pub revoked_tokens: RevokedTokenMap,
    pub stats: Arc<RequestStats>,

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
pub fn resolve_must_change_password(
    state: &AppState,
    username: &str,
    config_value: bool,
) -> bool {
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
                obj.insert(
                    "must_change_password".to_string(),
                           Value::Bool(false),
                );
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

fn default_timezone() -> String {
    "Europe/Paris".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_cache() -> bool {
    true
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

fn default_need_csrf() -> bool {
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

fn default_static_index() -> String {
    "index.html".to_string()
}

/// Checks a raw `routes.yml` for the deprecated `secure` key, which was
/// renamed to `required_login`. Unlike a normal unknown field, `secure`
/// used to control whether a route required authentication — silently
/// ignoring it would leave routes unauthenticated without warning anyone,
/// so we fail loudly instead of falling back to the `required_login`
/// default.
pub fn check_deprecated_secure_key(routes_str: &str) -> Result<(), String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(routes_str)
    .map_err(|e| format!("Failed to parse routes.yml: {e}"))?;

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
pub fn add_otpkey(config_path: &str, username: &str) {
    if !Path::new(config_path).exists() {
        eprintln!("Config file not found: {}", config_path);
        return;
    }

    let config_str =
    fs::read_to_string(config_path).expect("Failed to read the configuration file.");
    let mut json: Value =
    serde_json::from_str(&config_str).expect("Invalid JSON format in configuration file.");

    let users = json
    .get_mut("users")
    .and_then(|u| u.as_array_mut())
    .expect("Missing 'users' field in configuration file.");

    let mut updated = false;

    for user in users.iter_mut() {
        let name = user.get("username").and_then(|u| u.as_str());
        if name == Some(username) {
            if user.get("otpkey").is_some() {
                println!("User '{}' already has an OTP key.", username);
            } else {
                let otpkey = generate_base32_secret(32);
                user.as_object_mut()
                .unwrap()
                .insert("otpkey".to_string(), Value::String(otpkey.clone()));
                println!(
                    "OTP key successfully generated for '{}': {}",
                    username, otpkey
                );
                updated = true;
            }
            break;
        }
    }

    if updated {
        let updated_str = serde_json::to_string_pretty(&json)
        .expect("Failed to serialize the updated configuration.");
        fs::write(config_path, updated_str)
        .expect("Failed to write the updated configuration file.");
        println!("Configuration file has been updated.");
    } else if !users
        .iter()
        .any(|u| u.get("username").and_then(|n| n.as_str()) == Some(username))
        {
            eprintln!("User '{}' not found in the configuration file.", username);
        }
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
