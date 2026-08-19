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

#[derive(Debug, Deserialize, Clone)]
pub struct RouteRule {
    pub prefix: String,
    pub target: String,

    #[serde(default = "default_username")]
    pub username: Vec<String>,

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

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: i16,
}

fn default_weight() -> i16 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BackendInput {
    Simple(String),
    Detailed(BackendConfig),
}

#[derive(Default, Debug, Deserialize)]
pub struct RouteConfig {
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
    pub otpkey: Option<String>,
    pub allow: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,

    #[allow(dead_code)]
    pub email: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
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
        let mut state = serializer.serialize_struct("User", 2)?;
        state.serialize_field("username", &self.username)?;
        state.serialize_field("password", &self.password)?;
        state.serialize_field("otpkey", &self.otpkey)?;
        state.serialize_field("allow", &self.allow)?;
        state.serialize_field("roles", &self.allow)?;
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

    /// How often (in seconds) to re-scan the database and refresh the
    /// in-memory user list, so users added/edited directly in the DB
    /// eventually take effect without restarting the process. Defaults
    /// to 30s. Set to 0 to disable periodic refresh (DB is only read
    /// once, at startup).
    #[serde(default = "default_db_refresh_interval")]
    pub refresh_interval_secs: u64,
}

fn default_db_refresh_interval() -> u64 {
    30
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

    pub smtp: Option<SmtpConfig>,

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
}

impl Serialize for AppConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
    S: Serializer,
    {
        let mut state = serializer.serialize_struct("AppConfig", 7)?;
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
    pub fn refresh_db_users(&self) {
        let Some(db_cfg) = &self.databases else {
            return;
        };

        let fresh = crate::databases::db::load_users_from_config(db_cfg);
        let fresh_usernames: std::collections::HashSet<&str> =
        fresh.iter().map(|u| u.username.as_str()).collect();

        let mut guard = match self.db_users.write() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[databases] failed to acquire db_users lock: {e}");
                return;
            }
        };

        for new_user in &fresh {
            if let Some(existing) = guard.iter_mut().find(|u| u.username == new_user.username) {
                *existing = new_user.clone();
            } else {
                guard.push(new_user.clone());
            }
            self.index_roles(&new_user.username, &new_user.roles);
        }

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
            }
        }
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

#[derive(Debug, Deserialize, Clone)]
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
