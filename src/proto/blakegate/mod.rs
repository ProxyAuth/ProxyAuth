//! Blakegate — pushes ProxyAuth's live in-memory configuration to
//! external WebSocket endpoints, near real-time.
//!
//! # What gets sent, and what deliberately doesn't
//!
//! Every push is a JSON object: `proxyauth_id` (this crate's own
//! build identity — see [`ID`], generated once at compile time by
//! `build/build.rs` and baked into the binary; every instance running
//! that exact build reports the same value) plus the full in-memory
//! `config.json` shape (`AppConfig`) and the full in-memory
//! `routes.yml` shape (`RouteConfig`) — **redacted**
//! first. `AppConfig`'s own
//! `Serialize` impl (used to rewrite `config.json` back to disk) is
//! deliberately NOT reused as-is here: that impl includes `secret`
//! (the server's own token-signing master key) and every user's
//! `password` (an Argon2 hash) / `otpkey` (a TOTP seed) /
//! `anti_replay_secret` (ciphertext, but still key material) —
//! entirely appropriate for a local disk rewrite of the exact file
//! this data came from, but not something to hand to a remote
//! process over the network, however trusted the operator considers
//! it. Those specific fields are stripped before anything is
//! serialized to send; everything else (routing rules, rate limits,
//! which users exist and their roles/groups/email, ...) goes through
//! unredacted, since surfacing that is the whole point of this
//! feature.
//!
//! **Operators are responsible for treating every `blakegate` URL as
//! a trusted endpoint.** What's sent is still meaningfully sensitive
//! (usernames, roles, groups, email addresses, full routing
//! configuration) even with the redaction above.
//!
//! # Connection model
//!
//! One background task per configured URL. Each task:
//!
//! 1. Connects (`wss://`/`ws://` — see [`to_websocket_url`]), retrying
//!    with a fixed delay on failure. A Blakegate endpoint being
//!    temporarily unreachable never blocks ProxyAuth's own request
//!    handling — this is entirely decoupled from it.
//! 2. Sends a full snapshot immediately on every successful connect —
//!    the peer has no prior state to diff against otherwise.
//! 3. Polls [`AppConfig::current_generation`] on a short interval;
//!    sends a fresh snapshot whenever it's changed since the last
//!    send. This is *near* real-time, not instant — the actual
//!    latency is [`POLL_INTERVAL`]. Polling a counter is far less
//!    invasive than threading a broadcast channel through every one
//!    of the several, scattered functions that mutate `AppConfig`'s
//!    in-memory state, at the cost of that small fixed delay and, at
//!    most, one wasted "nothing changed" check per interval per
//!    connection.
//! 4. Reads every message the endpoint sends back and dispatches on
//!    it — currently one recognized request, `{"kind": "backup_users"}`
//!    (see [`handle_incoming_message`]/[`backup_users_to_database`]):
//!    writes every currently known account into the configured
//!    `databases` backend, on demand, only when Blakegate explicitly
//!    asks for it — never on a timer, never just because this
//!    instance happens to have accounts in memory. Anything else
//!    received is logged and otherwise ignored, so an unrecognized or
//!    future message kind never breaks the connection. Treat incoming
//!    messages as untrusted input: `backup_users` only ever writes
//!    ProxyAuth's *own already-known* accounts into a database it's
//!    already configured to use — it can't be used to inject
//!    arbitrary data, but a compromised or misbehaving endpoint could
//!    still trigger backups more often than intended.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::config::config::{AppConfig, RouteConfig};

/// How often each connection checks whether the in-memory generation
/// counter has moved since its last push. This is the effective
/// upper bound on push latency after a change — see the module doc
/// comment for why this is polled rather than event-driven.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Delay before retrying after a failed connect, or after an
/// established connection ends (error or peer close). Fixed rather
/// than exponential backoff — Blakegate endpoints are expected to be
/// long-lived internal infrastructure, not something ProxyAuth should
/// back off hard from; a short, constant retry keeps recovery fast
/// after a brief blip (a deploy, a restart) without hammering a
/// genuinely-down endpoint too aggressively either.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// ProxyAuth's own build identity — set once at compile time by
/// `build/build.rs` (`cargo:rustc-env=id=...`), which makes it
/// available to `env!("id")` anywhere in this crate, not just
/// `main.rs` where it's also referenced (as `const ID`) for the
/// startup banner. Every instance running this exact build reports
/// the same value.
const ID: &str = env!("id");

/// A TLS certificate verifier that accepts anything — used only for
/// `blakegate` entries with `selfcert: true`. See `BlakegateEndpoint`'s
/// doc comment on `selfcert` for what this actually gives up: this
/// makes the connection's TLS handshake trust *any* certificate the
/// endpoint presents, self-signed or not, matching hostname or not.
/// Never used unless an operator explicitly opts a specific endpoint
/// into it.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // A broad, standard set — this verifier never actually checks
        // the signature (both verify_tls1*_signature methods above
        // always succeed), so this just needs to list schemes rustls
        // will consider negotiable at all.
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Builds the `tokio_tungstenite` connector for one endpoint:
/// `None` (the crate's normal, trusted-CA verification) unless
/// `accept_self_signed` is set, in which case a rustls config using
/// [`AcceptAnyCertificate`] instead — see `BlakegateEndpoint::selfcert`.
fn build_connector(accept_self_signed: bool) -> Option<Connector> {
    if !accept_self_signed {
        return None;
    }
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth();
    Some(Connector::Rustls(Arc::new(tls_config)))
}

/// Rewrites an operator-supplied URL's scheme to a WebSocket one.
/// `https://`/`http://` are accepted for convenience (easier to
/// type/paste than `wss://`/`ws://`) and always rewritten, never
/// connected to literally — ProxyAuth never speaks plain HTTP(S) to a
/// `blakegate` entry. A URL with no recognized scheme at all defaults
/// to `wss://` (secure by default). An already-`ws://`/`wss://` URL
/// passes through unchanged.
fn to_websocket_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if url.starts_with("wss://") || url.starts_with("ws://") {
        url.to_string()
    } else {
        format!("wss://{url}")
    }
}

/// Builds the redacted JSON payload for one push — see the module doc
/// comment for exactly what's stripped and why.
fn build_snapshot(config: &AppConfig, routes: &RouteConfig) -> Value {
    let mut config_value = serde_json::to_value(config).unwrap_or(Value::Null);
    if let Some(obj) = config_value.as_object_mut() {
        obj.remove("secret");
        if let Some(users) = obj.get_mut("users").and_then(|u| u.as_array_mut()) {
            for user in users {
                if let Some(user_obj) = user.as_object_mut() {
                    user_obj.remove("password");
                    user_obj.remove("otpkey");
                    user_obj.remove("anti_replay_secret");
                }
            }
        }
    }

    let routes_value = serde_json::to_value(&routes.routes).unwrap_or(Value::Null);

    json!({
        "kind": "proxyauth_snapshot",
        "proxyauth_id": ID,
        "sent_at_unix_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        "config": config_value,
        "routes": routes_value,
    })
}

/// Starts one background task per `config.blakegate` entry. Returns
/// immediately — connection attempts and all pushes happen entirely
/// on spawned tasks; this never blocks startup, and a misconfigured
/// or unreachable endpoint never affects ProxyAuth's own request
/// handling.
pub fn spawn_clients(config: Arc<AppConfig>, routes: Arc<RouteConfig>) {
    for endpoint in &config.blakegate {
        let url = to_websocket_url(endpoint.url());
        let accept_self_signed = endpoint.accept_self_signed();
        if accept_self_signed {
            eprintln!(
                "[blakegate] \x1b[1;33m⚠ TLS certificate verification is DISABLED for {url} (selfcert: true)\x1b[0m — never use this against a real production endpoint, only local/internal testing."
            );
        }
        let config = Arc::clone(&config);
        let routes = Arc::clone(&routes);
        tokio::spawn(async move {
            run_client(url, accept_self_signed, config, routes).await;
        });
    }
}

/// One endpoint's connection lifecycle: connect, push on connect and
/// on every generation change, reconnect after `RECONNECT_DELAY` on
/// any error or disconnect. Runs forever — the task this is spawned
/// into only ever ends if the process itself exits.
/// RAII guard bracketing `AppConfig.blakegate_connected` around one
/// live connection's lifetime — incremented on construction,
/// decremented on drop, so it stays accurate even if `drive_connection`
/// returns via an early `?` rather than falling through normally.
struct ConnectedGuard<'a> {
    counter: &'a std::sync::atomic::AtomicUsize,
}

impl<'a> ConnectedGuard<'a> {
    fn new(counter: &'a std::sync::atomic::AtomicUsize) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self { counter }
    }
}

impl Drop for ConnectedGuard<'_> {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn run_client(
    url: String,
    accept_self_signed: bool,
    config: Arc<AppConfig>,
    routes: Arc<RouteConfig>,
) {
    let connector = build_connector(accept_self_signed);
    loop {
        let connect_result =
            tokio_tungstenite::connect_async_tls_with_config(&url, None, false, connector.clone())
                .await;
        match connect_result {
            Ok((stream, _response)) => {
                println!("[blakegate] connected to {url}");
                // Marks this endpoint "up" for as long as the connection
                // holds — see `AppConfig::should_use_database_as_fallback`,
                // which is what actually reacts to this count. Dropped
                // (decrementing) the moment this scope ends, regardless
                // of how `drive_connection` returned.
                let _connected = ConnectedGuard::new(&config.blakegate_connected);
                if let Err(e) = drive_connection(stream, &config, &routes).await {
                    eprintln!("[blakegate] connection to {url} ended: {e}");
                } else {
                    println!("[blakegate] {url} closed the connection");
                }
            }
            Err(e) => {
                eprintln!("[blakegate] failed to connect to {url}: {e}");
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Drives one live connection until it errors or the peer closes it —
/// sends the initial snapshot, then polls `current_generation()` and
/// pushes a fresh one on every change, while also draining (and, for
/// now, just logging) whatever the peer sends back.
async fn drive_connection(
    mut stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    config: &Arc<AppConfig>,
    routes: &Arc<RouteConfig>,
) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    // Always push once immediately on a fresh connection, regardless
    // of generation — the peer has no prior state to diff against.
    stream
        .send(Message::Text(build_snapshot(config, routes).to_string()))
        .await?;
    let mut last_sent_generation = config.current_generation();

    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.tick().await; // first tick fires immediately — consume it, we already just sent

    loop {
        tokio::select! {
            _ = poll.tick() => {
                let current = config.current_generation();
                if current != last_sent_generation {
                    stream
                        .send(Message::Text(build_snapshot(config, routes).to_string()))
                        .await?;
                    last_sent_generation = current;
                }
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(Message::Ping(payload))) => {
                        stream.send(Message::Pong(payload)).await?;
                    }
                    Some(Ok(Message::Text(text))) => {
                        handle_incoming_message(&text, config).await;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e),
                }
            }
        }
    }
}

/// Dispatches one incoming text message from a Blakegate endpoint.
/// Currently recognizes exactly one request: `{"kind": "backup_users"}`
/// — everything else is logged and otherwise ignored, so an
/// unrecognized/future message kind never crashes or blocks the
/// connection. This is the write-back path the module doc comment's
/// connection-model section flagged as a scaffold; `backup_users` is
/// its first real use.
async fn handle_incoming_message(text: &str, config: &Arc<AppConfig>) {
    let parsed: Option<Value> = serde_json::from_str(text).ok();
    let kind = parsed
        .as_ref()
        .and_then(|v| v.get("kind"))
        .and_then(|v| v.as_str());

    match kind {
        Some("backup_users") => backup_users_to_database(config).await,
        Some("users_sync") => apply_users_sync(parsed.as_ref(), config).await,
        Some("routes_sync") => acknowledge_routes_sync(parsed.as_ref()),
        Some("config_sync") => acknowledge_config_sync(parsed.as_ref()),
        _ => {
            println!("[blakegate] received (not acted on): {text}");
        }
    }
}

/// Acknowledges a `{"kind": "routes_sync", "routes": [...]}` push —
/// **recognized, but not yet applied to the live routing table.**
/// Unlike `users_sync`, `AppState.routes` isn't internally mutable
/// today (`Arc<RouteConfig>`, loaded once at startup, read directly by
/// every proxied request in `network::proxy` with no lock in between)
/// — making this genuinely live would mean giving `RouteConfig` the
/// same kind of interior-mutability `AppConfig` already has for
/// users/roles/groups, and updating every one of its read sites
/// accordingly. That's a real, separate piece of work, not something
/// to bolt on silently here. For now this just confirms the message
/// arrived and was well-formed, so the sending side (and whoever's
/// reading these logs) isn't left guessing whether it was silently
/// dropped as unrecognized.
fn acknowledge_routes_sync(parsed: Option<&Value>) {
    let Some(parsed) = parsed else {
        eprintln!("[blakegate] routes_sync: message wasn't valid JSON, ignoring.");
        return;
    };
    let route_count = parsed
        .get("routes")
        .and_then(|v| v.as_array())
        .map(|a| a.len());
    match route_count {
        Some(n) => println!(
            "[blakegate] routes_sync: received {n} route(s) — acknowledged, but NOT applied to the live routing table yet (route hot-reload isn't implemented)."
        ),
        None => {
            eprintln!("[blakegate] routes_sync: message is missing a \"routes\" array, ignoring.")
        }
    }
}

/// Acknowledges a `{"kind": "config_sync", "config": {...}}` push —
/// same status as `acknowledge_routes_sync`: **recognized, logged, not
/// applied.** Most of `AppConfig` (host, port, session/CSRF settings,
/// rate limits, TLS, `secret`, ...) is set once at startup from
/// `config.json` and read directly from then on — no `RwLock`, no
/// reload path, unlike the specific fields (`db_users`, `roles_index`,
/// `groups_index`, ...) that already support being updated live. A
/// handful of these settings (e.g. `port`, `tls`) couldn't safely take
/// effect without rebinding the listener anyway, so "apply this at
/// runtime" isn't a uniform operation even in principle — some fields
/// would need their own individual handling, not a single generic
/// mechanism. That design work hasn't happened yet; this function
/// exists so a `config_sync` push is at least visible and confirmed
/// well-formed in the meantime, rather than silently falling into the
/// generic "not acted on" case.
fn acknowledge_config_sync(parsed: Option<&Value>) {
    let Some(parsed) = parsed else {
        eprintln!("[blakegate] config_sync: message wasn't valid JSON, ignoring.");
        return;
    };
    match parsed.get("config") {
        Some(cfg) => {
            let field_count = cfg.as_object().map(|o| o.len());
            println!(
                "[blakegate] config_sync: received a config object ({} field(s)) — acknowledged, but NOT applied to this instance's live settings yet (config hot-reload isn't implemented).",
                field_count
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".to_string())
            );
        }
        None => {
            eprintln!("[blakegate] config_sync: message is missing a \"config\" object, ignoring.")
        }
    }
}

/// Backup mode: writes every currently known account
/// (`AppConfig::combined_users` — file-based `users` and any
/// database-sourced accounts alike) into the configured `databases`
/// backend, via the exact same `upsert_user` the `db-add-user` CLI
/// command uses.
///
/// Deliberately **only** runs in response to this explicit request —
/// never on a timer, never just because ProxyAuth happens to have
/// accounts in memory. Blakegate decides when a backup is warranted;
/// ProxyAuth doesn't second-guess that by also backing up on its own
/// schedule, which would defeat the point of putting Blakegate in
/// control of the cadence in the first place.
///
/// A no-op (with a log line explaining why) if `databases` isn't
/// configured — there's nowhere to write a backup to in that case,
/// and that's not treated as an error on the connection: a request
/// blakegate sent as a matter of course, before knowing this specific
/// instance has no database configured, shouldn't tear down the
/// websocket connection over it.
async fn backup_users_to_database(config: &Arc<AppConfig>) {
    write_users_to_database(config, config.combined_users(), "backup_users").await;
}

/// Applies a Blakegate `users_sync` push — the message that actually
/// makes "backup mode" real: `{"kind": "users_sync", "users": [...]}`,
/// where `users` is a full, current, authoritative list in the same
/// shape as `config.json`'s own `users` array.
///
/// Two things happen, in order:
/// 1. Applied to this instance's in-memory state
///    (`AppConfig::apply_blakegate_users`) — Blakegate, not the local
///    database, is what's actually keeping memory up to date while at
///    least one connection is up (see
///    `AppConfig::should_use_database_as_fallback`, and the periodic
///    refresh tasks in `main.rs` that check it).
/// 2. Written into the configured `databases` backend, as a backup —
///    so if every Blakegate connection later goes down, this instance
///    (or any other reading from the same database) still has a
///    reasonably fresh, durable copy to fall back on rather than
///    being stuck with nothing.
async fn apply_users_sync(parsed: Option<&Value>, config: &Arc<AppConfig>) {
    let Some(parsed) = parsed else {
        eprintln!("[blakegate] users_sync: message wasn't valid JSON, ignoring.");
        return;
    };

    let users: Vec<crate::config::config::User> = match parsed.get("users").cloned() {
        Some(v) => match serde_json::from_value(v) {
            Ok(users) => users,
            Err(e) => {
                eprintln!("[blakegate] users_sync: couldn't parse the \"users\" field: {e}");
                return;
            }
        },
        None => {
            eprintln!("[blakegate] users_sync: message is missing a \"users\" field, ignoring.");
            return;
        }
    };

    let count = users.len();
    config.apply_blakegate_users(&users);
    println!(
        "[blakegate] users_sync: applied {count} account(s) to memory (Blakegate is now the source of truth for users on this instance)."
    );

    write_users_to_database(config, users, "users_sync backup").await;
}

/// Writes `users` into the configured `databases` backend, via
/// `upsert_user` for each — the shared "actually persist these
/// accounts" step behind both `backup_users_to_database` (backs up
/// whatever's currently in memory, unchanged) and `apply_users_sync`
/// (backs up exactly what was just applied to memory from Blakegate's
/// push). A no-op, logged, if `databases` isn't configured — there's
/// nowhere to write to, and that's not treated as a connection error:
/// a request sent as a matter of course, before Blakegate necessarily
/// knows this instance has no database configured, shouldn't tear
/// down the websocket connection over it.
async fn write_users_to_database(
    config: &Arc<AppConfig>,
    users: Vec<crate::config::config::User>,
    context: &str,
) {
    let Some(db_cfg) = config.databases.clone() else {
        eprintln!(
            "[blakegate] {context}: no `databases` is configured on this instance — nothing to back up to."
        );
        return;
    };

    let count = users.len();

    // Diesel's calls are blocking — spawn_blocking so this doesn't
    // stall the tokio executor thread this connection's task runs on,
    // same reasoning as every other database call in this crate (see
    // e.g. main.rs's periodic refresh/purge tasks).
    let result = tokio::task::spawn_blocking(move || {
        crate::databases::db::with_connection(&db_cfg, |conn| {
            for user in &users {
                crate::databases::db::upsert_user(conn, user)?;
            }
            Ok(())
        })
    })
    .await;

    match result {
        Ok(Ok(())) => {
            println!("[blakegate] {context}: wrote {count} account(s) to the database.");
        }
        Ok(Err(e)) => {
            eprintln!("[blakegate] {context}: failed to write to the database: {e}");
        }
        Err(e) => {
            eprintln!("[blakegate] {context}: the write task panicked: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_https_to_wss() {
        assert_eq!(
            to_websocket_url("https://blakegate-1.example.com"),
            "wss://blakegate-1.example.com"
        );
    }

    #[test]
    fn rewrites_http_to_ws() {
        assert_eq!(
            to_websocket_url("http://internal.local:9000"),
            "ws://internal.local:9000"
        );
    }

    #[test]
    fn leaves_ws_and_wss_untouched() {
        assert_eq!(
            to_websocket_url("wss://already-ws.example.com"),
            "wss://already-ws.example.com"
        );
        assert_eq!(
            to_websocket_url("ws://already-ws.example.com"),
            "ws://already-ws.example.com"
        );
    }

    #[test]
    fn defaults_schemeless_url_to_wss() {
        assert_eq!(
            to_websocket_url("blakegate.example.com"),
            "wss://blakegate.example.com"
        );
    }
}
