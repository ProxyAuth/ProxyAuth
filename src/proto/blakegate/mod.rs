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
//! 4. Reads (and, for now, just logs) any message the endpoint sends
//!    back — a deliberate hook for a future write-back capability
//!    (Blakegate pushing configuration overrides into ProxyAuth's
//!    memory at startup), not implemented yet. Treat incoming
//!    messages as untrusted input if/when that lands: this is a
//!    natural place to add it, not a promise it's safe to wire up
//!    without its own authentication/validation story first.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

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
    for raw_url in &config.blakegate {
        let url = to_websocket_url(raw_url);
        let config = Arc::clone(&config);
        let routes = Arc::clone(&routes);
        tokio::spawn(async move {
            run_client(url, config, routes).await;
        });
    }
}

/// One endpoint's connection lifecycle: connect, push on connect and
/// on every generation change, reconnect after `RECONNECT_DELAY` on
/// any error or disconnect. Runs forever — the task this is spawned
/// into only ever ends if the process itself exits.
async fn run_client(url: String, config: Arc<AppConfig>, routes: Arc<RouteConfig>) {
    loop {
        match tokio_tungstenite::connect_async(&url).await {
            Ok((stream, _response)) => {
                println!("[blakegate] connected to {url}");
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
                        // Scaffold for a future write-back capability —
                        // see the module doc comment. Not applied to
                        // any in-memory state yet, just observed.
                        println!("[blakegate] received (not yet applied): {text}");
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e),
                }
            }
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
        assert_eq!(to_websocket_url("wss://already-ws.example.com"), "wss://already-ws.example.com");
        assert_eq!(to_websocket_url("ws://already-ws.example.com"), "ws://already-ws.example.com");
    }

    #[test]
    fn defaults_schemeless_url_to_wss() {
        assert_eq!(to_websocket_url("blakegate.example.com"), "wss://blakegate.example.com");
    }
}
