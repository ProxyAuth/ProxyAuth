// Copyright 2025 Vladimir Souchet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod acme;
mod adm;
mod build;
mod cli;
mod config;
mod databases;
mod keystore;
mod logs;
mod network;
mod proto;
mod reset;
mod revoke;
mod smtp;
mod start_actix;
mod stats;
mod tls;
mod token;

use crate::adm::registry_otp::{get_otpauth_uri, get_otpauth_uri_option, reset_otp_route};
use crate::adm::revoke::revoke_route;
use crate::adm::stats::{get_proxy_sessions, get_proxy_stats};
use crate::build::build_info::update_build_info;
use crate::cli::prompt::prompt;
use crate::keystore::import::decrypt_keystore;
use crate::network::accesslog::{self, AccessLogger};
use crate::network::compression::Compress;
use crate::network::config::init_loadbalancer;
use crate::network::cors::CorsMiddleware;
use crate::network::proxy::init_routes;
use crate::network::stats::{RequestStats, spawn_stats_ticker};
use crate::revoke::db::{load_revoked_tokens, start_revoked_token_ttl};
use crate::smtp::smtp::SmtpClient;
use crate::smtp::template::ensure_reset_template_exists;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{App, http::Method, web};
use chrono::Local;
use config::config::{AppConfig, AppState, RouteConfig, load_config};
use config::def_config;
use dashmap::DashMap;
use futures_util::future::join_all;
use logs::{ChannelLogWriter, get_logs, log_collector};
use network::proxy::global_proxy;
use network::ratelimit::{RateLimitLogger, UserToken};
use socket2::{Domain, Protocol, Socket, Type};
use start_actix::mode_actix_web;
pub use stats::tokencount::CounterToken;
use std::net::TcpListener;
use std::{fs, process, sync::Arc, time::Duration};
use tls::bind_server;
use token::auth::{auth_dispatch, auth_options};
use token::logout::{logout_dispatch, logout_options};
use token::reset_password::reset_password_route;
use token::vault as token_vault;
use tokio::sync::mpsc::unbounded_channel;
use tracing::info;
use tracing::{error, warn};
use tracing_loki::url::Url;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const ID: &str = env!("id");

struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", Local::now().format("%Y-%m-%d %H:%M:%S %:z"))
    }
}

fn print_launcher(mode: &str, version: &str, worker: u8, addr: &str, id: &str) {
    let msg = match mode {
        "NO_RATELIMIT_AUTH" => "ratelimit On (Proxy)",
        "NO_RATELIMIT_PROXY" => "ratelimit On (Auth)",
        "RATELIMIT_GLOBAL_ON" => "ratelimit On (Proxy, Auth)",
        "RATELIMIT_GLOBAL_OFF" => "ratelimit Off",
        _ => "ratelimit Off (No config)",
    };

    println!(
        "\nlaunch ProxyAuth v{} [{}] \n{}\nstarting service: \"proxyauth-service\" worker: {} listening on {}",
        version, id, msg, worker, addr
    );
}

/// Builds a `"host:port"` string suitable for `SocketAddr::parse`.
///
/// IPv6 literals need bracketing before a port is appended —
/// `"::1:8080"` is not a valid `SocketAddr` (it's ambiguous with the
/// address itself, since a bare IPv6 literal can itself contain many
/// colons); `"[::1]:8080"` is unambiguous. IPv4 addresses and
/// hostnames never contain a literal `:`, so its presence is a
/// reliable signal for which case this is. Doesn't double-wrap if the
/// operator already bracketed it themselves in `config.json`.
fn socket_addr_string(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

async fn create_listener(
    addr: &str,
    send_buf_size: usize,
    recv_buf_size: usize,
    backlog: i32,
) -> std::io::Result<TcpListener> {
    let sock_addr: std::net::SocketAddr = addr.parse().unwrap();
    let domain = if sock_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_send_buffer_size(send_buf_size)?;
    socket.set_recv_buffer_size(recv_buf_size)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(backlog)?;

    Ok(socket.into())
}

/// Handles ACME HTTP-01 challenge requests on plain port 80.
///
/// Let's Encrypt's validation servers always fetch
/// `http://{vhost}/.well-known/acme-challenge/{token}` over plain
/// HTTP on port 80 specifically — this isn't configurable on their
/// end, so a TLS-only deployment (the common case: everything real
/// served over 443, port 80 not listening at all) can never complete
/// a renewal without *something* answering there. Everything else
/// gets redirected to HTTPS, matching what operators generally expect
/// from port 80 anyway on an otherwise HTTPS-only site.
async fn acme_http01_responder(req: actix_web::HttpRequest) -> actix_web::HttpResponse {
    if req.method() == actix_web::http::Method::GET {
        if let Some(token) = crate::acme::challenge::extract_token(req.path()) {
            let host = req.connection_info().host().to_string();
            let vhost = crate::network::proxy::normalize_host(&host);
            return match crate::acme::challenge::lookup(&vhost, token) {
                Some(key_authorization) => actix_web::HttpResponse::Ok()
                    .append_header(("server", "ProxyAuth"))
                    .content_type("application/octet-stream")
                    .body(key_authorization),
                // A genuinely unknown/expired token must be a plain
                // 404 — NOT the HTTPS redirect below. Redirecting a
                // failed challenge lookup just moves the "not found"
                // problem to the main server on 443, where it can get
                // entangled with completely unrelated routing rules
                // (allow_ips, auth, etc.) that were never meant to
                // apply to ACME validation at all — a real bug this
                // comment is here specifically to prevent
                // reintroducing: it once turned a should-be-404 into a
                // confusing 403 from an `allow_ips`-restricted route.
                None => actix_web::HttpResponse::NotFound()
                    .append_header(("server", "ProxyAuth"))
                    .finish(),
            };
        }
    }

    let host = crate::network::proxy::normalize_host(&req.connection_info().host().to_string());
    let location = format!("https://{host}{}", req.uri());
    actix_web::HttpResponse::MovedPermanently()
        .append_header(("server", "ProxyAuth"))
        .append_header(("Location", location))
        .finish()
}

/// Spawns a minimal, plain-HTTP-only server bound to port 80, whose
/// only job is `acme_http01_responder` above — entirely separate from
/// the main server(s) (which may be TLS-only on 443), since actix
/// doesn't support mixing TLS and plain-HTTP listeners within one
/// `HttpServer` instance. Only spawned when at least one route has
/// `certbot_renew: true` and the main server runs with `tls: true` — a
/// plain-HTTP main server already answers ACME challenges itself
/// (see the same check wired into `global_proxy`), so a second
/// listener on the same port would be redundant, and nothing needs
/// this at all if no vhost actually uses automatic renewal.
///
/// Must be called before privileges are dropped — like the main
/// listener(s), binding port 80 needs root (or `CAP_NET_BIND_SERVICE`)
/// on any port below 1024.
async fn spawn_acme_http01_listener(
    config: &AppConfig,
    routes: &RouteConfig,
    server_futures: &mut Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
) {
    if !config.tls {
        return;
    }
    if !routes.routes.iter().any(|r| r.certbot_renew) {
        return;
    }

    for host in config.bind_addresses() {
        let addr = socket_addr_string(&host, 80);
        let listener = match create_listener(&addr, 4096, 4096, 128).await {
            Ok(l) => l,
            Err(e) => {
                error!(
                    "ACME: failed to bind the HTTP-01 challenge listener on {addr}: {e} — automatic renewal will keep failing until port 80 is reachable here"
                );
                continue;
            }
        };

        info!("ACME: HTTP-01 challenge listener bound on {addr}");

        let server = match actix_web::HttpServer::new(|| {
            App::new().default_service(web::to(acme_http01_responder))
        })
        .listen(listener)
        {
            Ok(s) => s.run(),
            Err(e) => {
                error!("ACME: failed to start the HTTP-01 challenge listener on {addr}: {e}");
                continue;
            }
        };

        server_futures.push(tokio::spawn(async move {
            let result = server.await;
            if let Err(ref e) = result {
                error!("ACME HTTP-01 listener terminated with error: {}", e);
            }
            result
        }));
    }
}

async fn wait_for_port(addr: &str, max_retries: u32, delay: Duration) {
    for attempt in 1..=max_retries {
        match create_listener(addr, 4096, 4096, 1).await {
            Ok(_) => {
                return;
            }
            Err(e) => {
                warn!(
                    "Port {} not yet available (attempt {}/{}): {}. Retrying in {}s...",
                    addr,
                    attempt,
                    max_retries,
                    e,
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
    eprintln!(
        "Port {} still unavailable after {} retries. Aborting.",
        addr, max_retries
    );
    process::exit(1);
}

macro_rules! build_app {
    ($state:expr) => {{
        let state = $state.clone();
        App::new()
            .app_data(state.clone())
            .app_data(web::PayloadConfig::new(state.config.max_body_size))
            .wrap(RateLimitLogger)
            .wrap(CorsMiddleware {
                config: state.clone(),
            })
            // Ordering is deliberate. Actix runs `wrap`s in reverse
            // registration order, so the last one registered is the
            // outermost. AccessLogger must be outermost to observe the
            // final status of *every* request — including 429s
            // synthesized by actix-governor, responses produced by the
            // CORS middleware, and errors converted by actix itself,
            // none of which ever reach a handler. Compress sits just
            // inside it, which means `[length]` logs the number of
            // bytes actually put on the wire (compressed), matching
            // nginx's `$body_bytes_sent` rather than the pre-encoding
            // size.
            .wrap(Compress {
                state: state.clone(),
            })
            .wrap(AccessLogger {
                state: state.clone(),
            })
            // `/auth`, `/reset-password` et `/adm/auth/totp/get` ne sont
            // PAS enregistres ici: ce sont les trois seules ressources que
            // les branches de `mode_actix` enveloppent d'un rate limiter,
            // et actix retient la premiere route declaree pour un chemin
            // donne. Les declarer ici aussi faisait gagner la version sans
            // limiteur, et celle des branches n'etait jamais atteinte —
            // `/auth` acceptait donc autant de tentatives de mot de passe
            // qu'on lui en envoyait, quelle que soit la configuration.
            //
            // Chaque branche les declare desormais exactement une fois,
            // via `auth_routes!` pour la version non limitee.
            .service(web::resource("/adm/stats").route(web::get().to(get_proxy_stats)))
            .service(web::resource("/adm/stats/sessions").route(web::get().to(get_proxy_sessions)))
            .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
            .service(web::resource("/adm/revoke").route(web::post().to(revoke_route)))
            .service(web::resource("/adm/auth/totp/reset").route(web::post().to(reset_otp_route)))
            .service(
                web::resource("/logout")
                    .route(web::get().to(logout_dispatch))
                    .route(web::method(Method::OPTIONS).to(logout_options)),
            )
    }};
}

/// Les trois ressources sensibles, sans rate limiter — pour les modes ou
/// `ratelimit_auth` est desactive. Les modes qui l'activent les declarent
/// eux-memes avec `.wrap(Governor::new(...))` sur chaque route.
macro_rules! auth_routes {
    ($app:expr) => {{
        $app.service(
            web::resource("/auth")
                .route(web::post().to(auth_dispatch))
                .route(web::method(Method::OPTIONS).to(auth_options)),
        )
        .service(web::resource("/reset-password").route(web::post().to(reset_password_route)))
        .service(
            web::resource("/adm/auth/totp/get")
                .route(web::post().to(get_otpauth_uri))
                .route(web::method(Method::OPTIONS).to(get_otpauth_uri_option)),
        )
    }};
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    if let Err(e) = prompt().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Root is needed for two things only: binding a listen socket on a
    // privileged port (<1024, e.g. 443) and reading TLS certificate
    // files that aren't readable by an unprivileged account (certbot's
    // /etc/letsencrypt/live/*/privkey.pem is root-only by default).
    // Both happen inside the instance loop below (`create_listener` /
    // `bind_server`) — everything from here down to that loop, and the
    // loop itself, still runs as whatever user started the process
    // (root, typically, when installed as a system service). The drop
    // to the configured run_user happens right after the loop, once
    // every socket is bound and every certificate is loaded — nginx
    // uses the same "bind/read privileged resources first, drop
    // privileges before serving a single request" pattern, just via
    // its master-then-fork model instead of ProxyAuth's single
    // process. Nothing here should process untrusted network input
    // before that point.
    //
    // Fail fast, with a clear explanation, if this process can't
    // actually pull that off — instead of letting the real cause
    // surface many steps later as a bare OS "Permission denied" on
    // whatever privileged operation happens to run first (which looks
    // identical to, say, a typo'd path, and gives zero indication the
    // real issue is "this process isn't root").
    let (peeked_run_user, _peeked_run_group) = def_config::peek_run_user_group();
    def_config::ensure_can_become(&peeked_run_user);

    // create default config files on first run (never overwrites an existing file)
    def_config::create_default_file(
        "/etc/proxyauth/config/config.json",
        def_config::DEFAULT_CONFIG_JSON,
    )
    .expect("Could not create default config/config.json");

    def_config::create_default_file(
        "/etc/proxyauth/config/routes.yml",
        def_config::DEFAULT_ROUTES_YML,
    )
    .expect("Could not create default config/routes.yml");

    let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

    // Periodically re-scan `databases` (if configured) so users added or
    // edited directly in the database eventually take effect without a
    // restart. Two independent timers:
    //   - incremental (refresh_interval_secs, default 30s): cheap,
    //     indexed query scoped to the last incremental_window_secs
    //     (default 5min) — picks up new/edited users quickly even with
    //     a large user base, since its cost scales with recent changes,
    //     not total row count.
    //   - full (full_refresh_interval_secs, default 5min): reads the
    //     whole table — the only way to detect a user hard-deleted from
    //     the database, since a time-window filter can never see a row
    //     that no longer exists.
    // Either can be set to 0 to disable it independently.
    //
    // Both loops below additionally skip themselves entirely while
    // Blakegate backup mode is active and connected (see
    // `AppConfig::should_use_database_as_fallback`) — Blakegate, not
    // this periodic refresh, is what's keeping memory current in that
    // case; the database is a write-only backup target instead (see
    // `proto::blakegate::apply_users_sync`). Note this does NOT cover
    // `load_config`'s own initial synchronous load at startup, further
    // up in this function — that one always runs regardless, as a
    // cold-start bootstrap giving this instance *something* to
    // authenticate against in the brief window before its first
    // Blakegate connection is established. Any stale data from that
    // initial load is superseded the moment the first `users_sync`
    // arrives, via the same revocation mechanism a full database
    // reload already uses for accounts no longer present.
    //
    // Both refresh_db_users*() calls below are synchronous/blocking
    // (Diesel isn't async) — a database that's unreachable can take a
    // long time to fail a TCP connection attempt (tens of seconds, if
    // packets are silently dropped rather than actively refused).
    // Running that directly inside a plain tokio::spawn ties up a
    // tokio worker thread for the whole duration; on a small instance
    // with few worker threads, that can starve the runtime enough that
    // graceful shutdown (SIGTERM handling) has no thread left to run
    // on until the blocking call eventually times out on its own.
    // spawn_blocking runs it on tokio's separate blocking-thread pool
    // instead, so a stuck database connection never holds up shutdown.
    if let Some(db_cfg) = &config.databases {
        if db_cfg.refresh_interval_secs > 0 {
            let refresh_config = Arc::clone(&config);
            let interval_secs = db_cfg.refresh_interval_secs;
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                // First tick fires immediately; skip it since load_config
                // already did an initial (full) load.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    // Blakegate backup mode active (`blakegate` configured)
                    // AND at least one connection currently up -> Blakegate
                    // is supplying user data right now, so the database
                    // must not also sync into memory on top of that. See
                    // `AppConfig::should_use_database_as_fallback`.
                    if !refresh_config.should_use_database_as_fallback() {
                        continue;
                    }
                    let refresh_config = Arc::clone(&refresh_config);
                    let _ = tokio::task::spawn_blocking(move || {
                        refresh_config.refresh_db_users_incremental();
                    })
                    .await;
                }
            });
        }

        if db_cfg.full_refresh_interval_secs > 0 {
            let refresh_config = Arc::clone(&config);
            let interval_secs = db_cfg.full_refresh_interval_secs;
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    // Same reasoning as the incremental refresh above.
                    if !refresh_config.should_use_database_as_fallback() {
                        continue;
                    }
                    let refresh_config = Arc::clone(&refresh_config);
                    let _ = tokio::task::spawn_blocking(move || {
                        refresh_config.refresh_db_users();
                    })
                    .await;
                }
            });
        }

        // Periodically hard-delete users that were soft-deleted
        // (`db-delete-user`) more than deleted_retention_secs ago.
        // Safe to enable on every instance — a second, redundant purge
        // just deletes zero rows. Same spawn_blocking reasoning as
        // above — purge_*_in_config are blocking Diesel calls too.
        if db_cfg.purge_interval_secs > 0 {
            let purge_config = Arc::clone(&config);
            let interval_secs = db_cfg.purge_interval_secs;
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let purge_config = Arc::clone(&purge_config);
                    let _ = tokio::task::spawn_blocking(move || {
                        let Some(db_cfg) = &purge_config.databases else {
                            return;
                        };
                        let n = crate::databases::db::purge_deleted_users_in_config(
                            db_cfg,
                            db_cfg.deleted_retention_secs,
                        );
                        if n > 0 {
                            println!("[databases] purged {n} soft-deleted user(s)");
                        }

                        let n_log = crate::databases::db::purge_deletion_log_in_config(
                            db_cfg,
                            db_cfg.deleted_retention_secs,
                        );
                        if n_log > 0 {
                            println!("[databases] purged {n_log} deletion log entr(y/ies)");
                        }
                    })
                    .await;
                }
            });
        }
    }

    // Password-reset tokens (`reset::db`, its own local LMDB store)
    // don't depend on `databases` at all — they're used for file-based
    // users too — so this purge runs unconditionally, unlike the
    // database-specific tasks above. Hourly by default is plenty for
    // something that's just cleaning up expired single-use tokens.
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let _ = tokio::task::spawn_blocking(|| match reset::db::purge_expired() {
                Ok(n) if n > 0 => println!("[reset] purged {n} expired password-reset token(s)"),
                Ok(_) => {}
                Err(e) => eprintln!("[reset] failed to purge expired tokens: {e}"),
            })
            .await;
        }
    });

    init_loadbalancer(&config);

    let routes_str =
        fs::read_to_string("/etc/proxyauth/config/routes.yml").expect("cannot read routes");

    if let Err(e) = config::config::check_deprecated_secure_key(&routes_str) {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    let routes_parsed: RouteConfig =
        serde_yaml::from_str(&routes_str).expect("Failed to parse routes.yml");
    let mut routes: RouteConfig = routes_parsed.expand_vhost_groups();

    let counter_token = Arc::new(CounterToken::new());

    // ── Stats ────────────────────────────────────────────────
    let stats = RequestStats::new();
    spawn_stats_ticker(stats.clone());

    // ── remove periodic CounterToken ────────────────────
    {
        let counter_clone = Arc::clone(&counter_token);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 min
            loop {
                tick.tick().await;
                let removed = counter_clone.purge_expired();
                if removed > 0 {
                    tracing::info!("purged {} expired tokens", removed);
                }
            }
        });
    }

    let revoked_tokens = match load_revoked_tokens() {
        Ok(tokens) => tokens,
        Err(e) => {
            error!(
                "Failed to load revoked token database: {}. Using empty token map.",
                e
            );
            Arc::new(DashMap::new())
        }
    };

    start_revoked_token_ttl(
        revoked_tokens.clone(),
        std::time::Duration::from_secs(15),
        config.redis.clone(),
    )
    .await;

    init_routes(&mut routes.routes);
    let routes = Arc::new(routes);

    // Pushes the in-memory config/routes state to every configured
    // `blakegate` endpoint over WebSocket, near real-time — entirely
    // decoupled from request handling below; see `blakegate`'s module
    // doc comment for exactly what's sent (redacted) and the
    // reconnect/polling model.
    proto::blakegate::spawn_clients(Arc::clone(&config), Arc::clone(&routes));

    // Periodic Let's Encrypt renewal check for every `certbot_renew:
    // true` vhost — see acme::spawn_periodic_scan's doc comment. A
    // fresh Arc<Vec<RouteRule>> rather than passing `routes` (the
    // Arc<RouteConfig> wrapper) directly, so this module only depends
    // on the specific piece it actually needs.
    crate::acme::spawn_periodic_scan(Arc::new(routes.routes.clone()), config.acme.clone());

    let ip_blocklist: Arc<arc_swap::ArcSwap<Vec<ipnet::IpNet>>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
    if !config.ip_blocklists.is_empty() {
        let bl_config = Arc::clone(&config);
        let bl_store = Arc::clone(&ip_blocklist);
        tokio::spawn(async move {
            let fresh = crate::network::ipblocklist::refresh_all(&bl_config).await;
            println!(
                "[ip_blocklist] loaded {} entr(y/ies) from {} source(s)",
                fresh.len(),
                bl_config.ip_blocklists.len()
            );
            bl_store.store(Arc::new(fresh));

            if bl_config.ip_blocklist_refresh_interval_secs == 0 {
                return;
            }
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                bl_config.ip_blocklist_refresh_interval_secs,
            ));
            ticker.tick().await; // initial load above already covered the first fetch
            loop {
                ticker.tick().await;
                let fresh = crate::network::ipblocklist::refresh_all(&bl_config).await;
                println!("[ip_blocklist] refreshed: {} entr(y/ies)", fresh.len());
                bl_store.store(Arc::new(fresh));
            }
        });
    }

    let redirect_protect_url_ips: Arc<DashMap<String, (Vec<ipnet::IpNet>, Vec<ipnet::IpNet>)>> =
        Arc::new(DashMap::new());
    let any_redirect_protect_urls = routes.routes.iter().any(|r| {
        r.redirect_protect
            .as_ref()
            .is_some_and(|rp| rp.allow_url_ips.is_some() || rp.deny_url_ips.is_some())
    });
    if any_redirect_protect_urls {
        let rp_config = Arc::clone(&config);
        let rp_routes = Arc::clone(&routes);
        let rp_store = Arc::clone(&redirect_protect_url_ips);
        tokio::spawn(async move {
            network::ipblocklist::refresh_redirect_protect_urls(&rp_routes.routes, &rp_store).await;
            println!(
                "[redirect_protect] loaded url-fetched allow/deny lists for {} route(s)",
                rp_store.len()
            );

            if rp_config.redirect_protect_refresh_interval_secs == 0 {
                return;
            }
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                rp_config.redirect_protect_refresh_interval_secs,
            ));
            ticker.tick().await; // initial load above already covered the first fetch
            loop {
                ticker.tick().await;
                network::ipblocklist::refresh_redirect_protect_urls(&rp_routes.routes, &rp_store)
                    .await;
                println!(
                    "[redirect_protect] refreshed url-fetched allow/deny lists for {} route(s)",
                    rp_store.len()
                );
            }
        });
    }

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::clone(&routes),
        counter: counter_token,
        revoked_tokens,
        stats,
        ip_blocklist,
        redirect_protect_url_ips,
        otp_overrides: Arc::new(DashMap::new()),
        password_overrides: Arc::new(DashMap::new()),
        must_change_overrides: Arc::new(DashMap::new()),
    });

    // Local-only Unix socket for `proxyauth stats` to read live stats
    // directly, without an HTTPS round-trip or the admin token —
    // RequestStats/CounterToken are in-process memory with no other
    // way for the separate, short-lived CLI process to reach them.
    // Bound here, while still root (matching the ACME port-80
    // listener's own reasoning) so it can chown the socket to
    // run_user before the privilege drop further down.
    {
        let stats_clone = Arc::clone(&state.stats);
        let counter_clone = Arc::clone(&state.counter);
        let run_user = config.effective_run_user().to_string();
        let run_group = config.effective_run_group().map(str::to_string);
        tokio::spawn(async move {
            let socket_path = std::path::Path::new(network::stats::STATS_SOCKET_PATH);
            if let Err(e) = network::stats::spawn_stats_socket(
                stats_clone,
                counter_clone,
                socket_path,
                &run_user,
                run_group.as_deref(),
            )
            .await
            {
                error!("stats socket ({}) stopped: {e}", socket_path.display());
            }
        });
    }

    // Builds the process-wide token vault from the operator secret and
    // the build constants. Must happen before any request is served: a
    // missing vault is a startup-ordering bug, and failing here beats
    // discovering it on the first login.
    if let Err(e) = token_vault::init(&config) {
        eprintln!("fatal: cannot initialise the token vault: {e}");
        std::process::exit(1);
    }

    // logs
    fn init_logging(config: &AppConfig) {
        let logs = config
            .log
            .get("type")
            .map(|v| v.trim_matches('"'))
            .unwrap_or("local");

        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("proxyauth=trace"))
            .add_directive("actix_web=warn".parse().unwrap())
            .add_directive("actix_server=warn".parse().unwrap());

        let base_registry = Registry::default().with(env_filter);

        match logs {
            "loki" => {
                let host = config.log.get("host").expect("Missing Loki host config");
                let url = Url::parse(host).expect("Invalid Loki URL");

                let (loki_layer, task) = tracing_loki::builder()
                    .label("app", "proxyauth")
                    .expect("builder failed")
                    .extra_field("pid", format!("{}", process::id()))
                    .expect("extra_field failed")
                    .build_url(url)
                    .expect("build_url failed");

                let loki_filter = tracing_subscriber::filter::filter_fn(|meta| {
                    meta.target().starts_with("proxyauth")
                });

                let fmt_layer = fmt::Layer::new()
                    .with_timer(LocalTime)
                    .with_filter(loki_filter);

                base_registry
                    .with(loki_layer.with_filter(LevelFilter::INFO))
                    .with(fmt_layer)
                    .init();

                tokio::spawn(task);
            }

            "http" => {
                let (tx, rx) = unbounded_channel::<String>();

                let max_logs = config
                    .log
                    .get("write_max_logs")
                    .and_then(|v| v.parse::<usize>().ok())
                    .expect("Invalid write_max_logs");

                if max_logs >= 100_000 {
                    eprintln!("write_max_logs must be < 100000");
                    process::exit(1);
                }

                let fmt_layer =
                    fmt::Layer::new()
                        .with_timer(LocalTime)
                        .with_writer(ChannelLogWriter {
                            sender: tx.clone().into(),
                        });

                base_registry.with(fmt_layer).init();

                tokio::spawn(log_collector(rx, max_logs));
            }

            "disabled" => {}

            _ => {
                // "local" (the default): writes directly to
                // /var/log/proxyauth/proxyauth.log via
                // `logs::ProxyAuthFileMakeWriter`, rather than the
                // implicit stdout default — so where these lines end
                // up doesn't depend on how the process happens to be
                // launched (an init script redirecting stdout, or not).
                //
                // Excludes the access-log target: those lines already
                // have their own destination (`access.log`, or a
                // per-vhost/route override) written directly by
                // `network::accesslog::VhostLogWriter` — without this
                // filter they'd *also* land here via the same
                // `info!(target: "proxyauth::access", ...)` call,
                // duplicating every request into both files instead of
                // keeping "requests" and "everything else" separate,
                // as intended.
                let local_filter = tracing_subscriber::filter::filter_fn(|meta| {
                    meta.target() != "proxyauth::access"
                });

                let fmt_layer = fmt::Layer::new()
                    .with_timer(LocalTime)
                    .with_writer(crate::logs::ProxyAuthFileMakeWriter)
                    .with_filter(local_filter);

                base_registry.with(fmt_layer).init();

                tokio::spawn(crate::logs::spawn_proxyauth_log_flusher(
                    config.logging.flush_interval_ms,
                ));
            }
        }
    }

    init_logging(&config);

    // Compiles the access-log format once, and starts the /proc
    // sampler only if that format actually uses [cpu-usage] or
    // [memory-usage]. Must run after init_logging so the tracing
    // subscriber the access log writes through already exists.
    accesslog::init(&config);

    // OIDC provider signing key — only generated/loaded if at least
    // one vhost actually declares `oidc:`. Skipping this entirely for
    // instances that don't use the feature avoids creating
    // /etc/proxyauth/oidc and a signing key nothing will ever read.
    if routes.routes.iter().any(|r| r.oidc.is_some()) {
        proto::oidc_provider::jwt::init_signing_key()
            .map_err(|e| format!("Failed to initialize OIDC provider signing key: {e}"))?;
    }

    // load SMTP template if smtp use
    if let Some(smtp_cfg) = &config.smtp {
        ensure_reset_template_exists()?;
        SmtpClient::new(smtp_cfg)?;
    } else {
        println!("SMTP not configured, skipping email setup.");
    }

    // check keystore if exist
    match decrypt_keystore(None) {
        Ok(Some(message)) => {
            let _ = update_build_info(&message);
            println!("Load keystore successfull from /etc/proxyauth/import/data.gpg");
        }
        Ok(None) => {}
        Err(err) => warn!("Failed to decrypt keystore: {:?}", err),
    }

    // configuration proxy ratelimit
    let requests_per_second_proxy_config = config
        .ratelimit_proxy
        .get("requests_per_second")
        .copied()
        .unwrap_or(0);

    let burst_proxy_config = config
        .ratelimit_proxy
        .get("burst")
        .copied()
        .unwrap_or(0)
        .try_into()
        .expect("bad burst_proxy value");

    // configuration auth ratelimit
    let requests_per_second_auth_config = config
        .ratelimit_auth
        .get("requests_per_second")
        .copied()
        .unwrap_or(0);

    let burst_auth_config = config
        .ratelimit_auth
        .get("burst")
        .copied()
        .unwrap_or(0)
        .try_into()
        .expect("bad burst_auth value");

    let mode_actix = mode_actix_web(
        &requests_per_second_auth_config,
        &requests_per_second_proxy_config,
    );

    // One or more bind addresses (e.g. IPv4 + IPv6 together via
    // `host: [...]` in config.json) — see AppConfig::bind_addresses.
    let bind_addrs = config.bind_addresses();
    let addrs: Vec<String> = bind_addrs
        .iter()
        .map(|h| socket_addr_string(h, config.port))
        .collect();

    for a in &addrs {
        wait_for_port(a, 5, Duration::from_secs(2)).await;
    }

    let num_instances = config.num_instances;

    // Les compteurs de rate limiting sont construits ici, une seule
    // fois, et partages par toutes les instances ci-dessous.
    //
    // `num_instances` ne cree PAS de processus : ce sont N serveurs
    // actix dans le meme espace d'adressage, chacun avec sa propre
    // boucle d'accept via SO_REUSEPORT (voir le join_all en fin de
    // fonction). Construire le GovernorConfig a l'interieur de la
    // boucle donnait donc a chaque instance son propre seau, et le
    // burst reellement applique valait `burst * num_instances` — avec
    // le defaut de 2, exactement le double de ce que config.json
    // annonce, ce qu'un test de charge mesurait comme "rate limit non
    // applique".
    //
    // Passe par un Arc plutot qu'un clone: `Governor::new` prend une
    // reference, et l'Arc garantit que les N fermetures partagent le
    // meme etat sans dependre de l'implementation de Clone sur
    // GovernorConfig.
    //
    // `requests_per_second: 0` desactive le limiteur concerne, et
    // `None` est la facon de le representer ici: aucun compteur n'est
    // construit, et le bras de `mode_actix` correspondant n'enveloppe
    // rien. Une valeur de repli (0 ramene a 1) transformerait
    // "desactive" en "la limite la plus stricte possible", ce qui est
    // l'inverse de ce que la configuration demande.
    //
    // Un `burst` de 0 alors que le limiteur est actif est un cas
    // different: `GovernorConfigBuilder::finish()` renvoie None pour un
    // burst nul, donc la valeur est ramenee a 1 — la plus stricte
    // representable — et signalee, plutot que de paniquer au demarrage.
    fn build_governor_period(requests_per_second: u64) -> Duration {
        Duration::from_secs_f64(1.0 / requests_per_second as f64)
    }

    fn usable_burst(burst: u32, which: &str) -> u32 {
        if burst == 0 {
            warn!(
                "ratelimit_{which}: `burst` is 0 while `requests_per_second` is not — a burst of 0 is not representable, using 1. Set `requests_per_second` to 0 to disable this rate limit entirely."
            );
            1
        } else {
            burst
        }
    }

    let governor_auth_conf = (requests_per_second_auth_config > 0).then(|| {
        std::sync::Arc::new(
            GovernorConfigBuilder::default()
                .burst_size(usable_burst(burst_auth_config, "auth"))
                .use_headers()
                .period(build_governor_period(requests_per_second_auth_config))
                .finish()
                .unwrap(),
        )
    });

    let governor_proxy_conf = (requests_per_second_proxy_config > 0).then(|| {
        std::sync::Arc::new(
            GovernorConfigBuilder::default()
                .burst_size(usable_burst(burst_proxy_config, "proxy"))
                .key_extractor(UserToken)
                .period(build_governor_period(requests_per_second_proxy_config))
                .finish()
                .unwrap(),
        )
    });

    let mut server_futures = Vec::new();

    print_launcher(mode_actix, VERSION, config.worker, &addrs.join(", "), ID);

    for _instance_id in 0..num_instances {
        let mut listener = Vec::with_capacity(addrs.len());
        for a in &addrs {
            listener.push(
                create_listener(
                    a,
                    64 * 1024,
                    64 * 1024,
                    config.socket_listen.try_into().unwrap(),
                )
                .await?,
            );
        }

        let state_cloned = state.clone();

        let server = match mode_actix.as_ref() {
            "NO_RATELIMIT_AUTH" => {
                // Clone d'Arc : meme compteur, pas un second seau.
                let governor_proxy_conf = governor_proxy_conf
                    .clone()
                    .expect("NO_RATELIMIT_AUTH implies ratelimit_proxy is enabled");

                bind_server(
                    move || {
                        auth_routes!(build_app!(state_cloned)).default_service(
                            web::to(global_proxy).wrap(Governor::new(&governor_proxy_conf)),
                        )
                    },
                    listener,
                    &config,
                    &routes.routes,
                )?
            }

            "NO_RATELIMIT_PROXY" => {
                let governor_auth_conf = governor_auth_conf
                    .clone()
                    .expect("NO_RATELIMIT_PROXY implies ratelimit_auth is enabled");

                bind_server(
                    move || {
                        build_app!(state_cloned)
                            .service(
                                web::resource("/auth")
                                    .route(
                                        web::post()
                                            .to(auth_dispatch)
                                            .wrap(Governor::new(&governor_auth_conf)),
                                    )
                                    .route(web::method(Method::OPTIONS).to(auth_options)),
                            )
                            .service(
                                web::resource("/reset-password").route(
                                    web::post()
                                        .to(reset_password_route)
                                        .wrap(Governor::new(&governor_auth_conf)),
                                ),
                            )
                            .service(
                                web::resource("/adm/auth/totp/get")
                                    .route(
                                        web::post()
                                            .to(get_otpauth_uri)
                                            .wrap(Governor::new(&governor_auth_conf)),
                                    )
                                    .route(web::method(Method::OPTIONS).to(get_otpauth_uri_option)),
                            )
                            .default_service(web::to(global_proxy))
                    },
                    listener,
                    &config,
                    &routes.routes,
                )?
            }

            // RATELIMIT_GLOBAL_OFF ne figure volontairement plus ici:
            // les deux limites sont a 0, donc rien ne doit etre
            // enveloppe. Ce mode tombe sur le bras `_` plus bas, qui
            // construit l'application sans aucun governor.
            "RATELIMIT_GLOBAL_ON" => {
                // `expect`: ce mode signifie exactement "les deux
                // limites sont actives", donc les deux Option sont Some
                // par construction (voir mode_actix_web).
                let governor_auth_conf = governor_auth_conf
                    .clone()
                    .expect("RATELIMIT_GLOBAL_ON implies ratelimit_auth is enabled");
                let governor_proxy_conf = governor_proxy_conf
                    .clone()
                    .expect("RATELIMIT_GLOBAL_ON implies ratelimit_proxy is enabled");

                bind_server(
                    move || {
                        build_app!(state_cloned)
                            .service(
                                web::resource("/auth")
                                    .route(
                                        web::post()
                                            .to(auth_dispatch)
                                            .wrap(Governor::new(&governor_auth_conf)),
                                    )
                                    .route(web::method(Method::OPTIONS).to(auth_options)),
                            )
                            .service(
                                web::resource("/reset-password").route(
                                    web::post()
                                        .to(reset_password_route)
                                        .wrap(Governor::new(&governor_auth_conf)),
                                ),
                            )
                            .service(
                                web::resource("/adm/auth/totp/get")
                                    .route(
                                        web::post()
                                            .to(get_otpauth_uri)
                                            .wrap(Governor::new(&governor_auth_conf)),
                                    )
                                    .route(web::method(Method::OPTIONS).to(get_otpauth_uri_option)),
                            )
                            .default_service(
                                web::to(global_proxy).wrap(Governor::new(&governor_proxy_conf)),
                            )
                    },
                    listener,
                    &config,
                    &routes.routes,
                )?
            }

            _ => bind_server(
                move || {
                    auth_routes!(build_app!(state_cloned)).default_service(web::to(global_proxy))
                },
                listener,
                &config,
                &routes.routes,
            )?,
        };

        server_futures.push(tokio::spawn(async move {
            let result = server.await;
            if let Err(ref e) = result {
                error!("Server instance terminated with error: {}", e);
            }
            result
        }));
    }

    // Bound before privileges are dropped below — port 80 needs root,
    // same reasoning as the main listener(s) above. A no-op (returns
    // immediately) unless tls: true and at least one route has
    // certbot_renew: true.
    spawn_acme_http01_listener(&config, &routes, &mut server_futures).await;

    // Every listener is bound and every TLS certificate (default +
    // per-vhost) is already loaded into the running server instances
    // above — nothing left needs root. Fix up ownership of anything
    // that might have just been created while still root (fresh
    // config.json/routes.yml/certs on a true first run), then drop to
    // the configured `run_user`/`run_group` (defaults to
    // `proxyauth`/its own group; set to e.g. `www-data` in
    // config.json to inherit that account's read access to files
    // instead of changing those files' permissions) before falling
    // into the loop below that actually waits on (and, via the
    // spawned tasks above, processes) real client connections.
    // `setuid`/`setgid` change credentials for the whole process
    // (every tokio worker thread), not just this one, so this covers
    // every request handled from this point on.
    def_config::reassert_ownership(config.effective_run_user(), config.effective_run_group());
    let _ = def_config::switch_to_user_and_group(
        config.effective_run_user(),
        config.effective_run_group(),
    );
    def_config::ensure_running_as(config.effective_run_user());

    let results = join_all(server_futures).await;
    for r in results {
        match r {
            Ok(Err(e)) => error!("Server exited with error: {}", e),
            Err(e) => error!("Server task panicked: {}", e),
            Ok(Ok(())) => {}
        }
    }

    // Every server future above has resolved — actix's own graceful
    // shutdown (built in, triggered by SIGTERM/SIGINT) already drained
    // in-flight requests by this point. One last flush so any
    // per-vhost/route log line written just before exit isn't left
    // sitting in a BufWriter that's about to be dropped without ever
    // reaching disk.
    accesslog::flush_vhost_writers();
    logs::flush_proxyauth_log();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn print_launcher_variants_do_not_panic() {
        let modes = [
            "NO_RATELIMIT_AUTH",
            "NO_RATELIMIT_PROXY",
            "RATELIMIT_GLOBAL_ON",
            "RATELIMIT_GLOBAL_OFF",
            "UNKNOWN_MODE",
        ];
        for m in modes {
            print_launcher(m, "0.0.0-test", 4, "127.0.0.1:1234", ID);
        }
    }

    #[tokio::test]
    async fn create_listener_ipv4_accepts_connection() {
        let listener = create_listener("127.0.0.1:0", 64 * 1024, 64 * 1024, 128)
            .await
            .expect("failed to create IPv4 listener");

        let addr = listener.local_addr().expect("no local addr");
        assert_ne!(addr.port(), 0, "port should be assigned");

        let t = thread::spawn(move || {
            let (_sock, _peer) = listener.accept().expect("accept failed");
        });

        thread::sleep(Duration::from_millis(50));

        let _stream = TcpStream::connect(addr).expect("connect failed");

        t.join().expect("accept thread panicked");
    }

    #[tokio::test]
    async fn create_listener_ipv6_accepts_connection_if_available() {
        match create_listener("[::1]:0", 64 * 1024, 64 * 1024, 128).await {
            Ok(listener) => {
                let addr = listener.local_addr().expect("no local addr (v6)");
                assert_ne!(addr.port(), 0, "port should be assigned (v6)");

                let t = thread::spawn(move || {
                    let _ = listener.accept();
                });

                thread::sleep(Duration::from_millis(50));

                let _ = TcpStream::connect(addr);
                let _ = t.join();
            }
            Err(_e) => {}
        }
    }

    #[tokio::test]
    async fn wait_for_port_succeeds_on_free_port() {
        wait_for_port("127.0.0.1:0", 3, Duration::from_millis(100)).await;
    }
}
