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
use config::def_config::{ensure_running_as_proxyauth, switch_to_user};
use dashmap::DashMap;
use futures_util::future::join_all;
use logs::{ChannelLogWriter, get_logs, log_collector};
use network::proxy::global_proxy;
use network::ratelimit::{RateLimitLogger, UserToken};
use network::shared_client::{
    ClientOptions, build_hyper_client_cert, build_hyper_client_normal, build_hyper_client_proxy,
};
use socket2::{Domain, Protocol, Socket, Type};
use start_actix::mode_actix_web;
pub use stats::tokencount::CounterToken;
use std::net::TcpListener;
use std::{fs, process, sync::Arc, time::Duration};
use tls::bind_server;
use token::auth::{auth, auth_options};
use token::logout::{logout_options, logout_session};
use token::reset_password::reset_password_route;
use token::security::init_derived_key;
use tokio::sync::mpsc::unbounded_channel;
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
            .service(
                web::resource("/auth")
                    .route(web::post().to(auth))
                    .route(web::method(Method::OPTIONS).to(auth_options)),
            )
            .service(web::resource("/reset-password").route(web::post().to(reset_password_route)))
            .service(web::resource("/adm/stats").route(web::get().to(get_proxy_stats)))
            .service(web::resource("/adm/stats/sessions").route(web::get().to(get_proxy_sessions)))
            .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
            .service(web::resource("/adm/revoke").route(web::post().to(revoke_route)))
            .service(web::resource("/adm/auth/totp/reset").route(web::post().to(reset_otp_route)))
            .service(
                web::resource("/logout")
                    .route(web::get().to(logout_session))
                    .route(web::method(Method::OPTIONS).to(logout_options)),
            )
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

    // launch as user proxyauth
    let _ = switch_to_user("proxyauth");

    // detect if program is running proxyauth user
    ensure_running_as_proxyauth();

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

    let mut routes: RouteConfig =
        serde_yaml::from_str(&routes_str).expect("Failed to parse routes.yml");

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

    let client_normal = build_hyper_client_normal(&config);
    let client_with_cert = build_hyper_client_cert(
        ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: false,
            cert_path: None,
            key_path: None,
        },
        &config,
    );

    let client_with_proxy = build_hyper_client_proxy(
        ClientOptions {
            use_proxy: true,
            proxy_addr: Some("http://127.0.0.1:8888".to_string()),
            use_cert: false,
            cert_path: None,
            key_path: None,
        },
        &config,
    );

    init_routes(&mut routes.routes);
    let routes = Arc::new(routes);

    // Pushes the in-memory config/routes state to every configured
    // `blakegate` endpoint over WebSocket, near real-time — entirely
    // decoupled from request handling below; see `blakegate`'s module
    // doc comment for exactly what's sent (redacted) and the
    // reconnect/polling model.
    proto::blakegate::spawn_clients(Arc::clone(&config), Arc::clone(&routes));

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::clone(&routes),
        counter: counter_token,
        client_normal,
        client_with_cert,
        client_with_proxy,
        revoked_tokens,
        stats,
        otp_overrides: Arc::new(DashMap::new()),
        password_overrides: Arc::new(DashMap::new()),
        must_change_overrides: Arc::new(DashMap::new()),
    });

    init_derived_key(&config.secret);

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
                let fmt_layer = fmt::Layer::new().with_timer(LocalTime);

                base_registry.with(fmt_layer).init();
            }
        }
    }

    init_logging(&config);

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

    let addr = format!("{}:{}", config.host, config.port);
    wait_for_port(&addr, 5, Duration::from_secs(2)).await;

    let num_instances = config.num_instances;

    let mut server_futures = Vec::new();

    print_launcher(mode_actix, VERSION, config.worker, &addr.to_string(), ID);

    for _instance_id in 0..num_instances {
        let listener = create_listener(
            &format!("{}:{}", config.host, config.port),
            64 * 1024,
            64 * 1024,
            config.socket_listen.try_into().unwrap(),
        )
        .await?;

        let state_cloned = state.clone();

        let server = match mode_actix.as_ref() {
            "NO_RATELIMIT_AUTH" => {
                let seconds_per_request =
                    Duration::from_secs_f64(1.0 / requests_per_second_proxy_config as f64);
                let governor_proxy_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_proxy_config)
                    .key_extractor(UserToken)
                    .period(seconds_per_request)
                    .finish()
                    .unwrap();

                bind_server(
                    move || {
                        build_app!(state_cloned).default_service(
                            web::to(global_proxy).wrap(Governor::new(&governor_proxy_conf)),
                        )
                    },
                    listener,
                    &config,
                )?
            }

            "NO_RATELIMIT_PROXY" => {
                let seconds_per_request =
                    Duration::from_secs_f64(1.0 / requests_per_second_auth_config as f64);
                let governor_auth_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_auth_config)
                    .use_headers()
                    .period(seconds_per_request)
                    .finish()
                    .unwrap();

                bind_server(
                    move || {
                        build_app!(state_cloned)
                            .service(
                                web::resource("/auth")
                                    .route(
                                        web::post()
                                            .to(auth)
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
                )?
            }

            "RATELIMIT_GLOBAL_ON" | "RATELIMIT_GLOBAL_OFF" => {
                let seconds_per_request_auth =
                    Duration::from_secs_f64(1.0 / requests_per_second_auth_config as f64);
                let governor_auth_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_auth_config)
                    .use_headers()
                    .period(seconds_per_request_auth)
                    .finish()
                    .unwrap();

                let seconds_per_request_proxy =
                    Duration::from_secs_f64(1.0 / requests_per_second_proxy_config as f64);
                let governor_proxy_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_proxy_config)
                    .key_extractor(UserToken)
                    .period(seconds_per_request_proxy)
                    .finish()
                    .unwrap();

                bind_server(
                    move || {
                        build_app!(state_cloned)
                            .service(
                                web::resource("/auth")
                                    .route(
                                        web::post()
                                            .to(auth)
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
                )?
            }

            _ => bind_server(
                move || build_app!(state_cloned).default_service(web::to(global_proxy)),
                listener,
                &config,
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

    let results = join_all(server_futures).await;
    for r in results {
        match r {
            Ok(Err(e)) => error!("Server exited with error: {}", e),
            Err(e) => error!("Server task panicked: {}", e),
            Ok(Ok(())) => {}
        }
    }

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
