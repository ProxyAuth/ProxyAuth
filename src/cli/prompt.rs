use crate::cli::command::{Cli, Commands};
use crate::config::config::{AppConfig, EmailEntry, User, load_config};
use crate::config::def_config::{
    ensure_run_user_exists, ensure_running_as, ensure_running_as_root,
    ensure_user_proxyauth_exists, peek_run_user_group, setup_proxyauth_db_directory,
    setup_proxyauth_directory, setup_proxyauth_directory_for, switch_to_user,
};
use crate::keystore::export::export_as_file;
use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher};
use clap::Parser;
use reqwest::{
    Certificate, ClientBuilder,
    header::{HeaderMap, HeaderValue},
};
use std::sync::Arc;

/// Builds a `reqwest::Client` for the CLI's own loopback-only calls to
/// the locally running ProxyAuth instance's admin API (`127.0.0.1`,
/// same host, same config file) — used for `reset-otp` and any future
/// CLI command that needs to hit its own `/adm/*` over HTTPS.
///
/// SECURITY: this used to be `danger_accept_invalid_certs(true)`,
/// trusting *any* certificate whatsoever presented on that connection.
/// The problem it was working around is real but narrower than that:
/// `/etc/proxyauth/certs/cert.pem` (the server's own default
/// certificate — see `tls.rs`) is a perfectly legitimate, correctly
/// issued certificate, it just isn't issued for the literal hostname
/// "127.0.0.1", so ordinary hostname verification fails against it
/// even though the certificate itself is exactly the one this CLI
/// should be talking to.
///
/// The fix here is certificate *pinning*, not disabling validation:
/// `tls_certs_only([cert])` restricts trust to exactly this one
/// certificate (nothing else — not the system CA store, not any other
/// certificate), and `danger_accept_invalid_hostnames` tolerates only
/// the specific hostname mismatch this loopback connection always has.
/// reqwest 0.13 actually enforces this pairing itself — it refuses to
/// build a client with hostname verification disabled unless
/// `tls_certs_only` has *also* been used to restrict the trust store,
/// specifically to prevent the far more dangerous combination of
/// "trust any hostname, using the full normal CA store." A process on
/// the same host can no longer intercept this connection by presenting
/// an arbitrary self-signed certificate — it would need the private
/// key matching this exact, on-disk certificate to be accepted at all.
/// Verified end-to-end against a real TLS server: the correct
/// certificate connects successfully, a different one is rejected.
///
/// Falls back to the old any-certificate-accepted behavior only if the
/// certificate file can't be read (e.g. TLS enabled but the default
/// cert genuinely isn't at the expected path for some reason) — loudly
/// warned, not silent, so a broken pin doesn't just look like a
/// mysterious connection failure.
fn build_loopback_admin_client() -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    const DEFAULT_CERT_PATH: &str = "/etc/proxyauth/certs/cert.pem";

    match std::fs::read(DEFAULT_CERT_PATH) {
        Ok(pem_bytes) => match Certificate::from_pem(&pem_bytes) {
            Ok(cert) => Ok(ClientBuilder::new()
                .tls_certs_only([cert])
                .danger_accept_invalid_hostnames(true)
                .build()?),
            Err(e) => {
                eprintln!(
                    "Warning: failed to parse {DEFAULT_CERT_PATH} ({e}) — falling back to accepting any certificate for this loopback-only connection."
                );
                Ok(ClientBuilder::new()
                    .danger_accept_invalid_certs(true)
                    .build()?)
            }
        },
        Err(e) => {
            eprintln!(
                "Warning: could not read {DEFAULT_CERT_PATH} ({e}) — falling back to accepting any certificate for this loopback-only connection."
            );
            Ok(ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .build()?)
        }
    }
}

/// Formats a duration in seconds as e.g. "2d 3h 14m 05s" — trims
/// leading zero units (an uptime under a minute just shows "42s", not
/// "0d 0h 0m 42s"), for `proxyauth stats`.
fn format_uptime(total_secs: u64) -> String {
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m {seconds:02}s")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

pub async fn prompt() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        None => return Ok(()),

        Some(Commands::Prepare { insecure }) => {
            switch_to_user("root")?;
            ensure_running_as_root();

            let (run_user, run_group) = peek_run_user_group();
            if run_user == "proxyauth" {
                ensure_user_proxyauth_exists()?;
                setup_proxyauth_directory()?;
            } else {
                // Custom run_user (e.g. www-data/nginx): verify it
                // exists rather than create it, then own
                // /etc/proxyauth by that account instead — this is
                // what lets ProxyAuth read that account's own files
                // (a `static` route's directory, say) without ever
                // touching that directory's permissions.
                ensure_run_user_exists(&run_user, run_group.as_deref())?;
                setup_proxyauth_directory_for(
                    &run_user,
                    run_group.as_deref().unwrap_or(&run_user),
                )?;
            }
            setup_proxyauth_db_directory(*insecure)?;
            std::process::exit(0);
        }

        Some(Commands::Sync { target }) => {
            ensure_running_as_root();

            match target.as_deref() {
                None => {
                    std::process::exit(0);
                }
                Some("export") => {
                    let _ = export_as_file(None);
                    std::process::exit(0);
                }
                Some(_host) => Ok(()),
            }
        }

        Some(Commands::Stats) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            // Local Unix socket, not HTTPS — RequestStats/CounterToken
            // are in-process memory in the running server; this socket
            // (spawned by the server itself, see
            // network::stats::spawn_stats_socket) is the channel that
            // actually makes them reachable from this separate CLI
            // process at all. No admin token needed either: the
            // socket's own filesystem permissions (0600, inside
            // /opt/proxyauth which is itself 700) are the
            // authentication.
            let socket_path = crate::network::stats::STATS_SOCKET_PATH;
            let mut stream = match tokio::net::UnixStream::connect(socket_path).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "Failed to connect to {socket_path}: {e} — is ProxyAuth running? (the socket is created at server startup, not before)"
                    );
                    std::process::exit(1);
                }
            };

            let mut buf = Vec::new();
            use tokio::io::AsyncReadExt;
            if let Err(e) = stream.read_to_end(&mut buf).await {
                eprintln!("Failed to read from {socket_path}: {e}");
                std::process::exit(1);
            }

            match serde_json::from_slice::<crate::network::stats::ProxyStatsResponse>(&buf) {
                Ok(resp) => {
                    println!("requests/sec (last):  {}", resp.requests_per_second);
                    println!("avg req/sec (10s):     {:.2}", resp.avg_rps_10s);
                    println!("avg req/sec (60s):     {:.2}", resp.avg_rps_60s);
                    println!("total requests:        {}", resp.total_requests);
                    println!("active sessions:       {}", resp.active_sessions);
                    println!(
                        "uptime:                {}",
                        format_uptime(resp.uptime_seconds)
                    );
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("Received malformed stats data from {socket_path}: {e}");
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::DbAddUser {
            username,
            password,
            email,
            primary_email,
            must_change_password,
        }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let Some(db_cfg) = &config.databases else {
                eprintln!("No 'databases' block configured in config.json — nothing to write to.");
                std::process::exit(1);
            };

            // A live connection is required, checked here before even
            // asking for a password — the LMDB fallback cache (see
            // databases::cache) exists only for *reads* used to keep
            // serving logins during a DB outage. It's never a valid
            // target for a write: writing there would silently diverge
            // from the real database and vanish on the next successful
            // sync, giving a false impression the user was actually
            // created.
            if let Err(e) = crate::databases::db::with_connection(db_cfg, |conn| {
                crate::databases::db::ensure_schema(conn)
            }) {
                eprintln!("Database is not reachable — cannot write a user: {e}");
                std::process::exit(1);
            }

            let password = match password {
                Some(p) => p.clone(),
                None => rpassword::prompt_password("password: ")?,
            };

            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| e.to_string())?
                .to_string();

            // --primary-email must name one of the --email addresses
            // given, if provided at all — otherwise it's ambiguous
            // which entry it was meant to mark. Defaults to the first
            // --email given, matching the pre-existing convention this
            // replaces (positional "first wins"), just made explicit.
            let email_entries: Vec<EmailEntry> = if email.is_empty() {
                Vec::new()
            } else {
                let primary_addr = match primary_email {
                    Some(p) => {
                        if !email.contains(p) {
                            eprintln!(
                                "--primary-email '{p}' must match one of the --email addresses given."
                            );
                            std::process::exit(1);
                        }
                        p.clone()
                    }
                    None => email[0].clone(),
                };
                email
                    .iter()
                    .map(|addr| EmailEntry {
                        address: addr.clone(),
                        primary: *addr == primary_addr,
                    })
                    .collect()
            };

            let user = User {
                username: username.clone(),
                password: hash,
                otpkey: None,
                allow: None,
                roles: None,
                groups: None,
                email: if email_entries.is_empty() {
                    None
                } else {
                    Some(email_entries)
                },
                must_change_password: *must_change_password,
            };

            crate::databases::db::with_connection(db_cfg, |conn| {
                crate::databases::db::upsert_user(conn, &user)
            })?;
            println!(
                "User '{}' written to the database (revived if it was previously soft-deleted).",
                username
            );
            std::process::exit(0);
        }

        Some(Commands::DbDeleteUser { username }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let Some(db_cfg) = &config.databases else {
                eprintln!(
                    "No 'databases' block configured in config.json — nothing to delete from."
                );
                std::process::exit(1);
            };

            // Same reasoning as db-add-user above — this must hit the
            // real database, never the local read-only fallback cache.
            match crate::databases::db::with_connection(db_cfg, |conn| {
                crate::databases::db::ensure_schema(conn)?;
                crate::databases::db::mark_user_deleted(conn, username)
            }) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Database is not reachable — cannot delete a user: {e}");
                    std::process::exit(1);
                }
            }

            println!(
                "User '{}' soft-deleted — will be revoked on the next incremental scan of every connected instance, and permanently purged after {}s.",
                username, db_cfg.deleted_retention_secs
            );
            std::process::exit(0);
        }

        Some(Commands::DbRestoreFromCache { force }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let Some(db_cfg) = &config.databases else {
                eprintln!(
                    "No 'databases' block configured in config.json — nothing to restore into."
                );
                std::process::exit(1);
            };

            let cached = match crate::databases::cache::read_snapshot() {
                Ok(users) if !users.is_empty() => users,
                Ok(_) => {
                    eprintln!("Local cache is empty — nothing to restore.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("No usable local cache to restore from: {e}");
                    std::process::exit(1);
                }
            };

            // Same reasoning as db-add-user/db-delete-user above — this
            // must hit the real database, never fall back to anything
            // else if it's unreachable. Everything here — the existing-
            // users check, the force gate, and the restore loop — runs
            // as one unit against the same connection.
            let restore_result = crate::databases::db::with_connection(db_cfg, |conn| {
                crate::databases::db::ensure_schema(conn)?;

                let existing: std::collections::HashSet<String> =
                    crate::databases::db::load_users(conn)?
                        .into_iter()
                        .map(|u| u.username)
                        .collect();

                if !existing.is_empty() && !force {
                    return Err(format!(
                        "Database already has {} user(s) — refusing to restore without --force, to avoid silently overwriting them with the (possibly older) cached snapshot. Re-run with --force if you're sure you want the cache to win.",
                        existing.len()
                    ));
                }

                let mut restored = 0u32;
                for user in &cached {
                    crate::databases::db::upsert_user(conn, user)
                        .map_err(|e| format!("Failed to restore user '{}': {e}", user.username))?;
                    restored += 1;
                }

                Ok(restored)
            });

            match restore_result {
                Ok(restored) => {
                    println!(
                        "Restored {} user(s) from the local cache into the database.",
                        restored
                    );
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::DbClearCache) => {
            // Loaded purely to read run_user — clear_snapshot() itself
            // needs nothing else from config.json.
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            match crate::databases::cache::clear_snapshot() {
                Ok(()) => {
                    println!(
                        "Local cache cleared. It will be repopulated on the next successful full database read."
                    );
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("Failed to clear local cache: {e}");
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::DbSyncCache { force }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let Some(db_cfg) = &config.databases else {
                eprintln!("No 'databases' block configured in config.json — nothing to sync.");
                std::process::exit(1);
            };

            // A live connection is required — this must be a genuinely
            // fresh read, never a fallback to the cache we're about to
            // overwrite (that would just be writing the cache back to
            // itself).
            let users = match crate::databases::db::with_connection(db_cfg, |conn| {
                crate::databases::db::ensure_schema(conn)?;
                crate::databases::db::load_users(conn)
            }) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("Database is not reachable — cannot sync the cache: {e}");
                    std::process::exit(1);
                }
            };

            if users.is_empty() && !*force {
                let existing_count = crate::databases::cache::read_snapshot()
                    .map(|u| u.len())
                    .unwrap_or(0);
                if existing_count > 0 {
                    eprintln!(
                        "Database returned 0 users, but the local cache currently has {existing_count} — refusing to overwrite it with an empty snapshot without --force."
                    );
                    eprintln!(
                        "If the database genuinely has no users right now, re-run with --force."
                    );
                    std::process::exit(1);
                }
            }

            let count = users.len();
            if let Err(e) = crate::databases::cache::write_snapshot(&users) {
                eprintln!("Failed to write the local cache: {e}");
                std::process::exit(1);
            }

            println!("Local cache synced from the database — now holds {count} user(s).");
            std::process::exit(0);
        }

        Some(Commands::ResetPassword { username, vhost }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            // --vhost resolves this vhost's own smtp/page_change_password
            // (from its route or `vhosts:` group), if it sets one — see
            // the flag's own doc comment for why this can't be resolved
            // automatically the way a live HTTP request's Host header
            // would let it be. An unrecognized --vhost is an error, not
            // a silent fall-through to the global config: the admin
            // explicitly asked for that vhost's settings, so silently
            // using something else instead could send the email via
            // the wrong SMTP server without any indication that happened.
            let vhost_route = if let Some(vhost_name) = vhost {
                let routes = match crate::cli::audit::load_routes_for_cli() {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                };
                match crate::network::proxy::find_vhost_route(
                    Some(vhost_name.as_str()),
                    &routes.routes,
                ) {
                    Some(r) => Some(r.clone()),
                    None => {
                        eprintln!(
                            "No route in routes.yml lists '{vhost_name}' in its vhost — check the spelling, or omit --vhost to use the global config.json default."
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                None
            };

            let resolved_page_change_password = vhost_route
                .as_ref()
                .and_then(|r| r.resolved_page_change_password(&config))
                .or(config.page_change_password.as_deref())
                .map(str::to_string);
            let resolved_smtp = vhost_route
                .as_ref()
                .and_then(|r| r.resolved_smtp(&config))
                .or(config.smtp.as_ref())
                .cloned();

            // Check every prerequisite up front and report all of them
            // together, rather than bailing on the first one — nobody
            // wants to fix "page_change_password missing", re-run,
            // then discover "this user has no email" only on the
            // second try. combined_users() already includes
            // database-backed users (refreshed by load_config() just
            // above), so this looks the user up wherever they actually
            // live, file or database.
            let mut problems = Vec::new();

            if resolved_page_change_password.is_none() {
                problems.push(
                    "'page_change_password' is not configured (checked the named --vhost, if any, then config.json) — nowhere to send the user.".to_string(),
                );
            }

            if resolved_smtp.is_none() {
                problems.push(
                    "'smtp' is not configured (checked the named --vhost, if any, then config.json) — cannot send an email.".to_string(),
                );
            }

            let combined_users = config.combined_users();
            let email = crate::token::reset_password::find_user_email(&combined_users, username);
            let user_exists = combined_users.iter().any(|u| &u.username == username);

            if !user_exists {
                problems.push(format!("Unknown user '{username}'."));
            } else if email.is_none() {
                problems.push(format!(
                    "User '{username}' has no email on file — add one to 'email' in config.json (or the database) before resetting their password this way."
                ));
            }

            if !problems.is_empty() {
                for p in &problems {
                    eprintln!("{p}");
                }
                std::process::exit(1);
            }

            // All checks passed, so these are guaranteed Some by this
            // point — the branches above already covered every case
            // where they wouldn't be.
            let page_change_password = resolved_page_change_password.unwrap();
            let smtp_cfg = resolved_smtp.unwrap();
            let email = email.unwrap();

            // 1 hour is generous enough for someone to check their
            // email without the link staying valid indefinitely.
            let token = match crate::reset::db::create_token(
                username,
                crate::reset::db::ResetKind::AdminReset,
                3600,
            ) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Failed to generate a reset token: {e}");
                    std::process::exit(1);
                }
            };

            let separator = if page_change_password.contains('?') {
                '&'
            } else {
                '?'
            };
            let reset_link = format!("{page_change_password}{separator}token={token}");

            let client = match crate::smtp::smtp::SmtpClient::new(&smtp_cfg) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to set up the SMTP client: {e}");
                    std::process::exit(1);
                }
            };

            match client
                .send_reset_password(&email, username, &reset_link)
                .await
            {
                Ok(()) => {
                    println!("Password reset link sent to '{username}' at {email}.");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("Failed to send the reset email: {e}");
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::ResetOtp { username }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            if config.token_admin.is_empty() {
                eprintln!(
                    "'token_admin' is not configured in config.json — cannot authenticate to the admin endpoint."
                );
                std::process::exit(1);
            }

            let combined_users = config.combined_users();
            if !combined_users.iter().any(|u| &u.username == username) {
                eprintln!("No such user: '{username}'.");
                std::process::exit(1);
            }

            let scheme = if config.tls { "https" } else { "http" };
            let url = format!("{scheme}://127.0.0.1:{}/adm/auth/totp/reset", config.port);

            let mut headers = HeaderMap::new();
            headers.insert("X-Auth-Token", HeaderValue::from_str(&config.token_admin)?);

            let client = if config.tls {
                build_loopback_admin_client()?
            } else {
                ClientBuilder::new().build()?
            };

            let response = client
                .post(&url)
                .headers(headers)
                .json(&serde_json::json!({ "username": username }))
                .send()
                .await?;

            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            if status.is_success() {
                println!("{body}");
                std::process::exit(0);
            } else {
                eprintln!("Server responded with {status}: {body}");
                std::process::exit(1);
            }
        }

        Some(Commands::Certbot { action }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());
            let routes = match crate::cli::audit::load_routes_for_cli() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            match action {
                crate::cli::command::CertbotAction::Renew { vhost, force } => {
                    if vhost.eq_ignore_ascii_case("all") {
                        let managed = crate::acme::collect_managed_vhosts(&routes.routes);
                        if managed.is_empty() {
                            println!(
                                "No vhost has both certbot_renew: true and a usable vhost_cert configured — nothing to renew."
                            );
                            std::process::exit(0);
                        }

                        let mut any_failed = false;
                        for mv in &managed {
                            print!("{}: ", mv.vhost);
                            match crate::acme::check_and_maybe_renew(mv, &config.acme, *force)
                                .await
                            {
                                crate::acme::RenewOutcome::NotDue { days_left } => {
                                    println!(
                                        "not due ({days_left} day(s) left, renew_before_days: {})",
                                        config.acme.renew_before_days
                                    );
                                }
                                crate::acme::RenewOutcome::Renewed => {
                                    println!("renewed");
                                }
                                crate::acme::RenewOutcome::Failed(e) => {
                                    println!("FAILED — currently valid certificate kept: {e}");
                                    any_failed = true;
                                }
                            }
                        }
                        std::process::exit(if any_failed { 1 } else { 0 });
                    }

                    let Some((cert_path, key_path)) =
                        crate::acme::find_vhost_cert_paths(&routes.routes, vhost)
                    else {
                        eprintln!(
                            "No vhost_cert (cert/key) configured for '{vhost}' in routes.yml — nothing to renew into. Set vhost_cert on a route listing this vhost first. (Use 'all' to renew every certbot_renew: true vhost at once.)"
                        );
                        std::process::exit(1);
                    };

                    let mv = crate::acme::ManagedVhost {
                        vhost: vhost.clone(),
                        cert_path,
                        key_path,
                    };

                    match crate::acme::check_and_maybe_renew(&mv, &config.acme, *force).await {
                        crate::acme::RenewOutcome::NotDue { days_left } => {
                            println!(
                                "'{vhost}' has {days_left} day(s) left (renew_before_days: {}) — not due yet. Use --force to renew anyway.",
                                config.acme.renew_before_days
                            );
                            std::process::exit(0);
                        }
                        crate::acme::RenewOutcome::Renewed => {
                            println!(
                                "Renewed successfully -> {} / {}",
                                mv.cert_path.display(),
                                mv.key_path.display()
                            );
                            std::process::exit(0);
                        }
                        crate::acme::RenewOutcome::Failed(e) => {
                            eprintln!(
                                "Renewal failed for '{vhost}' — the currently valid certificate keeps being used: {e}"
                            );
                            std::process::exit(1);
                        }
                    }
                }

                crate::cli::command::CertbotAction::Check { vhost } => {
                    let targets: Vec<crate::acme::ManagedVhost> = if vhost.eq_ignore_ascii_case("all")
                    {
                        crate::acme::collect_all_vhost_certs(&routes.routes)
                    } else {
                        match crate::acme::find_vhost_cert_paths(&routes.routes, vhost) {
                            Some((cert_path, key_path)) => vec![crate::acme::ManagedVhost {
                                vhost: vhost.clone(),
                                cert_path,
                                key_path,
                            }],
                            None => {
                                eprintln!(
                                    "No vhost_cert (cert/key) configured for '{vhost}' in routes.yml."
                                );
                                std::process::exit(1);
                            }
                        }
                    };

                    if targets.is_empty() {
                        println!("No vhost has a vhost_cert configured — nothing to check.");
                        std::process::exit(0);
                    }

                    let mut any_error = false;
                    for (i, mv) in targets.iter().enumerate() {
                        if i > 0 {
                            println!();
                        }
                        println!("{}", mv.vhost);
                        println!("  cert file:  {}", mv.cert_path.display());
                        match crate::acme::read_cert_info(&mv.cert_path) {
                            Ok(info) => {
                                println!("  subject:    {}", info.subject);
                                println!("  issuer:     {}", info.issuer);
                                println!("  valid from: {}", info.not_before);
                                println!("  valid till: {}", info.not_after);
                                println!("  days left:  {}", info.days_left);
                                println!("  serial:     {}", info.serial);
                                if !info.san.is_empty() {
                                    println!("  covers:     {}", info.san.join(", "));
                                }
                            }
                            Err(e) => {
                                println!("  {e}");
                                any_error = true;
                            }
                        }
                    }
                    std::process::exit(if any_error { 1 } else { 0 });
                }

                crate::cli::command::CertbotAction::New { vhost } => {
                    let Some((cert_path, key_path)) =
                        crate::acme::find_vhost_cert_paths(&routes.routes, vhost)
                    else {
                        eprintln!(
                            "No vhost_cert (cert/key) configured for '{vhost}' in routes.yml — set that first, then run this again."
                        );
                        std::process::exit(1);
                    };

                    println!("Issuing a new certificate for '{vhost}'...");
                    match crate::acme::renew::renew_certificate(
                        vhost,
                        &cert_path,
                        &key_path,
                        &config.acme,
                    )
                    .await
                    {
                        Ok(()) => {
                            println!(
                                "Issued successfully -> {} / {}",
                                cert_path.display(),
                                key_path.display()
                            );
                            println!(
                                "If '{vhost}' was just added to routes.yml, restart ProxyAuth now — the TLS layer only starts watching a vhost's certificate files at startup, so an already-running server won't pick up a brand new vhost's certificate on its own."
                            );
                            std::process::exit(0);
                        }
                        Err(e) => {
                            eprintln!("Failed to issue a certificate for '{vhost}': {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        Some(Commands::RoutesAudit) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let routes = match crate::cli::audit::load_routes_for_cli() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            crate::cli::audit::print_routes_audit(&config, &routes);
            std::process::exit(0);
        }

        Some(Commands::CheckAccess { username }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let routes = match crate::cli::audit::load_routes_for_cli() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            // Doesn't require the username to exist — checking access
            // for a not-(yet)-registered name is still meaningful
            // (e.g. "if I add alice with these groups, what would she
            // reach?"), so this deliberately doesn't reject unknown
            // usernames the way ResetPassword does.
            crate::cli::audit::print_check_access(&config, &routes, username);
            std::process::exit(0);
        }

        Some(Commands::CheckRoutes) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let routes = match crate::cli::audit::load_routes_for_cli() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            crate::cli::audit::print_check_routes(&config, &routes);
            std::process::exit(0);
        }

        Some(Commands::Users { list }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let routes = match crate::cli::audit::load_routes_for_cli() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            crate::cli::audit::print_users(&config, &routes, *list);
            std::process::exit(0);
        }

        Some(Commands::Groups { list }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let routes = match crate::cli::audit::load_routes_for_cli() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            crate::cli::audit::print_groups(&config, &routes, *list);
            std::process::exit(0);
        }

        Some(Commands::Roles { list }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            let routes = match crate::cli::audit::load_routes_for_cli() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            crate::cli::audit::print_roles(&config, &routes, *list);
            std::process::exit(0);
        }
    }
}
