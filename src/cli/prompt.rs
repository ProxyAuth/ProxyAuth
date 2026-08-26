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
    ClientBuilder,
    header::{HeaderMap, HeaderValue},
};
use std::sync::Arc;

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

            let mut headers = HeaderMap::new();
            headers.insert("X-Auth-Token", HeaderValue::from_str(&config.token_admin)?);

            let client = ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .build()?;

            let response = client
                .get("https://127.0.0.1:8080/adm/stats")
                .headers(headers)
                .send()
                .await?;

            if response.status().is_success() {
                let body = response.text().await?;
                println!("{}", body);
                std::process::exit(0);
            } else {
                eprintln!("Server responded with error status: {}", response.status());
                std::process::exit(1);
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

        Some(Commands::ResetPassword { username }) => {
            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");
            // Reads run_user from config.json (loaded above, while still
            // root) — defaults to "proxyauth" when unset, same as before,
            // but respects an explicit override so this command runs as
            // whichever user the running server itself uses.
            switch_to_user(config.effective_run_user())?;
            ensure_running_as(config.effective_run_user());

            // Check every prerequisite up front and report all of them
            // together, rather than bailing on the first one — nobody
            // wants to fix "page_change_password missing", re-run,
            // then discover "this user has no email" only on the
            // second try. combined_users() already includes
            // database-backed users (refreshed by load_config() just
            // above), so this looks the user up wherever they actually
            // live, file or database.
            let mut problems = Vec::new();

            if config.page_change_password.is_none() {
                problems.push(
                    "'page_change_password' is not configured in config.json — nowhere to send the user.".to_string(),
                );
            }

            if config.smtp.is_none() {
                problems.push(
                    "'smtp' is not configured in config.json — cannot send an email.".to_string(),
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
            let page_change_password = config.page_change_password.as_ref().unwrap();
            let smtp_cfg = config.smtp.as_ref().unwrap();
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

            let client = match crate::smtp::smtp::SmtpClient::new(smtp_cfg) {
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
