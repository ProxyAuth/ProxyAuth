use crate::cli::command::{Cli, Commands};
use crate::config::config::{AppConfig, EmailEntry, User, load_config};
use crate::config::def_config::{
    ensure_run_user_exists, ensure_running_as_proxyauth, ensure_running_as_root,
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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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

        Some(Commands::RoutesAudit) => {
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

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
