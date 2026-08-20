use crate::cli::command::{Cli, Commands};
use crate::config::config::{AppConfig, User, load_config};
use crate::config::def_config::{
    ensure_running_as_proxyauth, ensure_running_as_root, ensure_user_proxyauth_exists,
    setup_proxyauth_db_directory, setup_proxyauth_directory, switch_to_user,
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
            ensure_user_proxyauth_exists()?;
            setup_proxyauth_directory()?;
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

        Some(Commands::DbAddUser { username, password }) => {
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

            let Some(db_cfg) = &config.databases else {
                eprintln!(
                    "No 'databases' block configured in config.json — nothing to write to."
                );
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
            let mut conn = match crate::databases::db::connect(db_cfg) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database is not reachable — cannot write a user: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = crate::databases::db::ensure_schema(&mut conn) {
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

            let user = User {
                username: username.clone(),
                password: hash,
                otpkey: None,
                allow: None,
                roles: None,
                email: None,
            };

            crate::databases::db::upsert_user(&mut conn, &user)?;
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
            let mut conn = match crate::databases::db::connect(db_cfg) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database is not reachable — cannot delete a user: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = crate::databases::db::ensure_schema(&mut conn) {
                eprintln!("Database is not reachable — cannot delete a user: {e}");
                std::process::exit(1);
            }
            crate::databases::db::mark_user_deleted(&mut conn, username)?;

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
            // else if it's unreachable.
            let mut conn = match crate::databases::db::connect(db_cfg) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database is not reachable — cannot restore: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = crate::databases::db::ensure_schema(&mut conn) {
                eprintln!("Database is not reachable — cannot restore: {e}");
                std::process::exit(1);
            }

            let existing: std::collections::HashSet<String> =
            match crate::databases::db::load_users(&mut conn) {
                Ok(users) => users.into_iter().map(|u| u.username).collect(),
                Err(e) => {
                    eprintln!("Failed to read current database state before restoring: {e}");
                    std::process::exit(1);
                }
            };

            if !existing.is_empty() && !force {
                eprintln!(
                    "Database already has {} user(s) — refusing to restore without --force, to avoid silently overwriting them with the (possibly older) cached snapshot.",
                    existing.len()
                );
                eprintln!("Re-run with --force if you're sure you want the cache to win.");
                std::process::exit(1);
            }

            let mut restored = 0u32;
            for user in &cached {
                if let Err(e) = crate::databases::db::upsert_user(&mut conn, user) {
                    eprintln!("Failed to restore user '{}': {e}", user.username);
                    std::process::exit(1);
                }
                restored += 1;
            }

            println!(
                "Restored {} user(s) from the local cache into the database.",
                restored
            );
            std::process::exit(0);
        }
    }
}
