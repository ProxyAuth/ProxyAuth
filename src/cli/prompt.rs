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

            let password = match password {
                Some(p) => p.clone(),
                None => rpassword::prompt_password("password: ")?,
            };

            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| e.to_string())?
            .to_string();

            let mut conn = crate::databases::db::connect(db_cfg)?;
            crate::databases::db::ensure_schema(&mut conn)?;

            let user = User {
                username: username.clone(),
                password: hash,
                otpkey: None,
                allow: None,
                roles: None,
                email: None,
            };

            crate::databases::db::upsert_user(&mut conn, &user)?;
            println!("User '{}' written to the database.", username);
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

            let mut conn = crate::databases::db::connect(db_cfg)?;
            crate::databases::db::ensure_schema(&mut conn)?;
            crate::databases::db::mark_user_deleted(&mut conn, username)?;

            println!(
                "User '{}' soft-deleted — will be revoked on the next incremental scan of every connected instance, and permanently purged after {}s.",
                username, db_cfg.deleted_retention_secs
            );
            std::process::exit(0);
        }
    }
}
