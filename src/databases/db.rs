//! Database-backed user storage (Diesel), supporting PostgreSQL and MySQL.
//!
//! Configured via the `databases` block in `config.json`:
//! ```json
//! "databases": {
//!   "type": "postgres",
//!   "host": "127.0.0.1",
//!   "port": 5432,
//!   "db_name": "proxyauth",
//!   "user": "proxyauth",
//!   "password": "changeme"
//! }
//! ```
//! `port` is optional — it defaults to 5432 for postgres and 3306 for
//! mysql/mariadb when omitted.
//!
//! On startup, if `databases` is set, we connect, create the `users` table
//! if it doesn't exist yet, and load any users found there. Those users are
//! merged into `AppConfig.users` (DB entries take precedence over file
//! entries with the same username), so the rest of the auth code (which
//! only ever reads `AppConfig.users`) needs no changes.

use crate::config::config::{DatabaseConfig, User};
use diesel::connection::SimpleConnection;
use diesel::mysql::MysqlConnection;
use diesel::pg::PgConnection;
use diesel::sql_types::{Nullable, Text};
use diesel::{Connection, QueryableByName, RunQueryDsl, sql_query};

pub enum DbConnection {
    Postgres(PgConnection),
    MySql(MysqlConnection),
}

#[derive(QueryableByName, Debug)]
struct DbUserRow {
    #[diesel(sql_type = Text)]
    username: String,
    #[diesel(sql_type = Text)]
    password: String,
    #[diesel(sql_type = Nullable<Text>)]
    otpkey: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    allow: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    roles: Option<String>,
}

fn csv_to_vec(s: Option<String>) -> Option<Vec<String>> {
    s.map(|s| {
        s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
    })
}

fn vec_to_csv(v: &Option<Vec<String>>) -> Option<String> {
    v.as_ref().map(|v| v.join(","))
}

/// Opens a connection to the database described by `cfg`.
pub fn connect(cfg: &DatabaseConfig) -> Result<DbConnection, String> {
    match cfg.db_type.to_lowercase().as_str() {
        "postgres" | "postgresql" | "pg" => {
            let url = format!(
                "postgres://{}:{}@{}:{}/{}",
                cfg.user,
                cfg.password,
                cfg.host,
                cfg.effective_port(),
                              cfg.db_name
            );
            let conn = PgConnection::establish(&url)
            .map_err(|e| format!("Postgres connection failed: {e}"))?;
            Ok(DbConnection::Postgres(conn))
        }
        "mysql" | "mariadb" => {
            let url = format!(
                "mysql://{}:{}@{}:{}/{}",
                cfg.user,
                cfg.password,
                cfg.host,
                cfg.effective_port(),
                              cfg.db_name
            );
            let conn = MysqlConnection::establish(&url)
            .map_err(|e| format!("MySQL connection failed: {e}"))?;
            Ok(DbConnection::MySql(conn))
        }
        other => Err(format!(
            "Unsupported databases.type '{other}': expected 'postgres' or 'mysql'"
        )),
    }
}

/// Creates the `users` table if it doesn't exist yet. Safe to call on
/// every startup.
pub fn ensure_users_table(conn: &mut DbConnection) -> Result<(), String> {
    match conn {
        DbConnection::Postgres(c) => c
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password TEXT NOT NULL,
                otpkey TEXT,
                allow TEXT,
                roles TEXT
        )",
        )
        .map_err(|e| format!("Failed to create users table (postgres): {e}")),
        DbConnection::MySql(c) => c
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password TEXT NOT NULL,
                otpkey TEXT,
                allow TEXT,
                roles TEXT
        )",
        )
        .map_err(|e| format!("Failed to create users table (mysql): {e}")),
    }
}

/// Loads every user row from the `users` table.
pub fn load_users(conn: &mut DbConnection) -> Result<Vec<User>, String> {
    let rows: Vec<DbUserRow> = match conn {
        DbConnection::Postgres(c) => {
            sql_query("SELECT username, password, otpkey, allow, roles FROM users")
            .load(c)
            .map_err(|e| format!("Failed to load users (postgres): {e}"))?
        }
        DbConnection::MySql(c) => {
            sql_query("SELECT username, password, otpkey, allow, roles FROM users")
            .load(c)
            .map_err(|e| format!("Failed to load users (mysql): {e}"))?
        }
    };

    Ok(rows
    .into_iter()
    .map(|r| User {
        username: r.username,
         password: r.password,
         otpkey: r.otpkey,
         allow: csv_to_vec(r.allow),
         roles: csv_to_vec(r.roles),
         email: None,
    })
    .collect())
}

/// Writes (creates or updates) a user row. `password` must already be the
/// final stored value (e.g. an argon2 hash) — this function does not hash
/// it for you.
pub fn upsert_user(conn: &mut DbConnection, user: &User) -> Result<(), String> {
    let allow = vec_to_csv(&user.allow);
    let roles = vec_to_csv(&user.roles);

    match conn {
        DbConnection::Postgres(c) => sql_query(
            "INSERT INTO users (username, password, otpkey, allow, roles)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (username) DO UPDATE SET
        password = EXCLUDED.password,
        otpkey = EXCLUDED.otpkey,
        allow = EXCLUDED.allow,
        roles = EXCLUDED.roles",
        )
        .bind::<Text, _>(&user.username)
        .bind::<Text, _>(&user.password)
        .bind::<Nullable<Text>, _>(&user.otpkey)
        .bind::<Nullable<Text>, _>(&allow)
        .bind::<Nullable<Text>, _>(&roles)
        .execute(c)
        .map(|_| ())
        .map_err(|e| format!("Failed to upsert user (postgres): {e}")),

        DbConnection::MySql(c) => sql_query(
            "INSERT INTO users (username, password, otpkey, allow, roles)
        VALUES (?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
        password = VALUES(password),
        otpkey = VALUES(otpkey),
        allow = VALUES(allow),
        roles = VALUES(roles)",
        )
        .bind::<Text, _>(&user.username)
        .bind::<Text, _>(&user.password)
        .bind::<Nullable<Text>, _>(&user.otpkey)
        .bind::<Nullable<Text>, _>(&allow)
        .bind::<Nullable<Text>, _>(&roles)
        .execute(c)
        .map(|_| ())
        .map_err(|e| format!("Failed to upsert user (mysql): {e}")),
    }
}

/// Connects, ensures the table exists, and returns the users currently
/// stored in the database. Returns an empty Vec (with a logged warning,
/// never a panic) on any failure, so a DB outage doesn't take the whole
/// proxy down — file-based `users` in config.json still work.
pub fn load_users_from_config(cfg: &DatabaseConfig) -> Vec<User> {
    let mut conn = match connect(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[databases] {e}");
            return Vec::new();
        }
    };

    if let Err(e) = ensure_users_table(&mut conn) {
        eprintln!("[databases] {e}");
        return Vec::new();
    }

    match load_users(&mut conn) {
        Ok(users) => users,
        Err(e) => {
            eprintln!("[databases] {e}");
            Vec::new()
        }
    }
}
