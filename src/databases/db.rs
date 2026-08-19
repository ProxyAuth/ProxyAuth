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
//! On startup, if `databases` is set, we connect, create the schema if it
//! doesn't exist yet, and load any users found there (see
//! `AppConfig::combined_users` / `AppConfig::refresh_db_users`).
//!
//! Deleting a user (`ON DELETE CASCADE`) automatically cleans up their
//! `user_allow`/`user_roles` rows.

use crate::config::config::{DatabaseConfig, User};
use diesel::connection::SimpleConnection;
use diesel::mysql::MysqlConnection;
use diesel::pg::PgConnection;
use diesel::sql_types::{BigInt, Nullable, Text};
use diesel::{Connection, QueryableByName, RunQueryDsl, sql_query};
use std::collections::HashMap;

pub enum DbConnection {
    Postgres(PgConnection),
    MySql(MysqlConnection),
}

#[derive(QueryableByName, Debug)]
struct DbUserRow {
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = Text)]
    username: String,
    #[diesel(sql_type = Text)]
    password: String,
    #[diesel(sql_type = Nullable<Text>)]
    otpkey: Option<String>,
}

/// Generic (user_id, value) row shape shared by `user_allow` and
/// `user_roles` (aliased to `value` in the SELECT).
#[derive(QueryableByName, Debug)]
struct UserIdValueRow {
    #[diesel(sql_type = BigInt)]
    user_id: i64,
    #[diesel(sql_type = Text)]
    value: String,
}

#[derive(QueryableByName, Debug)]
struct IdRow {
    #[diesel(sql_type = BigInt)]
    id: i64,
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

/// Creates `users`, `user_allow` and `user_roles` if they don't exist yet.
/// Safe to call on every startup.
pub fn ensure_schema(conn: &mut DbConnection) -> Result<(), String> {
    match conn {
        DbConnection::Postgres(c) => {
            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                            password TEXT NOT NULL,
                            otpkey TEXT
            )",
            )
            .map_err(|e| format!("Failed to create users table (postgres): {e}"))?;

            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS user_allow (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            cidr TEXT NOT NULL
            )",
            )
            .map_err(|e| format!("Failed to create user_allow table (postgres): {e}"))?;

            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS user_roles (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            role TEXT NOT NULL
            )",
            )
            .map_err(|e| format!("Failed to create user_roles table (postgres): {e}"))?;

            Ok(())
        }
        DbConnection::MySql(c) => {
            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS users (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                            password TEXT NOT NULL,
                            otpkey TEXT
            )",
            )
            .map_err(|e| format!("Failed to create users table (mysql): {e}"))?;

            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS user_allow (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    cidr TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",
            )
            .map_err(|e| format!("Failed to create user_allow table (mysql): {e}"))?;

            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS user_roles (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    role TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",
            )
            .map_err(|e| format!("Failed to create user_roles table (mysql): {e}"))?;

            Ok(())
        }
    }
}

/// Loads every user, along with their `allow` and `roles` rows (three
/// simple queries, joined in memory — keeps the raw SQL portable across
/// both backends without relying on backend-specific aggregate functions
/// like `string_agg`/`GROUP_CONCAT`).
pub fn load_users(conn: &mut DbConnection) -> Result<Vec<User>, String> {
    let (user_rows, allow_rows, role_rows): (
        Vec<DbUserRow>,
        Vec<UserIdValueRow>,
        Vec<UserIdValueRow>,
    ) = match conn {
        DbConnection::Postgres(c) => (
            sql_query("SELECT id, username, password, otpkey FROM users")
            .load(c)
            .map_err(|e| format!("Failed to load users (postgres): {e}"))?,
                                      sql_query("SELECT user_id, cidr AS value FROM user_allow")
                                      .load(c)
                                      .map_err(|e| format!("Failed to load user_allow (postgres): {e}"))?,
                                      sql_query("SELECT user_id, role AS value FROM user_roles")
                                      .load(c)
                                      .map_err(|e| format!("Failed to load user_roles (postgres): {e}"))?,
        ),
        DbConnection::MySql(c) => (
            sql_query("SELECT id, username, password, otpkey FROM users")
            .load(c)
            .map_err(|e| format!("Failed to load users (mysql): {e}"))?,
                                   sql_query("SELECT user_id, cidr AS value FROM user_allow")
                                   .load(c)
                                   .map_err(|e| format!("Failed to load user_allow (mysql): {e}"))?,
                                   sql_query("SELECT user_id, role AS value FROM user_roles")
                                   .load(c)
                                   .map_err(|e| format!("Failed to load user_roles (mysql): {e}"))?,
        ),
    };

    let mut allow_map: HashMap<i64, Vec<String>> = HashMap::new();
    for row in allow_rows {
        allow_map.entry(row.user_id).or_default().push(row.value);
    }

    let mut roles_map: HashMap<i64, Vec<String>> = HashMap::new();
    for row in role_rows {
        roles_map.entry(row.user_id).or_default().push(row.value);
    }

    Ok(user_rows
    .into_iter()
    .map(|r| User {
        username: r.username,
         password: r.password,
         otpkey: r.otpkey,
         allow: allow_map.remove(&r.id),
         roles: roles_map.remove(&r.id),
         email: None,
    })
    .collect())
}

/// Inserts or updates the `users` row itself, returning its `id`.
fn upsert_user_row(conn: &mut DbConnection, user: &User) -> Result<i64, String> {
    match conn {
        DbConnection::Postgres(c) => {
            let row: IdRow = sql_query(
                "INSERT INTO users (username, password, otpkey)
            VALUES ($1, $2, $3)
            ON CONFLICT (username) DO UPDATE SET
            password = EXCLUDED.password,
            otpkey = EXCLUDED.otpkey
            RETURNING id",
            )
            .bind::<Text, _>(&user.username)
            .bind::<Text, _>(&user.password)
            .bind::<Nullable<Text>, _>(&user.otpkey)
            .get_result(c)
            .map_err(|e| format!("Failed to upsert user (postgres): {e}"))?;
            Ok(row.id)
        }
        DbConnection::MySql(c) => {
            sql_query(
                "INSERT INTO users (username, password, otpkey)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
            password = VALUES(password),
                      otpkey = VALUES(otpkey),
                      id = LAST_INSERT_ID(id)",
            )
            .bind::<Text, _>(&user.username)
            .bind::<Text, _>(&user.password)
            .bind::<Nullable<Text>, _>(&user.otpkey)
            .execute(c)
            .map_err(|e| format!("Failed to upsert user (mysql): {e}"))?;

            let row: IdRow = sql_query("SELECT LAST_INSERT_ID() AS id")
            .get_result(c)
            .map_err(|e| format!("Failed to fetch inserted user id (mysql): {e}"))?;
            Ok(row.id)
        }
    }
}

/// Replaces every `user_allow` row for `user_id` with `values` (deletes
/// then re-inserts — simplest way to handle add/remove/reorder of a
/// multi-valued field with a real child table).
fn replace_user_allow(
    conn: &mut DbConnection,
    user_id: i64,
    values: Option<&[String]>,
) -> Result<(), String> {
    match conn {
        DbConnection::Postgres(c) => {
            sql_query("DELETE FROM user_allow WHERE user_id = $1")
            .bind::<BigInt, _>(user_id)
            .execute(c)
            .map_err(|e| format!("Failed to clear user_allow (postgres): {e}"))?;
            for cidr in values.unwrap_or_default() {
                sql_query("INSERT INTO user_allow (user_id, cidr) VALUES ($1, $2)")
                .bind::<BigInt, _>(user_id)
                .bind::<Text, _>(cidr)
                .execute(c)
                .map_err(|e| format!("Failed to insert user_allow (postgres): {e}"))?;
            }
        }
        DbConnection::MySql(c) => {
            sql_query("DELETE FROM user_allow WHERE user_id = ?")
            .bind::<BigInt, _>(user_id)
            .execute(c)
            .map_err(|e| format!("Failed to clear user_allow (mysql): {e}"))?;
            for cidr in values.unwrap_or_default() {
                sql_query("INSERT INTO user_allow (user_id, cidr) VALUES (?, ?)")
                .bind::<BigInt, _>(user_id)
                .bind::<Text, _>(cidr)
                .execute(c)
                .map_err(|e| format!("Failed to insert user_allow (mysql): {e}"))?;
            }
        }
    }
    Ok(())
}

/// Same as `replace_user_allow`, for `user_roles`.
fn replace_user_roles(
    conn: &mut DbConnection,
    user_id: i64,
    values: Option<&[String]>,
) -> Result<(), String> {
    match conn {
        DbConnection::Postgres(c) => {
            sql_query("DELETE FROM user_roles WHERE user_id = $1")
            .bind::<BigInt, _>(user_id)
            .execute(c)
            .map_err(|e| format!("Failed to clear user_roles (postgres): {e}"))?;
            for role in values.unwrap_or_default() {
                sql_query("INSERT INTO user_roles (user_id, role) VALUES ($1, $2)")
                .bind::<BigInt, _>(user_id)
                .bind::<Text, _>(role)
                .execute(c)
                .map_err(|e| format!("Failed to insert user_roles (postgres): {e}"))?;
            }
        }
        DbConnection::MySql(c) => {
            sql_query("DELETE FROM user_roles WHERE user_id = ?")
            .bind::<BigInt, _>(user_id)
            .execute(c)
            .map_err(|e| format!("Failed to clear user_roles (mysql): {e}"))?;
            for role in values.unwrap_or_default() {
                sql_query("INSERT INTO user_roles (user_id, role) VALUES (?, ?)")
                .bind::<BigInt, _>(user_id)
                .bind::<Text, _>(role)
                .execute(c)
                .map_err(|e| format!("Failed to insert user_roles (mysql): {e}"))?;
            }
        }
    }
    Ok(())
}

/// Writes (creates or updates) a user, and replaces their `allow`/`roles`
/// rows to match `user` exactly. `password` must already be the final
/// stored value (e.g. an argon2 hash) — this function does not hash it
/// for you.
pub fn upsert_user(conn: &mut DbConnection, user: &User) -> Result<(), String> {
    let user_id = upsert_user_row(conn, user)?;
    replace_user_allow(conn, user_id, user.allow.as_deref())?;
    replace_user_roles(conn, user_id, user.roles.as_deref())?;
    Ok(())
}

/// Connects, ensures the schema exists, and returns the users currently
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

    if let Err(e) = ensure_schema(&mut conn) {
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
