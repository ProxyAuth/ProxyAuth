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
//!
//! ## Incremental scans
//! `created_at`/`modified_at` columns let a refresh query for just the
//! rows touched in a recent time window (`load_recently_changed_users`),
//! instead of always reading the entire `users` table. With a lot of
//! users, a full `SELECT * FROM users` on every refresh gets slow and
//! wastes bandwidth for the near-always-empty case of "nothing changed
//! since last time". A short, indexed `WHERE modified_at >= $cutoff`
//! stays fast no matter how large the table grows, since its cost scales
//! with *changes in the window*, not total row count.
//!
//! This does **not** replace the full scan — a `modified_at` filter can
//! never see a hard-deleted row, so `AppConfig` still runs an occasional
//! full `load_users` pass to catch deletions (see `refresh_db_users` /
//! `refresh_db_users_incremental` in `config.rs`).

use crate::config::config::{DatabaseConfig, User};
use crate::databases::cache;
use chrono::NaiveDateTime;
use diesel::connection::SimpleConnection;
use diesel::mysql::MysqlConnection;
use diesel::pg::PgConnection;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamp};
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

/// Same shape as `DbUserRow`, plus `deleted` — used only by the
/// incremental scan, which (unlike the full scan) needs to see
/// soft-deleted rows too, to revoke them immediately rather than
/// waiting for the next full scan.
#[derive(QueryableByName, Debug)]
struct DbUserChangeRow {
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = Text)]
    username: String,
    #[diesel(sql_type = Text)]
    password: String,
    #[diesel(sql_type = Nullable<Text>)]
    otpkey: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    deleted: bool,
}

/// One row from the incremental scan, distinguishing an active
/// create/update from a soft-deletion — see `load_recently_changed_users`.
pub enum DbUserChange {
    Upserted(User),
    Deleted { username: String },
}

/// A username from `deleted_users_log` (populated by the trigger on a
/// hard `DELETE FROM users`).
#[derive(QueryableByName, Debug)]
struct DeletedLogRow {
    #[diesel(sql_type = Text)]
    username: String,
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
                            otpkey TEXT,
                            created_at TIMESTAMP NOT NULL DEFAULT now(),
                            modified_at TIMESTAMP NOT NULL DEFAULT now(),
                            deleted BOOLEAN NOT NULL DEFAULT FALSE
            )",
            )
            .map_err(|e| format!("Failed to create users table (postgres): {e}"))?;

            // Index supporting the incremental scan's `WHERE modified_at
            // >= $cutoff` — without it, that query degrades to a full
            // table scan anyway, defeating the point.
            c.batch_execute(
                "CREATE INDEX IF NOT EXISTS idx_users_modified_at ON users (modified_at)",
            )
            .map_err(|e| format!("Failed to create users.modified_at index (postgres): {e}"))?;

            // Migration for installs from before created_at/modified_at/
            // deleted existed: CREATE TABLE IF NOT EXISTS above is a
            // no-op on an already-existing `users` table, so add the
            // columns here, explicitly, if missing. Postgres supports
            // `IF NOT EXISTS` on ADD COLUMN directly (9.6+), so this is
            // safe to re-run every startup.
            c.batch_execute(
                "ALTER TABLE users
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT now(),
                            ADD COLUMN IF NOT EXISTS modified_at TIMESTAMP NOT NULL DEFAULT now(),
                            ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE",
            )
            .map_err(|e| {
                format!("Failed to migrate users.created_at/modified_at/deleted (postgres): {e}")
            })?;

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

            // Log of hard-deletions, populated by a trigger (below) —
            // lets the incremental scan detect a raw `DELETE FROM users`
            // (bypassing the app's soft-delete convention) within a
            // bounded time window too, instead of needing a full-table
            // scan to notice a row is simply gone.
            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS deleted_users_log (
                    id BIGSERIAL PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                            deleted_at TIMESTAMP NOT NULL DEFAULT now()
            )",
            )
            .map_err(|e| format!("Failed to create deleted_users_log table (postgres): {e}"))?;

            c.batch_execute(
                "CREATE INDEX IF NOT EXISTS idx_deleted_users_log_deleted_at
                ON deleted_users_log (deleted_at)",
            )
            .map_err(|e| {
                format!("Failed to create deleted_users_log index (postgres): {e}")
            })?;

            c.batch_execute(
                "CREATE OR REPLACE FUNCTION log_deleted_user() RETURNS TRIGGER AS $$
                BEGIN
                INSERT INTO deleted_users_log (username) VALUES (OLD.username);
            RETURN OLD;
            END;
            $$ LANGUAGE plpgsql",
            )
            .map_err(|e| format!("Failed to create log_deleted_user() function (postgres): {e}"))?;

            // Re-created on every startup (drop then create) to stay
            // idempotent — Postgres has no `CREATE TRIGGER IF NOT
            // EXISTS` on versions this targets.
            c.batch_execute("DROP TRIGGER IF EXISTS trg_log_user_delete ON users")
            .map_err(|e| format!("Failed to drop trg_log_user_delete (postgres): {e}"))?;
            c.batch_execute(
                "CREATE TRIGGER trg_log_user_delete
                AFTER DELETE ON users
                FOR EACH ROW EXECUTE FUNCTION log_deleted_user()",
            )
            .map_err(|e| format!("Failed to create trg_log_user_delete (postgres): {e}"))?;

            Ok(())
        }
        DbConnection::MySql(c) => {
            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS users (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                            password TEXT NOT NULL,
                            otpkey TEXT,
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
                            deleted BOOLEAN NOT NULL DEFAULT FALSE,
                            INDEX idx_users_modified_at (modified_at)
            )",
            )
            .map_err(|e| format!("Failed to create users table (mysql): {e}"))?;

            // Migration for installs from before created_at/modified_at/
            // deleted existed. Unlike Postgres, `ADD COLUMN IF NOT
            // EXISTS` isn't reliably available across every MySQL/
            // MariaDB version this targets, so attempt the ALTER
            // unconditionally and treat a "duplicate column" error
            // (already migrated) as success.
            for stmt in [
                "ALTER TABLE users ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
                "ALTER TABLE users ADD COLUMN modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
                "ALTER TABLE users ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT FALSE",
                "ALTER TABLE users ADD INDEX idx_users_modified_at (modified_at)",
            ] {
                if let Err(e) = c.batch_execute(stmt) {
                    let msg = e.to_string().to_lowercase();
                    let already_there = msg.contains("duplicate column")
                    || msg.contains("duplicate key name")
                    || msg.contains("already exists");
                    if !already_there {
                        return Err(format!(
                            "Failed to migrate users.created_at/modified_at/deleted (mysql): {e}"
                        ));
                    }
                }
            }

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

            // Log of hard-deletions, populated by a trigger (below) —
            // lets the incremental scan detect a raw `DELETE FROM users`
            // (bypassing the app's soft-delete convention) within a
            // bounded time window too, instead of needing a full-table
            // scan to notice a row is simply gone.
            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS deleted_users_log (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                            deleted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_deleted_users_log_deleted_at (deleted_at)
            )",
            )
            .map_err(|e| format!("Failed to create deleted_users_log table (mysql): {e}"))?;

            // Re-created on every startup (drop then create) to stay
            // idempotent — MySQL/MariaDB has no reliable `CREATE
            // TRIGGER IF NOT EXISTS` across every targeted version.
            c.batch_execute("DROP TRIGGER IF EXISTS trg_log_user_delete")
            .map_err(|e| format!("Failed to drop trg_log_user_delete (mysql): {e}"))?;
            c.batch_execute(
                "CREATE TRIGGER trg_log_user_delete
                AFTER DELETE ON users
                FOR EACH ROW
                INSERT INTO deleted_users_log (username) VALUES (OLD.username)",
            )
            .map_err(|e| format!("Failed to create trg_log_user_delete (mysql): {e}"))?;

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
            sql_query("SELECT id, username, password, otpkey FROM users WHERE deleted = FALSE")
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
            sql_query("SELECT id, username, password, otpkey FROM users WHERE deleted = FALSE")
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
///
/// If a soft-deleted row with this username already exists (see
/// `mark_user_deleted`), this revives it: `deleted` is reset to
/// `FALSE` along with the fresh password/otpkey, so `db-add-user` on a
/// previously deleted username brings the account back rather than
/// silently leaving it revoked underneath new-looking data.
fn upsert_user_row(conn: &mut DbConnection, user: &User) -> Result<i64, String> {
    match conn {
        DbConnection::Postgres(c) => {
            let row: IdRow = sql_query(
                "INSERT INTO users (username, password, otpkey)
            VALUES ($1, $2, $3)
            ON CONFLICT (username) DO UPDATE SET
            password = EXCLUDED.password,
            otpkey = EXCLUDED.otpkey,
            deleted = FALSE,
            modified_at = now()
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
            // modified_at needs no explicit value here — the column's
            // `ON UPDATE CURRENT_TIMESTAMP` fires automatically whenever
            // this UPDATE branch of ON DUPLICATE KEY runs.
            sql_query(
                "INSERT INTO users (username, password, otpkey)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
            password = VALUES(password),
                      otpkey = VALUES(otpkey),
                      deleted = FALSE,
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
///
/// If `username` matches a previously soft-deleted row, it's revived
/// (`deleted` reset to `FALSE`) rather than left revoked underneath the
/// new data — see `upsert_user_row`.
pub fn upsert_user(conn: &mut DbConnection, user: &User) -> Result<(), String> {
    let user_id = upsert_user_row(conn, user)?;
    replace_user_allow(conn, user_id, user.allow.as_deref())?;
    replace_user_roles(conn, user_id, user.roles.as_deref())?;
    Ok(())
}

/// Soft-deletes a user: sets `deleted = TRUE` (and bumps `modified_at`)
/// instead of running `DELETE FROM users`. This is what makes deletion
/// visible to the incremental scan — a hard `DELETE` leaves no row for a
/// `WHERE modified_at >= cutoff` query to find, but an UPDATE does. The
/// row physically stays in place until `purge_deleted_users` reaps it
/// after `deleted_retention_secs` (see `DatabaseConfig`). Returns `Ok(())`
/// even if the username didn't exist (nothing to do).
pub fn mark_user_deleted(conn: &mut DbConnection, username: &str) -> Result<(), String> {
    match conn {
        DbConnection::Postgres(c) => {
            sql_query("UPDATE users SET deleted = TRUE, modified_at = now() WHERE username = $1")
            .bind::<Text, _>(username)
            .execute(c)
            .map_err(|e| format!("Failed to soft-delete user (postgres): {e}"))?;
        }
        DbConnection::MySql(c) => {
            // No explicit modified_at needed — ON UPDATE CURRENT_TIMESTAMP
            // fires automatically for this UPDATE.
            sql_query("UPDATE users SET deleted = TRUE WHERE username = ?")
            .bind::<Text, _>(username)
            .execute(c)
            .map_err(|e| format!("Failed to soft-delete user (mysql): {e}"))?;
        }
    }
    Ok(())
}

/// Permanently removes users that have been soft-deleted for at least
/// `retention_secs`. Meant to be called periodically (any single
/// instance running it is enough — a `DELETE` of already-gone rows on a
/// second instance is simply a no-op, so this is safe to run
/// redundantly from more than one). `ON DELETE CASCADE` on
/// `user_allow`/`user_roles` cleans up the child rows automatically.
/// Returns the number of rows actually deleted.
pub fn purge_deleted_users(conn: &mut DbConnection, retention_secs: i64) -> Result<u64, String> {
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(retention_secs);
    match conn {
        DbConnection::Postgres(c) => {
            sql_query("DELETE FROM users WHERE deleted = TRUE AND modified_at < $1")
            .bind::<Timestamp, _>(cutoff)
            .execute(c)
            .map(|n| n as u64)
            .map_err(|e| format!("Failed to purge deleted users (postgres): {e}"))
        }
        DbConnection::MySql(c) => {
            sql_query("DELETE FROM users WHERE deleted = TRUE AND modified_at < ?")
            .bind::<Timestamp, _>(cutoff)
            .execute(c)
            .map(|n| n as u64)
            .map_err(|e| format!("Failed to purge deleted users (mysql): {e}"))
        }
    }
}

/// Trims `deleted_users_log` entries older than `retention_secs` — the
/// log would otherwise grow forever. Note: `purge_deleted_users` above
/// itself fires the delete trigger, so purging soft-deleted rows adds a
/// few more entries here too; harmless, just something to keep in mind
/// when reading row counts.
pub fn purge_deletion_log(conn: &mut DbConnection, retention_secs: i64) -> Result<u64, String> {
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(retention_secs);
    match conn {
        DbConnection::Postgres(c) => sql_query("DELETE FROM deleted_users_log WHERE deleted_at < $1")
        .bind::<Timestamp, _>(cutoff)
        .execute(c)
        .map(|n| n as u64)
        .map_err(|e| format!("Failed to purge deleted_users_log (postgres): {e}")),
        DbConnection::MySql(c) => sql_query("DELETE FROM deleted_users_log WHERE deleted_at < ?")
        .bind::<Timestamp, _>(cutoff)
        .execute(c)
        .map(|n| n as u64)
        .map_err(|e| format!("Failed to purge deleted_users_log (mysql): {e}")),
    }
}

/// Connects and soft-deletes a user by username. Errors are logged, not
/// panicked — consistent with the rest of this module's "never take
/// down the caller" style, but note this one has a real side effect
/// (unlike the read-only `load_*_from_config` helpers), so callers that
/// need to know whether it actually happened should check the return.
pub fn mark_user_deleted_in_config(cfg: &DatabaseConfig, username: &str) -> Result<(), String> {
    let mut conn = connect(cfg)?;
    ensure_schema(&mut conn)?;
    mark_user_deleted(&mut conn, username)
}

/// Loads the users whose `modified_at` falls at or after `cutoff` — the
/// incremental counterpart to `load_users`, used for frequent refreshes
/// so the query cost scales with *recent changes*, not total row count.
///
/// Unlike `load_users`, this does **not** filter out `deleted = TRUE`
/// rows — a soft-deletion is itself a `modified_at`-bumping UPDATE, so
/// it naturally falls inside the scanned window. It also merges in
/// hard-deletions from `deleted_users_log` (see `load_recent_deletions`)
/// — populated by a trigger, so a raw `DELETE FROM users` run outside
/// the app's normal soft-delete flow is *also* caught within a bounded
/// window, instead of needing the slower full-table scan. Either kind
/// comes back as `DbUserChange::Deleted`; the caller doesn't need to
/// care which one it was.
pub fn load_recently_changed_users(
    conn: &mut DbConnection,
    cutoff: NaiveDateTime,
) -> Result<Vec<DbUserChange>, String> {
    let rows: Vec<DbUserChangeRow> = match conn {
        DbConnection::Postgres(c) => sql_query(
            "SELECT id, username, password, otpkey, deleted FROM users WHERE modified_at >= $1",
        )
        .bind::<Timestamp, _>(cutoff)
        .load(c)
        .map_err(|e| format!("Failed to load recently changed users (postgres): {e}"))?,
        DbConnection::MySql(c) => sql_query(
            "SELECT id, username, password, otpkey, deleted FROM users WHERE modified_at >= ?",
        )
        .bind::<Timestamp, _>(cutoff)
        .load(c)
        .map_err(|e| format!("Failed to load recently changed users (mysql): {e}"))?,
    };

    // Small, bounded set (bounded by how many users changed in the
    // window) — a per-id lookup for allow/roles here is cheap and keeps
    // things portable without relying on backend-specific array binds
    // (Postgres `= ANY($1)` vs MySQL `IN (...)`) for a WHERE-IN clause.
    let mut changes = Vec::with_capacity(rows.len());
    for row in rows {
        if row.deleted {
            changes.push(DbUserChange::Deleted {
                username: row.username,
            });
            continue;
        }

        let allow = load_values_for_user(conn, "user_allow", "cidr", row.id)?;
        let roles = load_values_for_user(conn, "user_roles", "role", row.id)?;
        changes.push(DbUserChange::Upserted(User {
            username: row.username,
            password: row.password,
            otpkey: row.otpkey,
            allow: if allow.is_empty() { None } else { Some(allow) },
                                            roles: if roles.is_empty() { None } else { Some(roles) },
                                            email: None,
        }));
    }

    for username in load_recent_deletions(conn, cutoff)? {
        changes.push(DbUserChange::Deleted { username });
    }

    Ok(changes)
}

/// Reads usernames hard-deleted (`DELETE FROM users`) at or after
/// `cutoff`, from `deleted_users_log` (populated by a trigger — see
/// `ensure_schema`). May return the same username more than once if it
/// was deleted, re-created, and deleted again within the window;
/// callers revoking by username handle that fine (idempotent).
fn load_recent_deletions(conn: &mut DbConnection, cutoff: NaiveDateTime) -> Result<Vec<String>, String> {
    match conn {
        DbConnection::Postgres(c) => {
            sql_query("SELECT username FROM deleted_users_log WHERE deleted_at >= $1")
            .bind::<Timestamp, _>(cutoff)
            .load::<DeletedLogRow>(c)
            .map(|rows| rows.into_iter().map(|r| r.username).collect())
            .map_err(|e| format!("Failed to load deleted_users_log (postgres): {e}"))
        }
        DbConnection::MySql(c) => {
            sql_query("SELECT username FROM deleted_users_log WHERE deleted_at >= ?")
            .bind::<Timestamp, _>(cutoff)
            .load::<DeletedLogRow>(c)
            .map(|rows| rows.into_iter().map(|r| r.username).collect())
            .map_err(|e| format!("Failed to load deleted_users_log (mysql): {e}"))
        }
    }
}

/// Fetches all `value` entries for one user from a child table
/// (`user_allow`/`user_roles`), by raw `user_id`. `table`/`column` are
/// always one of the two hardcoded call sites below — never user input —
/// so building the query string with them is safe.
fn load_values_for_user(
    conn: &mut DbConnection,
    table: &str,
    column: &str,
    user_id: i64,
) -> Result<Vec<String>, String> {
    let query = format!("SELECT {column} AS value FROM {table} WHERE user_id = ");
    match conn {
        DbConnection::Postgres(c) => sql_query(format!("{query}$1"))
        .bind::<BigInt, _>(user_id)
        .load::<UserIdValueRow>(c)
        .map(|rows| rows.into_iter().map(|r| r.value).collect())
        .map_err(|e| format!("Failed to load {table} for user (postgres): {e}")),
        DbConnection::MySql(c) => sql_query(format!("{query}?"))
        .bind::<BigInt, _>(user_id)
        .load::<UserIdValueRow>(c)
        .map(|rows| rows.into_iter().map(|r| r.value).collect())
        .map_err(|e| format!("Failed to load {table} for user (mysql): {e}")),
    }
}

/// Connects, ensures the schema exists, and returns only the changes
/// (creates/updates and soft-deletions) within the last `window_secs`
/// seconds — the incremental counterpart to `load_users_from_config`.
/// Same failure behavior: returns an empty Vec (logged, never a panic)
/// so a DB outage doesn't affect file-based `users`.
pub fn load_recently_changed_from_config(
    cfg: &DatabaseConfig,
    window_secs: i64,
) -> Vec<DbUserChange> {
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

    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(window_secs);

    match load_recently_changed_users(&mut conn, cutoff) {
        Ok(changes) => changes,
        Err(e) => {
            eprintln!("[databases] {e}");
            Vec::new()
        }
    }
}

/// Connects, ensures the schema exists, and purges users that have been
/// soft-deleted for at least `retention_secs`. Logs and returns 0 on
/// any failure rather than panicking, consistent with the rest of this
/// module.
pub fn purge_deleted_users_in_config(cfg: &DatabaseConfig, retention_secs: i64) -> u64 {
    let mut conn = match connect(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[databases] {e}");
            return 0;
        }
    };

    if let Err(e) = ensure_schema(&mut conn) {
        eprintln!("[databases] {e}");
        return 0;
    }

    match purge_deleted_users(&mut conn, retention_secs) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[databases] {e}");
            0
        }
    }
}

/// Connects, ensures the schema exists, and trims `deleted_users_log`
/// entries older than `retention_secs`. Same failure behavior as
/// `purge_deleted_users_in_config`.
pub fn purge_deletion_log_in_config(cfg: &DatabaseConfig, retention_secs: i64) -> u64 {
    let mut conn = match connect(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[databases] {e}");
            return 0;
        }
    };

    if let Err(e) = ensure_schema(&mut conn) {
        eprintln!("[databases] {e}");
        return 0;
    }

    match purge_deletion_log(&mut conn, retention_secs) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[databases] {e}");
            0
        }
    }
}

/// Connects, ensures the schema exists, and returns the users currently
/// stored in the database. Returns an empty Vec (with a logged warning,
/// never a panic) on any failure, so a DB outage doesn't take the whole
/// proxy down — file-based `users` in config.json still work.
/// Connects, ensures the schema exists, and returns the users currently
/// stored in the database. Returns `None` — distinct from `Some(vec![])`
/// — on any connection/query failure, so callers can tell "the database
/// is unreachable, don't touch what I already know" apart from "the
/// database answered and genuinely has zero users right now". Confusing
/// the two used to be a real bug: `refresh_db_users` treated an empty
/// result as "every user was deleted" and revoked all of them on a
/// transient DB outage — a five-second network blip could log out an
/// entire user base. See `AppConfig::refresh_db_users`.
///
/// On success, the result is also cached to a local LMDB store (see
/// `cache` module) so that if the database is unreachable on a later
/// *startup* — not just a mid-session outage — ProxyAuth can still come
/// up with the last known set of database-backed users instead of zero,
/// falling back to that cache below when the database itself fails.
pub fn load_users_from_config(cfg: &DatabaseConfig) -> Option<Vec<User>> {
    let mut conn = match connect(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[databases] {e}");
            return cache::read_snapshot_with_fallback_log();
        }
    };

    if let Err(e) = ensure_schema(&mut conn) {
        eprintln!("[databases] {e}");
        return cache::read_snapshot_with_fallback_log();
    }

    match load_users(&mut conn) {
        Ok(users) => {
            if let Err(e) = cache::write_snapshot(&users) {
                eprintln!("[databases] failed to update local cache: {e}");
            }
            Some(users)
        }
        Err(e) => {
            eprintln!("[databases] {e}");
            cache::read_snapshot_with_fallback_log()
        }
    }
}
