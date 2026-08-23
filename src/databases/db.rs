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

use crate::config::config::{DatabaseConfig, EmailEntry, User};
use crate::databases::cache;
use chrono::NaiveDateTime;
use diesel::connection::SimpleConnection;
use diesel::mysql::MysqlConnection;
use diesel::pg::PgConnection;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamp};
use diesel::{Connection, OptionalExtension, QueryableByName, RunQueryDsl, sql_query};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

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
    #[diesel(sql_type = diesel::sql_types::Bool)]
    must_change_password: bool,
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
    #[diesel(sql_type = diesel::sql_types::Bool)]
    must_change_password: bool,
}

/// One row from the incremental scan, distinguishing an active
/// create/update from a soft-deletion — see `load_recently_changed_users`.
pub enum DbUserChange {
    Upserted(User),
    Deleted { username: String },
}

/// The result of `load_users_from_config`, distinguishing a fresh read
/// of the real database from a fallback to the local LMDB cache.
///
/// This distinction matters for correctness, not just diagnostics:
/// `AppConfig::refresh_db_users` uses "is this username absent from the
/// list I just got?" to decide who to revoke. That's only safe to do
/// against a list that's actually current. The cache is only refreshed
/// on a successful *full* scan — if the database goes down again before
/// the next one, and a user was created via the (more frequent)
/// incremental scan in between, that user exists in RAM but wouldn't
/// exist in the stale cached snapshot — comparing against it would
/// incorrectly revoke a user who was never deleted. So a `Cache` result
/// is only ever upserted, never used for absence-based revocation;
/// only a genuine `Database` result is.
pub enum UsersSource {
    Database(Vec<User>),
    Cache(Vec<User>),
}

impl UsersSource {
    pub fn users(&self) -> &[User] {
        match self {
            UsersSource::Database(u) | UsersSource::Cache(u) => u,
        }
    }
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

/// Same idea as `UserIdValueRow`, but for `user_email` specifically —
/// that table has a second column (`is_primary`) the generic
/// single-value helper can't carry.
#[derive(QueryableByName, Debug)]
struct UserEmailRow {
    #[diesel(sql_type = BigInt)]
    user_id: i64,
    #[diesel(sql_type = Text)]
    address: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_primary: bool,
}

#[derive(QueryableByName, Debug)]
struct IdRow {
    #[diesel(sql_type = BigInt)]
    id: i64,
}

/// Bounds how many abandoned connection-attempt threads can be alive at
/// once (see `connect` below) — without this, a database that stays
/// unreachable for a while causes these to accumulate faster than they
/// naturally resolve, since a new attempt starts every scan tick (as
/// often as every 30s) while an abandoned one can take much longer
/// than `connect_timeout_secs` to actually finish in the background
/// (bounded only by the OS's own TCP timeout, often 30-130s+). Past
/// enough accumulated threads, this was observed to make the whole
/// process slow to respond to SIGTERM again — the exact problem
/// `connect_timeout_secs` was meant to solve, just re-introduced by a
/// pile of abandoned attempts instead of one long one.
static INFLIGHT_CONNECT_ATTEMPTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const MAX_INFLIGHT_CONNECT_ATTEMPTS: usize = 3;

/// Opens a connection to the database described by `cfg`.
///
/// Bounded to `cfg.connect_timeout_secs` (default 5s), via `connect_inner`
/// running on its own OS thread while this function waits on a channel
/// with a timeout — not just a URL-level timeout parameter, because
/// that approach doesn't work uniformly: Postgres's libpq honors a
/// `connect_timeout=N` query parameter, but MySQL/MariaDB's client
/// library (as used through Diesel) does **not** — verified empirically
/// (a stuck-server connection attempt with `connect_timeout=3` in the
/// URL still hung indefinitely for MySQL). This wrapper works the same
/// way regardless of backend, so `connect()` never blocks its caller
/// longer than the configured timeout either way.
///
/// If the timeout elapses, the spawned thread is abandoned — it keeps
/// trying in the background until its own eventual OS-level timeout.
/// `INFLIGHT_CONNECT_ATTEMPTS` caps how many such abandoned attempts
/// can pile up at once: if the cap is already reached, this returns an
/// error immediately without spawning yet another one, rather than
/// letting them accumulate unbounded while the database stays down.
pub fn connect(cfg: &DatabaseConfig) -> Result<DbConnection, String> {
    use std::sync::atomic::Ordering;

    if INFLIGHT_CONNECT_ATTEMPTS.load(Ordering::Acquire) >= MAX_INFLIGHT_CONNECT_ATTEMPTS {
        return Err(format!(
            "Too many database connection attempts already in progress (limit: {MAX_INFLIGHT_CONNECT_ATTEMPTS}) — the database has likely been unreachable for a while; skipping this attempt rather than piling on another one"
        ));
    }

    let timeout = std::time::Duration::from_secs(cfg.connect_timeout_secs.max(1));
    let cfg_owned = cfg.clone();
    let (tx, rx) = std::sync::mpsc::channel();

    INFLIGHT_CONNECT_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
    std::thread::spawn(move || {
        let result = connect_inner(&cfg_owned);
        // The receiver may already be gone (we timed out and moved on)
        // — that's fine, .send() just fails silently in that case.
        let _ = tx.send(result);
        INFLIGHT_CONNECT_ATTEMPTS.fetch_sub(1, Ordering::AcqRel);
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Err(format!(
            "Database connection attempt did not complete within {}s — giving up (the database may be unreachable, or the connect_timeout_secs setting may need adjusting for your network)",
            timeout.as_secs()
        )),
    }
}

fn connect_inner(cfg: &DatabaseConfig) -> Result<DbConnection, String> {
    match cfg.db_type.to_lowercase().as_str() {
        "postgres" | "postgresql" | "pg" => {
            let url = format!(
                "postgres://{}:{}@{}:{}/{}?connect_timeout={}",
                cfg.user,
                cfg.password,
                cfg.host,
                cfg.effective_port(),
                cfg.db_name,
                cfg.connect_timeout_secs.max(1),
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

/// The one, process-lifetime database connection — established on
/// first use, then reused for every subsequent operation instead of
/// reconnecting each time. `None` means "not connected right now"
/// (either never connected yet, or the last operation on it failed and
/// it was dropped so the next call reconnects from scratch).
static DB_CONNECTION: OnceLock<Mutex<Option<DbConnection>>> = OnceLock::new();

fn db_connection_slot() -> &'static Mutex<Option<DbConnection>> {
    DB_CONNECTION.get_or_init(|| Mutex::new(None))
}

/// Runs `f` against the single shared, persistent database connection —
/// connecting first if this is the very first call, or if the
/// connection was dropped after a previous call's operation failed.
/// Every caller in this module (the periodic scans, the CLI commands,
/// `reset_password_route`'s DB write) goes through this instead of
/// calling `connect()` directly and opening its own short-lived
/// connection, so the database sees one long-lived connection over the
/// process's lifetime rather than a fresh one per operation.
///
/// Deliberately simple about *when* to reconnect: any `Err` from `f` —
/// not just ones that look connection-related — drops the stored
/// connection, so the next call starts fresh. This can occasionally
/// reconnect after an error that didn't strictly need it (e.g. a
/// constraint violation on a perfectly healthy connection), but that's
/// a minor inefficiency, not a correctness problem — distinguishing
/// "the connection itself died" from "the query failed for a data
/// reason" would mean parsing Diesel's error variants (this module
/// already converts everything to `String` well before this point, so
/// that distinction isn't available here without a larger refactor).
///
/// A `Mutex` around a single connection means database operations are
/// serialized process-wide — only one can run at a time. For
/// ProxyAuth's actual DB workload (periodic scans a few times a
/// minute, occasional CLI/admin use, occasional password resets)
/// that's an acceptable, deliberate trade-off in exchange for a
/// simple, well-understood connection lifecycle; a connection pool
/// (e.g. `diesel::r2d2`) would allow genuine concurrency at the cost
/// of more moving parts, if that's ever needed.
pub fn with_connection<T>(
    cfg: &DatabaseConfig,
    f: impl FnOnce(&mut DbConnection) -> Result<T, String>,
) -> Result<T, String> {
    let slot = db_connection_slot();
    let mut guard = match slot.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            // A previous operation panicked while holding this lock —
            // recover by taking the guard anyway (its *contents* — an
            // Option<DbConnection> — are still perfectly usable data,
            // a panic doesn't corrupt them) and force a reconnect,
            // rather than letting one panic permanently break all
            // future database access for the rest of the process.
            let mut g = poisoned.into_inner();
            *g = None;
            g
        }
    };

    if guard.is_none() {
        *guard = Some(connect(cfg)?);
    }

    // Safe: the branch above guarantees Some at this point.
    let conn = guard.as_mut().expect("connection slot just set to Some");

    match f(conn) {
        Ok(value) => Ok(value),
        Err(e) => {
            *guard = None;
            Err(e)
        }
    }
}

/// Once `ensure_schema` has run successfully in this process, every DDL
/// step (table/index/trigger creation, migrations) is skipped on later
/// calls — the schema doesn't change after the first time, and calling
/// it on every scan tick (every 30s by default) was needlessly racy:
/// concurrent calls (from the incremental scan, the full scan, the
/// purge task, all running independently) could interleave their
/// DROP TRIGGER/CREATE TRIGGER pairs, briefly leaving the deletion
/// trigger absent or spuriously failing with "already exists" —
/// which `load_users_from_config` would then misread as the database
/// being unreachable and fall back to the local cache for no real
/// reason. Process-local (not persisted), so a fresh process still
/// runs it once at its own startup.
static SCHEMA_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Creates `users`, `user_allow` and `user_roles` if they don't exist yet.
/// Safe to call on every startup — and cheap to call repeatedly after
/// that too, since it does nothing once `SCHEMA_READY` is set (see
/// above) rather than re-running DDL every time.
pub fn ensure_schema(conn: &mut DbConnection) -> Result<(), String> {
    if SCHEMA_READY.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }

    ensure_schema_inner(conn)?;

    SCHEMA_READY.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

fn ensure_schema_inner(conn: &mut DbConnection) -> Result<(), String> {
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
                            deleted BOOLEAN NOT NULL DEFAULT FALSE,
                            must_change_password BOOLEAN NOT NULL DEFAULT FALSE
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
            // deleted/must_change_password existed: CREATE TABLE IF NOT
            // EXISTS above is a no-op on an already-existing `users`
            // table, so add the columns here, explicitly, if missing.
            // Postgres supports `IF NOT EXISTS` on ADD COLUMN directly
            // (9.6+), so this is safe to re-run every startup.
            c.batch_execute(
                "ALTER TABLE users
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT now(),
                            ADD COLUMN IF NOT EXISTS modified_at TIMESTAMP NOT NULL DEFAULT now(),
                            ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
                            ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE",
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

            // `group` is a reserved word in both Postgres and MySQL
            // (used by GROUP BY) — the column/table below is named
            // `group_name`/`groups` to sidestep needing to quote it
            // everywhere, and `groups` is a genuine parent table
            // (with a real FK from `user_groups.group_id`) rather than
            // a free-text column repeated on every membership row —
            // a typo in a group name on one user's row can't silently
            // create a phantom group no route will ever match, and
            // renaming a group is a one-row UPDATE instead of a
            // mass-update across every member.
            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS groups (
                    id BIGSERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL UNIQUE
            )",
            )
            .map_err(|e| format!("Failed to create groups table (postgres): {e}"))?;

            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS user_groups (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                            UNIQUE (user_id, group_id)
            )",
            )
            .map_err(|e| format!("Failed to create user_groups table (postgres): {e}"))?;

            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS user_email (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            email TEXT NOT NULL,
                            is_primary BOOLEAN NOT NULL DEFAULT FALSE
            )",
            )
            .map_err(|e| format!("Failed to create user_email table (postgres): {e}"))?;

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
            .map_err(|e| format!("Failed to create deleted_users_log index (postgres): {e}"))?;

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
            // EXISTS` on versions this targets. If a concurrent call
            // (another scan tick, another instance) recreates it
            // between our DROP and CREATE, treat "already exists" as
            // success rather than a hard failure — the trigger being
            // present is all we actually care about.
            c.batch_execute("DROP TRIGGER IF EXISTS trg_log_user_delete ON users")
                .map_err(|e| format!("Failed to drop trg_log_user_delete (postgres): {e}"))?;
            if let Err(e) = c.batch_execute(
                "CREATE TRIGGER trg_log_user_delete
                AFTER DELETE ON users
                FOR EACH ROW EXECUTE FUNCTION log_deleted_user()",
            ) {
                let msg = e.to_string().to_lowercase();
                if !msg.contains("already exists") {
                    return Err(format!(
                        "Failed to create trg_log_user_delete (postgres): {e}"
                    ));
                }
            }

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
                            must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
                            INDEX idx_users_modified_at (modified_at)
            )",
            )
            .map_err(|e| format!("Failed to create users table (mysql): {e}"))?;

            // Migration for installs from before created_at/modified_at/
            // deleted/must_change_password existed. Unlike Postgres,
            // `ADD COLUMN IF NOT EXISTS` isn't reliably available
            // across every MySQL/MariaDB version this targets, so
            // attempt the ALTER unconditionally and treat a "duplicate
            // column" error (already migrated) as success.
            for stmt in [
                "ALTER TABLE users ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
                "ALTER TABLE users ADD COLUMN modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
                "ALTER TABLE users ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT FALSE",
                "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE",
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

            // See the matching comment in the postgres branch above for
            // why `groups` is a real parent table with a genuine FK,
            // not a free-text column repeated per membership row.
            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS groups (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL UNIQUE
            )",
            )
            .map_err(|e| format!("Failed to create groups table (mysql): {e}"))?;

            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS user_groups (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    group_id BIGINT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                    UNIQUE KEY uq_user_group (user_id, group_id)
            )",
            )
            .map_err(|e| format!("Failed to create user_groups table (mysql): {e}"))?;

            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS user_email (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    email TEXT NOT NULL,
                    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",
            )
            .map_err(|e| format!("Failed to create user_email table (mysql): {e}"))?;

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
            // TRIGGER IF NOT EXISTS` across every targeted version. If
            // a concurrent call (another scan tick, another instance)
            // recreates it between our DROP and CREATE, treat "already
            // exists" as success rather than a hard failure — the
            // trigger being present is all we actually care about.
            c.batch_execute("DROP TRIGGER IF EXISTS trg_log_user_delete")
                .map_err(|e| format!("Failed to drop trg_log_user_delete (mysql): {e}"))?;
            if let Err(e) = c.batch_execute(
                "CREATE TRIGGER trg_log_user_delete
                AFTER DELETE ON users
                FOR EACH ROW
                INSERT INTO deleted_users_log (username) VALUES (OLD.username)",
            ) {
                let msg = e.to_string().to_lowercase();
                if !msg.contains("already exists") {
                    return Err(format!("Failed to create trg_log_user_delete (mysql): {e}"));
                }
            }

            Ok(())
        }
    }
}

/// Loads every user, along with their `allow`, `roles`, and `groups`
/// rows (queries joined in memory — keeps the raw SQL portable across
/// both backends without relying on backend-specific aggregate functions
/// like `string_agg`/`GROUP_CONCAT`).
pub fn load_users(conn: &mut DbConnection) -> Result<Vec<User>, String> {
    let (user_rows, allow_rows, role_rows, group_rows, email_rows): (
        Vec<DbUserRow>,
        Vec<UserIdValueRow>,
        Vec<UserIdValueRow>,
        Vec<UserIdValueRow>,
        Vec<UserEmailRow>,
    ) = match conn {
        DbConnection::Postgres(c) => (
            sql_query("SELECT id, username, password, otpkey, must_change_password FROM users WHERE deleted = FALSE")
            .load(c)
            .map_err(|e| format!("Failed to load users (postgres): {e}"))?,
                                      sql_query("SELECT user_id, cidr AS value FROM user_allow")
                                      .load(c)
                                      .map_err(|e| format!("Failed to load user_allow (postgres): {e}"))?,
                                      sql_query("SELECT user_id, role AS value FROM user_roles")
                                      .load(c)
                                      .map_err(|e| format!("Failed to load user_roles (postgres): {e}"))?,
                                      sql_query("SELECT user_groups.user_id, groups.name AS value FROM user_groups JOIN groups ON groups.id = user_groups.group_id")
                                      .load(c)
                                      .map_err(|e| format!("Failed to load user_groups (postgres): {e}"))?,
                                      sql_query("SELECT user_id, email AS address, is_primary FROM user_email")
                                      .load(c)
                                      .map_err(|e| format!("Failed to load user_email (postgres): {e}"))?,
        ),
        DbConnection::MySql(c) => (
            sql_query("SELECT id, username, password, otpkey, must_change_password FROM users WHERE deleted = FALSE")
            .load(c)
            .map_err(|e| format!("Failed to load users (mysql): {e}"))?,
                                   sql_query("SELECT user_id, cidr AS value FROM user_allow")
                                   .load(c)
                                   .map_err(|e| format!("Failed to load user_allow (mysql): {e}"))?,
                                   sql_query("SELECT user_id, role AS value FROM user_roles")
                                   .load(c)
                                   .map_err(|e| format!("Failed to load user_roles (mysql): {e}"))?,
                                   sql_query("SELECT user_groups.user_id, groups.name AS value FROM user_groups JOIN groups ON groups.id = user_groups.group_id")
                                   .load(c)
                                   .map_err(|e| format!("Failed to load user_groups (mysql): {e}"))?,
                                   sql_query("SELECT user_id, email AS address, is_primary FROM user_email")
                                   .load(c)
                                   .map_err(|e| format!("Failed to load user_email (mysql): {e}"))?,
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

    let mut groups_map: HashMap<i64, Vec<String>> = HashMap::new();
    for row in group_rows {
        groups_map.entry(row.user_id).or_default().push(row.value);
    }

    let mut email_map: HashMap<i64, Vec<EmailEntry>> = HashMap::new();
    for row in email_rows {
        email_map.entry(row.user_id).or_default().push(EmailEntry {
            address: row.address,
            primary: row.is_primary,
        });
    }

    Ok(user_rows
        .into_iter()
        .map(|r| User {
            username: r.username,
            password: r.password,
            otpkey: r.otpkey,
            allow: allow_map.remove(&r.id),
            roles: roles_map.remove(&r.id),
            groups: groups_map.remove(&r.id),
            email: email_map.remove(&r.id),
            must_change_password: r.must_change_password,
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
                "INSERT INTO users (username, password, otpkey, must_change_password)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (username) DO UPDATE SET
            password = EXCLUDED.password,
            otpkey = EXCLUDED.otpkey,
            must_change_password = EXCLUDED.must_change_password,
            deleted = FALSE,
            modified_at = now()
            RETURNING id",
            )
            .bind::<Text, _>(&user.username)
            .bind::<Text, _>(&user.password)
            .bind::<Nullable<Text>, _>(&user.otpkey)
            .bind::<diesel::sql_types::Bool, _>(user.must_change_password)
            .get_result(c)
            .map_err(|e| format!("Failed to upsert user (postgres): {e}"))?;
            Ok(row.id)
        }
        DbConnection::MySql(c) => {
            // modified_at needs no explicit value here — the column's
            // `ON UPDATE CURRENT_TIMESTAMP` fires automatically whenever
            // this UPDATE branch of ON DUPLICATE KEY runs.
            sql_query(
                "INSERT INTO users (username, password, otpkey, must_change_password)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
            password = VALUES(password),
                      otpkey = VALUES(otpkey),
                      must_change_password = VALUES(must_change_password),
                      deleted = FALSE,
                      id = LAST_INSERT_ID(id)",
            )
            .bind::<Text, _>(&user.username)
            .bind::<Text, _>(&user.password)
            .bind::<Nullable<Text>, _>(&user.otpkey)
            .bind::<diesel::sql_types::Bool, _>(user.must_change_password)
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

/// Resolves a group name to its `groups.id`, creating the row first if
/// it doesn't exist yet. Idempotent and race-safe under concurrent
/// callers: the upsert-and-return-id is one atomic statement per
/// backend (`ON CONFLICT ... RETURNING` for Postgres,
/// `ON DUPLICATE KEY UPDATE` + `LAST_INSERT_ID()` for MySQL — the
/// standard idiom for "insert or fetch the existing id" there), not a
/// separate SELECT-then-INSERT with a race between them.
fn ensure_group_id(conn: &mut DbConnection, name: &str) -> Result<i64, String> {
    #[derive(QueryableByName)]
    struct IdRow {
        #[diesel(sql_type = BigInt)]
        id: i64,
    }

    match conn {
        DbConnection::Postgres(c) => {
            let row: IdRow = sql_query(
                "INSERT INTO groups (name) VALUES ($1)
                ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
                RETURNING id",
            )
            .bind::<Text, _>(name)
            .get_result(c)
            .map_err(|e| format!("Failed to upsert group '{name}' (postgres): {e}"))?;
            Ok(row.id)
        }
        DbConnection::MySql(c) => {
            sql_query("INSERT INTO groups (name) VALUES (?) ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)")
            .bind::<Text, _>(name)
            .execute(c)
            .map_err(|e| format!("Failed to upsert group '{name}' (mysql): {e}"))?;

            let row: IdRow = sql_query("SELECT LAST_INSERT_ID() AS id")
                .get_result(c)
                .map_err(|e| {
                    format!("Failed to read LAST_INSERT_ID for group '{name}' (mysql): {e}")
                })?;
            Ok(row.id)
        }
    }
}

/// Same as `replace_user_allow`, for `user_groups` — except each value
/// is a group *name*, resolved (or created) to a `groups.id` via
/// `ensure_group_id` first, since `user_groups.group_id` is a real FK
/// rather than a free-text column. Membership rows are only touched
/// once every name has resolved successfully, so a failure partway
/// through (a genuine DB error — group *creation* here can't itself
/// fail on "already exists") leaves the previous membership intact
/// rather than half-updated.
fn replace_user_groups(
    conn: &mut DbConnection,
    user_id: i64,
    values: Option<&[String]>,
) -> Result<(), String> {
    let mut group_ids = Vec::new();
    for name in values.unwrap_or_default() {
        group_ids.push(ensure_group_id(conn, name)?);
    }

    match conn {
        DbConnection::Postgres(c) => {
            sql_query("DELETE FROM user_groups WHERE user_id = $1")
                .bind::<BigInt, _>(user_id)
                .execute(c)
                .map_err(|e| format!("Failed to clear user_groups (postgres): {e}"))?;
            for group_id in &group_ids {
                sql_query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
                    .bind::<BigInt, _>(user_id)
                    .bind::<BigInt, _>(*group_id)
                    .execute(c)
                    .map_err(|e| format!("Failed to insert user_groups (postgres): {e}"))?;
            }
        }
        DbConnection::MySql(c) => {
            sql_query("DELETE FROM user_groups WHERE user_id = ?")
                .bind::<BigInt, _>(user_id)
                .execute(c)
                .map_err(|e| format!("Failed to clear user_groups (mysql): {e}"))?;
            for group_id in &group_ids {
                sql_query("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)")
                    .bind::<BigInt, _>(user_id)
                    .bind::<BigInt, _>(*group_id)
                    .execute(c)
                    .map_err(|e| format!("Failed to insert user_groups (mysql): {e}"))?;
            }
        }
    }
    Ok(())
}

/// Same as `replace_user_allow`, for `user_email`.
/// Same as `replace_user_allow`, for `user_email` — also writes
/// `is_primary` per entry, since `EmailEntry` carries that explicitly
/// rather than relying on list order.
fn replace_user_email(
    conn: &mut DbConnection,
    user_id: i64,
    values: Option<&[EmailEntry]>,
) -> Result<(), String> {
    match conn {
        DbConnection::Postgres(c) => {
            sql_query("DELETE FROM user_email WHERE user_id = $1")
                .bind::<BigInt, _>(user_id)
                .execute(c)
                .map_err(|e| format!("Failed to clear user_email (postgres): {e}"))?;
            for entry in values.unwrap_or_default() {
                sql_query(
                    "INSERT INTO user_email (user_id, email, is_primary) VALUES ($1, $2, $3)",
                )
                .bind::<BigInt, _>(user_id)
                .bind::<Text, _>(&entry.address)
                .bind::<diesel::sql_types::Bool, _>(entry.primary)
                .execute(c)
                .map_err(|e| format!("Failed to insert user_email (postgres): {e}"))?;
            }
        }
        DbConnection::MySql(c) => {
            sql_query("DELETE FROM user_email WHERE user_id = ?")
                .bind::<BigInt, _>(user_id)
                .execute(c)
                .map_err(|e| format!("Failed to clear user_email (mysql): {e}"))?;
            for entry in values.unwrap_or_default() {
                sql_query("INSERT INTO user_email (user_id, email, is_primary) VALUES (?, ?, ?)")
                    .bind::<BigInt, _>(user_id)
                    .bind::<Text, _>(&entry.address)
                    .bind::<diesel::sql_types::Bool, _>(entry.primary)
                    .execute(c)
                    .map_err(|e| format!("Failed to insert user_email (mysql): {e}"))?;
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
///
/// Authoritative, not a merge: `must_change_password` is set to exactly
/// whatever `user.must_change_password` says, every call — including
/// resetting a currently-`true` flag back to `false` if `user` doesn't
/// set it. `db-add-user` (the CLI command backed by this) relies on
/// that: each run represents the account's complete intended state,
/// not a partial patch, so re-running it without
/// `--must-change-password` intentionally clears a pending forced
/// change rather than leaving it dangling from some earlier call.
pub fn upsert_user(conn: &mut DbConnection, user: &User) -> Result<(), String> {
    let user_id = upsert_user_row(conn, user)?;
    replace_user_allow(conn, user_id, user.allow.as_deref())?;
    replace_user_roles(conn, user_id, user.roles.as_deref())?;
    replace_user_groups(conn, user_id, user.groups.as_deref())?;
    replace_user_email(conn, user_id, user.email.as_deref())?;
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

/// Sets a new password for a user (must already be the final stored
/// value — an Argon2 hash, not plaintext) and clears
/// `must_change_password` at the same time, since a completed password
/// change always satisfies it regardless of which flow triggered it
/// (an admin's `reset-password`, or a forced first-login change).
/// Returns `Ok(false)` if no row matched `username` (nothing to do,
/// not an error).
pub fn update_password(
    conn: &mut DbConnection,
    username: &str,
    new_password_hash: &str,
) -> Result<bool, String> {
    let affected = match conn {
        DbConnection::Postgres(c) => sql_query(
            "UPDATE users SET password = $1, must_change_password = FALSE, modified_at = now()
        WHERE username = $2 AND deleted = FALSE",
        )
        .bind::<Text, _>(new_password_hash)
        .bind::<Text, _>(username)
        .execute(c)
        .map_err(|e| format!("Failed to update password (postgres): {e}"))?,
        DbConnection::MySql(c) => sql_query(
            "UPDATE users SET password = ?, must_change_password = FALSE
            WHERE username = ? AND deleted = FALSE",
        )
        .bind::<Text, _>(new_password_hash)
        .bind::<Text, _>(username)
        .execute(c)
        .map_err(|e| format!("Failed to update password (mysql): {e}"))?,
    };
    Ok(affected > 0)
}

/// Fetches a single non-deleted user by username, with its `allow`/
/// `roles`. Used to refresh the in-memory `db_users` snapshot for one
/// user immediately after a write (e.g. `update_password`), without
/// waiting for the next scan tick.
pub fn load_user_by_username(
    conn: &mut DbConnection,
    username: &str,
) -> Result<Option<User>, String> {
    let row: Option<DbUserRow> = match conn {
        DbConnection::Postgres(c) => sql_query(
            "SELECT id, username, password, otpkey, must_change_password FROM users
            WHERE username = $1 AND deleted = FALSE",
        )
        .bind::<Text, _>(username)
        .get_result(c)
        .optional()
        .map_err(|e| format!("Failed to load user '{username}' (postgres): {e}"))?,
        DbConnection::MySql(c) => sql_query(
            "SELECT id, username, password, otpkey, must_change_password FROM users
            WHERE username = ? AND deleted = FALSE",
        )
        .bind::<Text, _>(username)
        .get_result(c)
        .optional()
        .map_err(|e| format!("Failed to load user '{username}' (mysql): {e}"))?,
    };

    let Some(row) = row else {
        return Ok(None);
    };

    let allow = load_values_for_user(conn, "user_allow", "cidr", row.id)?;
    let roles = load_values_for_user(conn, "user_roles", "role", row.id)?;
    let groups = load_groups_for_user(conn, row.id)?;
    let email = load_emails_for_user(conn, row.id)?;

    Ok(Some(User {
        username: row.username,
        password: row.password,
        otpkey: row.otpkey,
        allow: if allow.is_empty() { None } else { Some(allow) },
        roles: if roles.is_empty() { None } else { Some(roles) },
        groups: if groups.is_empty() {
            None
        } else {
            Some(groups)
        },
        email: if email.is_empty() { None } else { Some(email) },
        must_change_password: row.must_change_password,
    }))
}

/// Permanently removes users that have been soft-deleted for at least
/// `retention_secs`. Meant to be called periodically (any single
/// instance running it is enough — a `DELETE` of already-gone rows on a
/// second instance is simply a no-op, so this is safe to run
/// redundantly from more than one). `ON DELETE CASCADE` on
/// `user_allow`/`user_roles`/`user_groups` cleans up the child rows
/// automatically (the `groups` table itself is untouched — a group
/// definition outlives any particular member).
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
        DbConnection::Postgres(c) => {
            sql_query("DELETE FROM deleted_users_log WHERE deleted_at < $1")
                .bind::<Timestamp, _>(cutoff)
                .execute(c)
                .map(|n| n as u64)
                .map_err(|e| format!("Failed to purge deleted_users_log (postgres): {e}"))
        }
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
///
/// Not currently called anywhere — `db-delete-user` (cli/prompt.rs)
/// calls `with_connection`/`ensure_schema`/`mark_user_deleted` directly
/// instead, so it can report which specific step failed with its own
/// message. Kept as public API for a future caller that just wants
/// "delete this user" in one call without that level of control (e.g.
/// an eventual admin HTTP endpoint).
#[allow(dead_code)]
pub fn mark_user_deleted_in_config(cfg: &DatabaseConfig, username: &str) -> Result<(), String> {
    with_connection(cfg, |conn| {
        ensure_schema(conn)?;
        mark_user_deleted(conn, username)
    })
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
            "SELECT id, username, password, otpkey, deleted, must_change_password FROM users WHERE modified_at >= $1",
        )
        .bind::<Timestamp, _>(cutoff)
        .load(c)
        .map_err(|e| format!("Failed to load recently changed users (postgres): {e}"))?,
        DbConnection::MySql(c) => sql_query(
            "SELECT id, username, password, otpkey, deleted, must_change_password FROM users WHERE modified_at >= ?",
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
        let groups = load_groups_for_user(conn, row.id)?;
        let email = load_emails_for_user(conn, row.id)?;
        changes.push(DbUserChange::Upserted(User {
            username: row.username,
            password: row.password,
            otpkey: row.otpkey,
            allow: if allow.is_empty() { None } else { Some(allow) },
            roles: if roles.is_empty() { None } else { Some(roles) },
            groups: if groups.is_empty() {
                None
            } else {
                Some(groups)
            },
            email: if email.is_empty() { None } else { Some(email) },
            must_change_password: row.must_change_password,
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
fn load_recent_deletions(
    conn: &mut DbConnection,
    cutoff: NaiveDateTime,
) -> Result<Vec<String>, String> {
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

/// Same idea as `load_values_for_user`, for one user's group
/// membership specifically — needs a JOIN (`user_groups.group_id` ->
/// `groups.name`) rather than a plain child-table select, since group
/// names live in `groups` now, not as a free-text column on
/// `user_groups` itself (see `ensure_group_id`).
fn load_groups_for_user(conn: &mut DbConnection, user_id: i64) -> Result<Vec<String>, String> {
    #[derive(QueryableByName)]
    struct GroupNameRow {
        #[diesel(sql_type = Text)]
        value: String,
    }

    match conn {
        DbConnection::Postgres(c) => sql_query(
            "SELECT groups.name AS value FROM user_groups
            JOIN groups ON groups.id = user_groups.group_id
            WHERE user_groups.user_id = $1",
        )
        .bind::<BigInt, _>(user_id)
        .load::<GroupNameRow>(c)
        .map(|rows| rows.into_iter().map(|r| r.value).collect())
        .map_err(|e| format!("Failed to load user_groups for user (postgres): {e}")),
        DbConnection::MySql(c) => sql_query(
            "SELECT groups.name AS value FROM user_groups
            JOIN groups ON groups.id = user_groups.group_id
            WHERE user_groups.user_id = ?",
        )
        .bind::<BigInt, _>(user_id)
        .load::<GroupNameRow>(c)
        .map(|rows| rows.into_iter().map(|r| r.value).collect())
        .map_err(|e| format!("Failed to load user_groups for user (mysql): {e}")),
    }
}

/// Loads every `user_email` row for one user, `is_primary` included.
fn load_emails_for_user(conn: &mut DbConnection, user_id: i64) -> Result<Vec<EmailEntry>, String> {
    let rows: Vec<UserEmailRow> = match conn {
        DbConnection::Postgres(c) => sql_query(
            "SELECT user_id, email AS address, is_primary FROM user_email WHERE user_id = $1",
        )
        .bind::<BigInt, _>(user_id)
        .load(c)
        .map_err(|e| format!("Failed to load user_email for user (postgres): {e}"))?,
        DbConnection::MySql(c) => sql_query(
            "SELECT user_id, email AS address, is_primary FROM user_email WHERE user_id = ?",
        )
        .bind::<BigInt, _>(user_id)
        .load(c)
        .map_err(|e| format!("Failed to load user_email for user (mysql): {e}"))?,
    };

    Ok(rows
        .into_iter()
        .map(|r| EmailEntry {
            address: r.address,
            primary: r.is_primary,
        })
        .collect())
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
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(window_secs);

    match with_connection(cfg, |conn| {
        ensure_schema(conn)?;
        load_recently_changed_users(conn, cutoff)
    }) {
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
    match with_connection(cfg, |conn| {
        ensure_schema(conn)?;
        purge_deleted_users(conn, retention_secs)
    }) {
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
    match with_connection(cfg, |conn| {
        ensure_schema(conn)?;
        purge_deletion_log(conn, retention_secs)
    }) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[databases] {e}");
            0
        }
    }
}

/// Connects, ensures the schema exists, and returns the users currently
/// stored in the database. Returns `None` — distinct from
/// `Some(UsersSource::Database(vec![]))` — on any connection/query
/// failure with no usable cache either, so callers can tell "nothing at
/// all to go on, don't touch what I already know" apart from "I have
/// *something*, even if it's only the cache". See `UsersSource` for why
/// the distinction between a fresh database read and a cache fallback
/// matters, not just where the data came from.
///
/// On a successful database read, the result is also mirrored to a
/// local LMDB store (see `cache` module) so that if the database is
/// unreachable later — most importantly on a subsequent *startup*, not
/// just mid-session — ProxyAuth can still come up with the last known
/// set of database-backed users instead of zero.
pub fn load_users_from_config(cfg: &DatabaseConfig) -> Option<UsersSource> {
    let result = with_connection(cfg, |conn| {
        ensure_schema(conn)?;
        load_users(conn)
    });

    match result {
        Ok(users) => {
            if let Err(e) = cache::write_snapshot(&users) {
                eprintln!("[databases] failed to update local cache: {e}");
            }
            Some(UsersSource::Database(users))
        }
        Err(e) => {
            eprintln!("[databases] {e}");
            cache::read_snapshot_with_fallback_log().map(UsersSource::Cache)
        }
    }
}
