//! Local LMDB fallback cache for `databases`-backed users.
//!
//! Whenever `load_users_from_config` successfully reads the full user
//! list from PostgreSQL/MySQL, it's mirrored here. If the database is
//! unreachable the next time ProxyAuth needs that list — most
//! importantly, on startup — this cache stands in instead of leaving
//! `databases`-backed users unavailable simply because the database
//! happened to be down at exactly that moment (e.g. restarting both at
//! once during a deploy, or the database recovering more slowly than
//! ProxyAuth after an outage).
//!
//! Deliberately a separate, self-contained LMDB environment from the
//! one `revoke::db` uses for token revocation — that one is only
//! initialized later in startup (`start_revoked_token_ttl`, after
//! `load_config`), and LMDB environments aren't meant to be reopened
//! concurrently by unrelated code paths on the same directory. Keeping
//! this one independent avoids an initialization-order dependency
//! between the two entirely.
//!
//! This is a cache, not a source of truth: it only ever holds the most
//! recent successful snapshot, is best-effort on write (a failure to
//! update it is logged, never propagated as a hard error), and is
//! itself only ever consulted when the real database can't be reached.

use crate::config::config::User;
use lmdb::{Environment, Transaction, WriteFlags};
use once_cell::sync::OnceCell;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static CACHE_ENV: OnceCell<Environment> = OnceCell::new();
static CACHE_MUTEX: Mutex<()> = Mutex::new(());

const DB_NAME: &str = "db_users_cache";
const SNAPSHOT_KEY: &[u8] = b"snapshot";

fn cache_path() -> PathBuf {
    let base = std::env::var("PROXYAUTH_DB_CACHE_PATH")
    .unwrap_or_else(|_| "/opt/proxyauth/db/db_users_cache".to_string());
    PathBuf::from(base)
}

fn env() -> Result<&'static Environment, String> {
    if let Some(env) = CACHE_ENV.get() {
        return Ok(env);
    }

    let path = cache_path();
    std::fs::create_dir_all(&path)
    .map_err(|e| format!("Failed to create LMDB cache dir {}: {e}", path.display()))?;

    let env = Environment::new()
    .set_max_dbs(1)
    .open(Path::new(&path))
    .map_err(|e| format!("Failed to open LMDB cache at {}: {e}", path.display()))?;

    env.create_db(Some(DB_NAME), lmdb::DatabaseFlags::empty())
    .map_err(|e| format!("Failed to create/open LMDB cache db: {e}"))?;

    // Another thread may have raced us to initialize it — either way,
    // by this point `CACHE_ENV.get()` will return Some.
    let _ = CACHE_ENV.set(env);
    CACHE_ENV
    .get()
    .ok_or_else(|| "LMDB cache environment failed to initialize".to_string())
}

/// Overwrites the cached snapshot with `users`. Best-effort — errors are
/// returned for the caller to log, never panicked on.
pub fn write_snapshot(users: &[User]) -> Result<(), String> {
    let env = env()?;
    let bytes = serde_json::to_vec(users)
    .map_err(|e| format!("Failed to serialize users for LMDB cache: {e}"))?;

    let _guard = CACHE_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
    .open_db(Some(DB_NAME))
    .map_err(|e| format!("Failed to open LMDB cache db: {e}"))?;
    let mut txn = env
    .begin_rw_txn()
    .map_err(|e| format!("Failed to begin LMDB cache write txn: {e}"))?;
    txn.put(db, &SNAPSHOT_KEY, &bytes, WriteFlags::empty())
    .map_err(|e| format!("Failed to write LMDB cache snapshot: {e}"))?;
    txn.commit()
    .map_err(|e| format!("Failed to commit LMDB cache snapshot: {e}"))?;

    Ok(())
}

/// Reads the cached snapshot, if one exists.
pub fn read_snapshot() -> Result<Vec<User>, String> {
    let env = env()?;

    let _guard = CACHE_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
    .open_db(Some(DB_NAME))
    .map_err(|e| format!("Failed to open LMDB cache db: {e}"))?;
    let txn = env
    .begin_ro_txn()
    .map_err(|e| format!("Failed to begin LMDB cache read txn: {e}"))?;
    let bytes = txn
    .get(db, &SNAPSHOT_KEY)
    .map_err(|e| format!("No cached snapshot available: {e}"))?;

    serde_json::from_slice(bytes)
    .map_err(|e| format!("Failed to deserialize cached snapshot: {e}"))
}

/// Deletes the cached snapshot, if one exists. A no-op (not an error) if
/// there was nothing cached to begin with. The next successful full
/// database read repopulates it as usual — this only clears what's
/// there *right now*, it doesn't disable caching going forward.
pub fn clear_snapshot() -> Result<(), String> {
    let env = env()?;

    let _guard = CACHE_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
    .open_db(Some(DB_NAME))
    .map_err(|e| format!("Failed to open LMDB cache db: {e}"))?;
    let mut txn = env
    .begin_rw_txn()
    .map_err(|e| format!("Failed to begin LMDB cache write txn: {e}"))?;

    match txn.del(db, &SNAPSHOT_KEY, None) {
        Ok(()) => {}
        Err(lmdb::Error::NotFound) => {
            // Nothing cached — already in the desired end state.
        }
        Err(e) => return Err(format!("Failed to clear LMDB cache snapshot: {e}")),
    }

    txn.commit()
    .map_err(|e| format!("Failed to commit LMDB cache clear: {e}"))?;

    Ok(())
}

/// Same as `read_snapshot`, but logs the outcome and adapts it to the
/// `Option<Vec<User>>` shape `load_users_from_config` needs: `Some` on a
/// cache hit (treated the same as a fresh database read by callers —
/// it's the last known good full state), `None` if there's no usable
/// cache either, meaning the caller should leave its current in-memory
/// state untouched rather than guess.
pub(super) fn read_snapshot_with_fallback_log() -> Option<Vec<User>> {
    match read_snapshot() {
        Ok(users) => {
            eprintln!(
                "[databases] database unreachable — falling back to {} cached user(s) from local LMDB store",
                users.len()
            );
            Some(users)
        }
        Err(e) => {
            eprintln!("[databases] database unreachable and no usable local cache either ({e}) — leaving current state untouched");
            None
        }
    }
}
