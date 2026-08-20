//! Local LMDB store for password-reset tokens.
//!
//! A token is created by `proxyauth reset-password` (an admin resetting
//! someone's password) or automatically on a successful login where the
//! user's `must_change_password` flag is set (a temporary password an
//! admin just gave them). Either way, the token is a single-use,
//! time-limited proof that whoever holds the link is allowed to set a
//! new password for one specific username, without needing their old
//! password — that's the whole point of the flow.
//!
//! Deliberately its own LMDB environment, for the same reason
//! `databases::cache` is: kept independent from `revoke::db`'s
//! environment (initialized later in startup) and from
//! `databases::cache`'s (a different concern entirely), to avoid any
//! initialization-order coupling between unrelated LMDB uses.
//!
//! Tokens are stored as a JSON blob per key (the token itself), so a
//! lookup is a single point read — no scan needed to validate one.

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::OffsetDateTime;

static RESET_ENV: OnceCell<lmdb::Environment> = OnceCell::new();
static RESET_MUTEX: Mutex<()> = Mutex::new(());

const DB_NAME: &str = "password_reset";

/// Which flow created this token — purely informational (logged), not
/// used to branch behavior: both flows converge on the same
/// "submit a new password with this token" handling.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResetKind {
    AdminReset,
    FirstLogin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResetEntry {
    username: String,
    kind: ResetKind,
    expires_at: i64,
}

fn reset_path() -> PathBuf {
    let base = std::env::var("PROXYAUTH_PASSWORD_RESET_PATH")
    .unwrap_or_else(|_| "/opt/proxyauth/db/password_reset".to_string());
    PathBuf::from(base)
}

fn env() -> Result<&'static lmdb::Environment, String> {
    if let Some(env) = RESET_ENV.get() {
        return Ok(env);
    }

    let path = reset_path();
    std::fs::create_dir_all(&path)
    .map_err(|e| format!("Failed to create password-reset dir {}: {e}", path.display()))?;

    let env = lmdb::Environment::new()
    .set_max_dbs(1)
    .open(Path::new(&path))
    .map_err(|e| format!("Failed to open password-reset LMDB at {}: {e}", path.display()))?;

    env.create_db(Some(DB_NAME), lmdb::DatabaseFlags::empty())
    .map_err(|e| format!("Failed to create/open password-reset LMDB db: {e}"))?;

    let _ = RESET_ENV.set(env);
    RESET_ENV
    .get()
    .ok_or_else(|| "password-reset LMDB environment failed to initialize".to_string())
}

/// Generates a new, single-use, time-limited reset token for `username`
/// and stores it. `ttl_secs` controls how long it stays valid. Returns
/// the token string to embed in the reset link.
pub fn create_token(username: &str, kind: ResetKind, ttl_secs: i64) -> Result<String, String> {
    use lmdb::{Transaction, WriteFlags};

    let env = env()?;
    let token = crate::token::auth::generate_random_string(64);

    let entry = ResetEntry {
        username: username.to_string(),
        kind,
        expires_at: OffsetDateTime::now_utc().unix_timestamp() + ttl_secs,
    };
    let bytes = serde_json::to_vec(&entry)
    .map_err(|e| format!("Failed to serialize reset token entry: {e}"))?;

    let _guard = RESET_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
    .open_db(Some(DB_NAME))
    .map_err(|e| format!("Failed to open password-reset LMDB db: {e}"))?;
    let mut txn = env
    .begin_rw_txn()
    .map_err(|e| format!("Failed to begin password-reset write txn: {e}"))?;
    txn.put(db, &token.as_bytes(), &bytes, WriteFlags::empty())
    .map_err(|e| format!("Failed to store reset token: {e}"))?;
    txn.commit()
    .map_err(|e| format!("Failed to commit reset token: {e}"))?;

    Ok(token)
}

/// Checks a token: valid (exists, not expired) returns the username it
/// was issued for. Does **not** consume it — a failed password
/// submission (e.g. mismatched confirmation) shouldn't burn the token,
/// the user should be able to retry with the same link. Call
/// `consume_token` once the password change actually succeeds.
pub fn validate_token(token: &str) -> Result<String, String> {
    use lmdb::Transaction;

    let env = env()?;
    let _guard = RESET_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
    .open_db(Some(DB_NAME))
    .map_err(|e| format!("Failed to open password-reset LMDB db: {e}"))?;
    let txn = env
    .begin_ro_txn()
    .map_err(|e| format!("Failed to begin password-reset read txn: {e}"))?;
    let bytes = txn
    .get(db, &token.as_bytes())
    .map_err(|_| "Invalid or expired reset token".to_string())?;

    let entry: ResetEntry = serde_json::from_slice(bytes)
    .map_err(|e| format!("Failed to deserialize reset token entry: {e}"))?;

    if entry.expires_at <= OffsetDateTime::now_utc().unix_timestamp() {
        return Err("Invalid or expired reset token".to_string());
    }

    Ok(entry.username)
}

/// Permanently invalidates a token — called once its password change
/// has actually been applied, so the same link can't be reused.
pub fn consume_token(token: &str) -> Result<(), String> {
    use lmdb::Transaction;

    let env = env()?;
    let _guard = RESET_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
    .open_db(Some(DB_NAME))
    .map_err(|e| format!("Failed to open password-reset LMDB db: {e}"))?;
    let mut txn = env
    .begin_rw_txn()
    .map_err(|e| format!("Failed to begin password-reset write txn: {e}"))?;
    // A token that's already gone (double-submit, race) is fine to
    // no-op on — the outcome ("this token can't be used again") is
    // already true either way.
    let _ = txn.del(db, &token.as_bytes(), None);
    txn.commit()
    .map_err(|e| format!("Failed to commit reset token deletion: {e}"))?;

    Ok(())
}

/// Sweeps every stored token and deletes the expired ones. Meant to be
/// called periodically — tokens that are never submitted would
/// otherwise accumulate forever. Returns the number purged.
pub fn purge_expired() -> Result<u64, String> {
    use lmdb::{Cursor, Transaction, WriteFlags};

    let env = env()?;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let _guard = RESET_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
    .open_db(Some(DB_NAME))
    .map_err(|e| format!("Failed to open password-reset LMDB db: {e}"))?;

    let expired_keys: Vec<Vec<u8>> = {
        let txn = env
        .begin_ro_txn()
        .map_err(|e| format!("Failed to begin password-reset read txn: {e}"))?;
        let mut cursor = txn
        .open_ro_cursor(db)
        .map_err(|e| format!("Failed to open password-reset cursor: {e}"))?;

        let mut keys = Vec::new();
        for item in cursor.iter() {
            let (key, value) = item.map_err(|e| format!("Failed to read reset entry: {e}"))?;
            if let Ok(entry) = serde_json::from_slice::<ResetEntry>(value) {
                if entry.expires_at <= now {
                    keys.push(key.to_vec());
                }
            }
        }
        keys
    };

    if expired_keys.is_empty() {
        return Ok(0);
    }

    let mut txn = env
    .begin_rw_txn()
    .map_err(|e| format!("Failed to begin password-reset write txn: {e}"))?;
    for key in &expired_keys {
        let _ = txn.del(db, key, None);
    }
    txn.commit()
    .map_err(|e| format!("Failed to commit password-reset purge: {e}"))?;

    Ok(expired_keys.len() as u64)
}
