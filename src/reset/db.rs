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
    std::fs::create_dir_all(&path).map_err(|e| {
        format!(
            "Failed to create password-reset dir {}: {e}",
            path.display()
        )
    })?;

    // SECURITY: this directory holds single-use password-reset tokens
    // (valid for up to an hour) — restrict to owner-only rather than
    // relying solely on the process umask, which may not be 077 in
    // every deployment. Unix-only; on other platforms this is a no-op
    // and permissions fall back to whatever create_dir_all produced.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
    }

    let env = lmdb::Environment::new()
        .set_max_dbs(1)
        .open(Path::new(&path))
        .map_err(|e| {
            format!(
                "Failed to open password-reset LMDB at {}: {e}",
                path.display()
            )
        })?;

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

/// Validates *and* consumes a token in one atomic step — checks it
/// exists and isn't expired, and deletes it, within a single LMDB
/// read-write transaction.
///
/// SECURITY: this exists specifically to close a real race condition
/// that `validate_token` (read-only) followed by a later, separate
/// `consume_token` call left open. Between those two calls, the caller
/// typically does real work — hashing the new password with Argon2 is
/// deliberately slow, tens to hundreds of milliseconds — during which
/// the token is still present and still valid. Two requests carrying
/// the *same* token, arriving close enough together to both land in
/// that window, would both pass the old `validate_token` check before
/// either one reached `consume_token`: the single-use guarantee this
/// token exists to provide would be defeated, and whichever password
/// write happened to land second would silently win.
///
/// Using one read-write transaction for both the check and the delete
/// closes that window entirely — under `RESET_MUTEX` (already the
/// established pattern every other function in this file uses for its
/// own transaction), a second concurrent call for the same token
/// either sees it already gone (if it arrives after this one commits)
/// or blocks until this one finishes (if it arrives during), and in
/// neither case can it observe the token as simultaneously "still
/// valid."
///
/// UX note: unlike the old `validate_token`, this call consumes the
/// token on success even if the caller's *own* subsequent work (e.g.
/// the actual database/file write for the new password) later fails —
/// there is no way to "peek" at a single-use token without this same
/// class of race reappearing. A failure after this call succeeds means
/// the user needs a fresh reset link, not a retry with the same one.
/// This trade-off is deliberate: the checks that *don't* need the
/// token at all (password confirmation match, minimum length) already
/// run earlier in `reset_password_route`, before this is ever called,
/// so a mistyped password never burns a token in the first place —
/// only a genuine backend failure after a syntactically valid
/// submission does, which is rare enough not to be worth reopening the
/// race for.
pub fn validate_and_consume_token(token: &str) -> Result<String, String> {
    use lmdb::Transaction;

    let env = env()?;
    let _guard = RESET_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
        .open_db(Some(DB_NAME))
        .map_err(|e| format!("Failed to open password-reset LMDB db: {e}"))?;

    // A single read-write transaction for the whole check-then-delete —
    // this is what makes it atomic. A read-only txn here, or a
    // separate begin_rw_txn() later, would reopen exactly the race
    // this function exists to close.
    let mut txn = env
        .begin_rw_txn()
        .map_err(|e| format!("Failed to begin password-reset write txn: {e}"))?;

    let bytes = txn
        .get(db, &token.as_bytes())
        .map_err(|_| "Invalid or expired reset token".to_string())?
        .to_vec();

    let entry: ResetEntry = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Failed to deserialize reset token entry: {e}"))?;

    if entry.expires_at <= OffsetDateTime::now_utc().unix_timestamp() {
        // Expired tokens are simply rejected here, not actively
        // deleted — `purge_expired()` already sweeps these separately,
        // and there's no race to close for a token that was never
        // going to validate for anyone.
        return Err("Invalid or expired reset token".to_string());
    }

    // Delete within the SAME transaction as the read above, before
    // committing — this is the atomic part. Any other call for this
    // same token, from this point until this transaction commits, is
    // serialized behind RESET_MUTEX and will correctly see the token
    // as already gone once it does proceed.
    txn.del(db, &token.as_bytes(), None)
        .map_err(|e| format!("Failed to delete reset token during validation: {e}"))?;

    txn.commit()
        .map_err(|e| format!("Failed to commit reset token validate-and-consume: {e}"))?;

    Ok(entry.username)
}

/// Sweeps every stored token and deletes the expired ones. Meant to be
/// called periodically — tokens that are never submitted would
/// otherwise accumulate forever. Returns the number purged.
pub fn purge_expired() -> Result<u64, String> {
    use lmdb::{Cursor, Transaction};

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
