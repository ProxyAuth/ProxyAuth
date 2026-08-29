//! Local LMDB store for OIDC authorization codes — the short-lived,
//! single-use code `/authorize` hands the browser, which the backend
//! (the relying party) then exchanges at `/token` for an `id_token`.
//!
//! Its own LMDB environment, same reasoning as `reset::db`'s: kept
//! independent from every other LMDB use in the codebase so none of
//! them are coupled by initialization order.
//!
//! # Validate-and-consume is atomic from the start here
//!
//! `reset::db`'s original design split validation (read-only) and
//! consumption (delete) into two separate calls, which turned out to
//! leave a real race window — the same token could validate twice if
//! two requests landed close enough together (see
//! `reset::db::validate_and_consume_token`'s own doc comment for the
//! full incident). An authorization code is exactly the same category
//! of single-use secret, so this store only ever exposes one atomic
//! `validate_and_consume` operation — there's no separate read-only
//! `validate` at all, deliberately, so a future caller can't
//! accidentally reintroduce that same class of bug by reaching for a
//! two-step version that doesn't exist here.

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::OffsetDateTime;

static AUTHCODE_ENV: OnceCell<lmdb::Environment> = OnceCell::new();
static AUTHCODE_MUTEX: Mutex<()> = Mutex::new(());

const DB_NAME: &str = "oidc_authcode";

/// Codes are deliberately very short-lived — unlike a password-reset
/// link (meant to survive the time it takes a human to check their
/// email), an authorization code is meant to survive one immediate
/// server-to-server redirect-and-exchange, typically well under a
/// second in practice. 120s leaves headroom for a slow network
/// without meaningfully widening the window an intercepted code stays
/// dangerous in.
pub const AUTHCODE_TTL_SECS: i64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeEntry {
    pub client_id: String,
    pub redirect_uri: String,
    pub username: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String, // always "S256" — see authorize.rs
    pub expires_at: i64,
}

fn authcode_path() -> PathBuf {
    let base = std::env::var("PROXYAUTH_OIDC_AUTHCODE_PATH")
        .unwrap_or_else(|_| "/opt/proxyauth/db/oidc_authcode".to_string());
    PathBuf::from(base)
}

fn env() -> Result<&'static lmdb::Environment, String> {
    if let Some(env) = AUTHCODE_ENV.get() {
        return Ok(env);
    }

    let path = authcode_path();
    std::fs::create_dir_all(&path)
        .map_err(|e| format!("Failed to create OIDC authcode dir {}: {e}", path.display()))?;

    // SECURITY: same reasoning as reset::db's own directory — an
    // authorization code, however short-lived, is a genuine
    // single-use credential (it's what stands between "logged in with
    // ProxyAuth" and "the backend has an id_token"). Owner-only rather
    // than relying on the process umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
    }

    let env = lmdb::Environment::new()
        .set_max_dbs(1)
        .open(Path::new(&path))
        .map_err(|e| format!("Failed to open OIDC authcode LMDB at {}: {e}", path.display()))?;

    env.create_db(Some(DB_NAME), lmdb::DatabaseFlags::empty())
        .map_err(|e| format!("Failed to create/open OIDC authcode LMDB db: {e}"))?;

    let _ = AUTHCODE_ENV.set(env);
    AUTHCODE_ENV
        .get()
        .ok_or_else(|| "OIDC authcode LMDB environment failed to initialize".to_string())
}

/// Generates a new, single-use authorization code and stores it.
/// Returns the code string to redirect the browser back to the
/// relying party's `redirect_uri` with.
pub fn create_code(entry: AuthCodeEntry) -> Result<String, String> {
    use lmdb::{Transaction, WriteFlags};

    let env = env()?;
    let _guard = AUTHCODE_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
        .open_db(Some(DB_NAME))
        .map_err(|e| format!("Failed to open OIDC authcode LMDB db: {e}"))?;

    // 256 bits from OsRng, hex-encoded — plenty of entropy for a
    // 120-second-lived, single-use secret; no need for the heavier
    // shift+BLAKE3 construction `token::auth::generate_random_string`
    // uses for ProxyAuth's own longer-lived tokens.
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let code = hex::encode(raw);

    let serialized =
        serde_json::to_vec(&entry).map_err(|e| format!("Failed to serialize authcode entry: {e}"))?;

    let mut txn = env
        .begin_rw_txn()
        .map_err(|e| format!("Failed to begin OIDC authcode write txn: {e}"))?;
    txn.put(db, &code.as_bytes(), &serialized, WriteFlags::empty())
        .map_err(|e| format!("Failed to store OIDC authcode: {e}"))?;
    txn.commit()
        .map_err(|e| format!("Failed to commit OIDC authcode: {e}"))?;

    Ok(code)
}

/// Validates and consumes an authorization code in one atomic step —
/// checks it exists and isn't expired, and deletes it, within a
/// single LMDB read-write transaction. See this module's own doc
/// comment for why there's no separate, non-atomic `validate` step.
///
/// Returns the stored entry on success. The caller (`token.rs`) is
/// responsible for checking `client_id`/`redirect_uri` against what
/// the token request actually presented, and for verifying
/// `code_challenge` against the presented `code_verifier` — this
/// function only proves the code itself is genuine, single-use, and
/// not expired; it doesn't know what the caller is allowed to do with
/// the entry it returns.
pub fn validate_and_consume_code(code: &str) -> Result<AuthCodeEntry, String> {
    use lmdb::Transaction;

    let env = env()?;
    let _guard = AUTHCODE_MUTEX.lock().map_err(|e| e.to_string())?;
    let db = env
        .open_db(Some(DB_NAME))
        .map_err(|e| format!("Failed to open OIDC authcode LMDB db: {e}"))?;

    let mut txn = env
        .begin_rw_txn()
        .map_err(|e| format!("Failed to begin OIDC authcode write txn: {e}"))?;

    let bytes = txn
        .get(db, &code.as_bytes())
        .map_err(|_| "Invalid or expired authorization code".to_string())?
        .to_vec();

    let entry: AuthCodeEntry = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Failed to deserialize OIDC authcode entry: {e}"))?;

    if entry.expires_at <= OffsetDateTime::now_utc().unix_timestamp() {
        // Same reasoning as reset::db::validate_and_consume_token: an
        // expired code is simply rejected here, not actively deleted
        // — a background sweep (not yet built for this store; TODO if
        // this ever needs one, matching reset::db::purge_expired)
        // would clean these up separately. There's no race to close
        // for a code that was never going to validate for anyone.
        return Err("Invalid or expired authorization code".to_string());
    }

    // Delete within the SAME transaction as the read, before
    // committing — see reset::db::validate_and_consume_token's doc
    // comment for exactly why this ordering is what makes it atomic.
    txn.del(db, &code.as_bytes(), None)
        .map_err(|e| format!("Failed to delete OIDC authcode during validation: {e}"))?;

    txn.commit()
        .map_err(|e| format!("Failed to commit OIDC authcode validate-and-consume: {e}"))?;

    Ok(entry)
}
