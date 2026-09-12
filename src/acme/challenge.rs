//! HTTP-01 ACME challenge store.
//!
//! The challenge store is backed by LMDB so that the short-lived
//! `proxyauth certbot` CLI process and the already-running ProxyAuth
//! server process can exchange ACME HTTP-01 challenges safely.
//!
//! The CLI publishes the challenge before notifying the ACME server
//! that the challenge is ready. The HTTP server then reads the same
//! LMDB entry when Let's Encrypt requests:
//!
//! /.well-known/acme-challenge/{token}
//!
//! The store is deliberately separate from the main ProxyAuth database.

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static CHALLENGE_ENV: OnceCell<lmdb::Environment> = OnceCell::new();
static CHALLENGE_MUTEX: Mutex<()> = Mutex::new(());

const DB_NAME: &str = "acme_challenges";

/// Maximum lifetime of an orphaned challenge.
///
/// A normal renewal removes its challenge immediately after the ACME
/// order completes. This timeout only protects against stale entries
/// left behind after a crashed process.
const MAX_ENTRY_AGE_SECS: i64 = 600;

#[derive(Debug, Serialize, Deserialize)]
struct ChallengeEntry {
    key_authorization: String,
    published_at: i64,
}

/// Returns the directory used by the ACME challenge LMDB.
///
/// This can be overridden with:
///
/// PROXYAUTH_ACME_CHALLENGE_PATH=/some/path
///
/// The default is the production path used by ProxyAuth.
fn challenge_path() -> PathBuf {
    let base = std::env::var("PROXYAUTH_ACME_CHALLENGE_PATH")
        .unwrap_or_else(|_| "/opt/proxyauth/db/acme_challenges".to_string());

    PathBuf::from(base)
}

/// Open the shared ACME challenge LMDB environment.
///
/// Important:
/// - Do NOT chmod the directory here.
/// - Permissions must be managed by the installer/admin.
/// - The directory is shared between the ProxyAuth daemon and the
///   short-lived `proxyauth certbot` process.
///
/// Changing permissions every time the environment is opened can make
/// a challenge published by one process inaccessible to another process
/// running under a different Unix user.
fn env() -> Result<&'static lmdb::Environment, String> {
    CHALLENGE_ENV.get_or_try_init(|| {
        let path = challenge_path();

        std::fs::create_dir_all(&path).map_err(|e| {
            format!(
                "Failed to create ACME challenge dir {}: {e}",
                path.display()
            )
        })?;

        let env = lmdb::Environment::new()
            .set_max_dbs(1)
            .open(Path::new(&path))
            .map_err(|e| {
                format!(
                    "Failed to open ACME challenge LMDB at {}: {e}",
                    path.display()
                )
            })?;

        env.create_db(Some(DB_NAME), lmdb::DatabaseFlags::empty())
            .map_err(|e| format!("Failed to create/open ACME challenge LMDB database: {e}"))?;

        Ok(env)
    })
}

/// Build the LMDB key.
///
/// The vhost is normalized to lowercase so that:
///
/// Example.com
/// example.com
/// EXAMPLE.COM
///
/// all address the same challenge namespace.
///
/// A null-byte separator is safe because neither a hostname nor an
/// ACME base64url token can contain it.
fn make_key(vhost: &str, token: &str) -> Vec<u8> {
    let mut key = vhost.to_ascii_lowercase().into_bytes();

    key.push(0);

    key.extend_from_slice(token.as_bytes());

    key
}

/// Current UNIX timestamp.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Publish an ACME HTTP-01 challenge.
///
/// This function MUST complete successfully before the ACME order is
/// told that the challenge is ready.
pub fn publish(vhost: &str, token: &str, key_authorization: &str) -> Result<(), String> {
    use lmdb::{Transaction, WriteFlags};

    let env = env()?;

    let entry = ChallengeEntry {
        key_authorization: key_authorization.to_string(),
        published_at: now(),
    };

    let bytes = serde_json::to_vec(&entry)
        .map_err(|e| format!("Failed to serialize ACME challenge entry: {e}"))?;

    let _guard = CHALLENGE_MUTEX
        .lock()
        .map_err(|e| format!("Failed to lock ACME challenge store: {e}"))?;

    let db = env
        .open_db(Some(DB_NAME))
        .map_err(|e| format!("Failed to open ACME challenge LMDB database: {e}"))?;

    let mut txn = env
        .begin_rw_txn()
        .map_err(|e| format!("Failed to begin ACME challenge write transaction: {e}"))?;

    txn.put(db, &make_key(vhost, token), &bytes, WriteFlags::empty())
        .map_err(|e| format!("Failed to store ACME challenge for {vhost}: {e}"))?;

    txn.commit()
        .map_err(|e| format!("Failed to commit ACME challenge for {vhost}: {e}"))?;

    // Visible at info level, unlike lookup()'s own debug-level logging
    // — so a real renewal attempt's logs show BOTH what was published
    // and what was looked up side by side, rather than only ever
    // seeing the lookup half of the story.
    tracing::info!(
        vhost = %vhost,
        token = %token,
        path = %challenge_path().display(),
        "ACME challenge published"
    );

    Ok(())
}

/// Remove an ACME challenge.
///
/// Failure is intentionally ignored because cleanup happens after an
/// order has already completed or failed and there is nothing useful
/// the caller can do at that point.
pub fn remove(vhost: &str, token: &str) {
    use lmdb::Transaction;

    let Ok(env) = env() else {
        tracing::warn!(
            vhost = %vhost,
            token = %token,
            "Unable to open ACME challenge store during cleanup"
        );

        return;
    };

    let Ok(_guard) = CHALLENGE_MUTEX.lock() else {
        tracing::warn!(
            vhost = %vhost,
            token = %token,
            "Unable to lock ACME challenge store during cleanup"
        );

        return;
    };

    let Ok(db) = env.open_db(Some(DB_NAME)) else {
        tracing::warn!(
            vhost = %vhost,
            token = %token,
            "Unable to open ACME challenge database during cleanup"
        );

        return;
    };

    let Ok(mut txn) = env.begin_rw_txn() else {
        tracing::warn!(
            vhost = %vhost,
            token = %token,
            "Unable to start ACME challenge cleanup transaction"
        );

        return;
    };

    match txn.del(db, &make_key(vhost, token), None) {
        Ok(_) => {
            let _ = txn.commit();

            tracing::debug!(
                vhost = %vhost,
                token = %token,
                "ACME challenge removed"
            );
        }

        Err(lmdb::Error::NotFound) => {
            let _ = txn.commit();

            tracing::debug!(
                vhost = %vhost,
                token = %token,
                "ACME challenge already absent"
            );
        }

        Err(e) => {
            tracing::warn!(
                vhost = %vhost,
                token = %token,
                error = %e,
                "Failed to remove ACME challenge"
            );
        }
    }
}

/// Look up an ACME challenge.
///
/// This function deliberately logs storage failures instead of silently
/// converting every error into `None`.
///
/// This distinction is important:
///
/// - NotFound = normal 404.
/// - Permission/LMDB failure = server configuration/storage problem.
///
/// Without this logging, an LMDB permission problem appears to Let's
/// Encrypt as a simple HTTP 404.
pub fn lookup(vhost: &str, token: &str) -> Option<String> {
    use lmdb::Transaction;

    let env = match env() {
        Ok(env) => env,

        Err(e) => {
            tracing::error!(
                vhost = %vhost,
                token = %token,
                error = %e,
                "ACME challenge store unavailable"
            );

            return None;
        }
    };

    let _guard = match CHALLENGE_MUTEX.lock() {
        Ok(guard) => guard,

        Err(e) => {
            tracing::error!(
                vhost = %vhost,
                token = %token,
                error = %e,
                "ACME challenge store mutex unavailable"
            );

            return None;
        }
    };

    let db = match env.open_db(Some(DB_NAME)) {
        Ok(db) => db,

        Err(e) => {
            tracing::error!(
                vhost = %vhost,
                token = %token,
                error = %e,
                "ACME challenge database unavailable"
            );

            return None;
        }
    };

    let txn = match env.begin_ro_txn() {
        Ok(txn) => txn,

        Err(e) => {
            tracing::error!(
                vhost = %vhost,
                token = %token,
                error = %e,
                "Failed to start ACME challenge read transaction"
            );

            return None;
        }
    };

    let bytes = match txn.get(db, &make_key(vhost, token)) {
        Ok(bytes) => bytes,

        Err(lmdb::Error::NotFound) => {
            // info, not debug — this is the exact line to compare
            // against "ACME challenge published" above when a real
            // renewal fails: same vhost/token but a different `path`
            // between the two log lines means the CLI and the running
            // server are resolving PROXYAUTH_ACME_CHALLENGE_PATH to
            // two different directories, which is otherwise invisible.
            tracing::info!(
                vhost = %vhost,
                token = %token,
                path = %challenge_path().display(),
                "ACME challenge token not found"
            );

            return None;
        }

        Err(e) => {
            tracing::error!(
                vhost = %vhost,
                token = %token,
                error = %e,
                "ACME challenge LMDB lookup failed"
            );

            return None;
        }
    };

    let entry: ChallengeEntry = match serde_json::from_slice(bytes) {
        Ok(entry) => entry,

        Err(e) => {
            tracing::error!(
                vhost = %vhost,
                token = %token,
                error = %e,
                "Invalid ACME challenge entry in LMDB"
            );

            return None;
        }
    };

    let age = now() - entry.published_at;

    if age < 0 || age > MAX_ENTRY_AGE_SECS {
        tracing::warn!(
            vhost = %vhost,
            token = %token,
            age = age,
            "ACME challenge expired or has invalid timestamp"
        );

        return None;
    }

    tracing::info!(
        vhost = %vhost,
        token = %token,
        age = age,
        "ACME challenge served from LMDB"
    );

    Some(entry.key_authorization)
}

/// Extract an ACME token from an HTTP request path.
///
/// Accepts:
///
/// /.well-known/acme-challenge/<token>
///
/// Rejects:
///
/// /.well-known/acme-challenge/
/// /.well-known/acme-challenge
/// /foo/bar
/// /.well-known/acme-challenge/foo/bar
pub fn extract_token(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/.well-known/acme-challenge/")?;

    if rest.is_empty() || rest.contains('/') {
        return None;
    }

    Some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        static INIT: std::sync::Once = std::sync::Once::new();

        INIT.call_once(|| {
            let dir = std::env::temp_dir().join(format!(
                "proxyauth_acme_challenge_test_{}",
                std::process::id()
            ));

            unsafe {
                std::env::set_var("PROXYAUTH_ACME_CHALLENGE_PATH", dir);
            }
        });
    }

    #[test]
    fn extract_token_matches_well_formed_path() {
        assert_eq!(
            extract_token("/.well-known/acme-challenge/abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_token_rejects_unrelated_paths() {
        assert_eq!(extract_token("/foo/bar"), None);

        assert_eq!(extract_token("/.well-known/acme-challenge/"), None);

        assert_eq!(extract_token("/.well-known/acme-challenge"), None);
    }

    #[test]
    fn extract_token_rejects_nested_paths() {
        assert_eq!(extract_token("/.well-known/acme-challenge/a/b"), None);
    }

    #[test]
    fn publish_then_lookup_roundtrips() {
        setup();

        publish("test-a.example.com", "tok-1", "key-auth-value-1").unwrap();

        assert_eq!(
            lookup("test-a.example.com", "tok-1"),
            Some("key-auth-value-1".to_string())
        );
    }

    #[test]
    fn lookup_is_case_insensitive_on_vhost() {
        setup();

        publish("Test-B.Example.com", "tok-2", "value-2").unwrap();

        assert_eq!(
            lookup("test-b.example.com", "tok-2"),
            Some("value-2".to_string())
        );

        assert_eq!(
            lookup("TEST-B.EXAMPLE.COM", "tok-2"),
            Some("value-2".to_string())
        );
    }

    #[test]
    fn lookup_misses_unpublished_pair() {
        setup();

        assert_eq!(lookup("never-published.example.com", "whatever"), None);
    }

    #[test]
    fn different_vhosts_dont_collide_on_same_token() {
        setup();

        publish("host-one.example.com", "shared-token", "value-for-one").unwrap();

        publish("host-two.example.com", "shared-token", "value-for-two").unwrap();

        assert_eq!(
            lookup("host-one.example.com", "shared-token"),
            Some("value-for-one".to_string())
        );

        assert_eq!(
            lookup("host-two.example.com", "shared-token"),
            Some("value-for-two".to_string())
        );
    }

    #[test]
    fn remove_clears_the_entry() {
        setup();

        publish("test-c.example.com", "tok-3", "value-3").unwrap();

        assert!(lookup("test-c.example.com", "tok-3").is_some());

        remove("test-c.example.com", "tok-3");

        assert_eq!(lookup("test-c.example.com", "tok-3"), None);
    }

    #[test]
    fn remove_of_nonexistent_entry_is_a_harmless_no_op() {
        setup();

        remove("never-published-either.example.com", "nope");
    }

    #[test]
    fn concurrent_publish_from_many_threads_loses_nothing() {
        setup();

        let n = 50;

        let handles: Vec<_> = (0..n)
            .map(|i| {
                std::thread::spawn(move || {
                    let vhost = format!("lmdb-thread-{i}.example.com");

                    let value = format!("value-{i}");

                    publish(&vhost, "shared-token-across-all-threads", &value).unwrap();
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        for i in 0..n {
            let vhost = format!("lmdb-thread-{i}.example.com");

            let expected = format!("value-{i}");

            assert_eq!(
                lookup(&vhost, "shared-token-across-all-threads"),
                Some(expected),
                "lost concurrent publish for thread {i}"
            );
        }
    }
}
