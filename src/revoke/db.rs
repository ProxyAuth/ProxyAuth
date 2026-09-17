//! Revocation store: an in-memory map read on every request, persisted to
//! LMDB, and shared between instances through Redis when configured.
//!
//! ```text
//!   revoke_token ──► memory ──► LMDB ──► Redis (optional)
//!
//!   every tick:  Redis ──► LMDB/memory   (other nodes' revocations)
//!                LMDB  ──► memory         (other processes on this host)
//!                purge expired entries from memory, LMDB and Redis
//! ```
//!
//! An entry's value is when it may be forgotten — see
//! `revoke::load::revocation_purge_at`. A token can never outlive
//! `token_expiry_seconds`, so no entry needs to be kept longer than that
//! after it was recorded: LMDB stores both instants, and Redis keys carry
//! a matching TTL, so every store cleans itself up.
//!
//! LMDB value layout (big-endian):
//!
//! ```text
//! 16 bytes  revoked_at (u64) + value (u64)     current
//!  8 bytes  value (u64)                        older versions
//!  0 bytes  "never" (value 0)                   older versions
//! ```
//!
//! `value == 0` ("never") only exists in data written by older
//! versions. Such entries are migrated as soon as they are read: they are
//! given `now + token_expiry_seconds`, which is safe because every token
//! they could refer to was issued before `now`.

use anyhow::Error;
use dashmap::DashMap;
use lmdb::{Cursor, Environment, Transaction, WriteFlags};
use once_cell::sync::OnceCell;
use redis::{Client, Commands};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::revoke::load::revocation_purge_at;

pub static REDIS: OnceCell<Client> = OnceCell::new();
pub static LMDB_ENV: OnceCell<lmdb::Environment> = OnceCell::new();
pub static LMDB_MUTEX: Mutex<()> = Mutex::new(());

pub type RevokedTokenMap = Arc<DashMap<String, u64>>;

/// `token_expiry_seconds`, as set by [`set_token_lifetime`]. `0` until
/// then, in which case legacy "never" entries are left untouched.
static TOKEN_LIFETIME_SECS: AtomicU64 = AtomicU64::new(0);

/// Tells the store how long a token can live at most. Called at startup,
/// before [`start_revoked_token_ttl`].
pub fn set_token_lifetime(secs: i64) {
    TOKEN_LIFETIME_SECS.store(secs.max(0) as u64, Ordering::Relaxed);
}

pub fn token_lifetime() -> u64 {
    TOKEN_LIFETIME_SECS.load(Ordering::Relaxed)
}

/// The purge date given to a legacy "never" entry found at `now`, or
/// `None` while the token lifetime is unknown.
pub fn migrated_purge_at(now: u64) -> Option<u64> {
    match token_lifetime() {
        0 => None,
        lifetime => Some(now.saturating_add(lifetime)),
    }
}

/// One revocation as stored in LMDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationRecord {
    /// When the revocation was recorded (Unix seconds); `0` if unknown
    /// (written by an older version).
    pub revoked_at: u64,
    /// The in-memory value: purge date, or a packed rotation value.
    pub value: u64,
}

/// Shortest TTL given to a Redis revocation key, so every node sees it on
/// at least one sync tick even when the entry is about to be purged.
pub const REDIS_MIN_TTL_SECS: u64 = 60;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn start_revoked_token_ttl(
    revoked_tokens: RevokedTokenMap,
    every: Duration,
    redis_url: Option<String>,
) {
    let path = std::env::var("LMDB_PATH").unwrap_or_else(|_| "/opt/proxyauth/db/".to_string());

    if LMDB_ENV.get().is_none() {
        let env = Environment::new()
            .set_max_dbs(1)
            .open(Path::new(&path))
            .expect("Failed to open LMDB");

        env.create_db(Some("revoke"), lmdb::DatabaseFlags::empty())
            .expect("Failed to create/open LMDB 'revoke' db");

        // A concurrent caller may have won the race; either env is fine.
        let _ = LMDB_ENV.set(env);
    }

    lmdb_read_all_into(&revoked_tokens);
    debug!("[RevokedSync] Loaded {} entries from LMDB at startup", revoked_tokens.len());

    if let Some(url) = redis_url {
        if REDIS.get().is_none() {
            let mut attempts = 3;
            while attempts > 0 {
                match Client::open(url.clone()) {
                    Ok(client) => {
                        let _ = REDIS.set(client);
                        debug!("[RevokedSync] Redis initialized successfully");
                        break;
                    }
                    Err(e) => {
                        attempts -= 1;
                        error!(
                            "[RevokedSync] Failed to initialize Redis: {e}. Retrying... ({attempts} attempts left)"
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
            if REDIS.get().is_none() {
                error!("[RevokedSync] Failed to initialize Redis after retries; revocations stay local");
            }
        }
    }

    // The sync loop runs with or without Redis: LMDB still has to be read
    // back and purged on its own.
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let (Ok(mut sigterm), Ok(mut sigint)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            warn!("[RevokedSync] Cannot listen for shutdown signals; LMDB will not be flushed on exit");
            return;
        };
        tokio::select! {
            _ = sigterm.recv() => info!("[RevokedSync] Received SIGTERM, initiating shutdown"),
            _ = sigint.recv() => info!("[RevokedSync] Received SIGINT, initiating shutdown"),
        }
        let _ = shutdown_tx.send(true);
    });

    tokio::spawn(async move {
        let mut interval = time::interval(every);
        debug!("[RevokedSync] Starting sync loop with interval {:?}", every);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let map = revoked_tokens.clone();
                    // LMDB and Redis calls block: keep them off the
                    // runtime's worker threads.
                    if let Err(e) = tokio::task::spawn_blocking(move || sync_tick(&map)).await {
                        error!("[RevokedSync] sync tick failed: {e}");
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("[RevokedSync] Shutting down token sync loop");
                        break;
                    }
                }
            }
        }

        let _guard = LMDB_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(env) = LMDB_ENV.get() {
            match env.sync(true) {
                Ok(()) => info!("[RevokedSync] LMDB synced successfully"),
                Err(e) => error!("[RevokedSync] Failed to sync LMDB on shutdown: {e}"),
            }
        }
    });
}

/// One pass of the sync loop.
pub fn sync_tick(map: &RevokedTokenMap) {
    let now = now_secs();

    if let Some(client) = REDIS.get() {
        pull_from_redis(client, map, now);
    }

    lmdb_read_all_into(map);

    let purged = purge_expired(map, now);
    if !purged.is_empty() {
        lmdb_delete_many(&purged);
        if let Some(client) = REDIS.get() {
            redis_delete_many(client, &purged);
        }
        debug!("[RevokedSync] Purged {} expired entries", purged.len());
    }
}

/// Removes every entry whose purge date has passed from `map` and
/// returns their keys. Permanent entries (`0`) are kept.
pub fn purge_expired(map: &RevokedTokenMap, now: u64) -> Vec<String> {
    let mut purged = Vec::new();
    map.retain(|key, value| {
        let purge_at = revocation_purge_at(key, *value);
        let keep = purge_at == 0 || purge_at > now;
        if !keep {
            purged.push(key.clone());
        }
        keep
    });
    purged
}

// ───────────────────────────── Redis ─────────────────────────────

/// Redis keys of one revocation.
pub fn redis_keys(token_id: &str) -> [String; 3] {
    [
        format!("token:{token_id}"),
        format!("{token_id}_action"),
        format!("{token_id}_count"),
    ]
}

/// TTL for a revocation's Redis keys: until the entry may be purged, at
/// least [`REDIS_MIN_TTL_SECS`]; `None` for a permanent entry.
pub fn redis_ttl_secs(key: &str, value: u64, now: u64) -> Option<u64> {
    match revocation_purge_at(key, value) {
        0 => None,
        purge_at => Some(purge_at.saturating_sub(now).max(REDIS_MIN_TTL_SECS)),
    }
}

/// Publishes a revocation on the Redis bus, with keys that expire when
/// the entry may be purged.
pub fn redis_publish(client: &Client, token_id: &str, value: u64) -> Result<(), Error> {
    let mut con = client.get_connection_with_timeout(Duration::from_secs(5))?;
    let [token_key, action_key, count_key] = redis_keys(token_id);

    let mut pipe = redis::pipe();
    pipe.atomic()
        .set(&token_key, value)
        .ignore()
        .set(&action_key, 1)
        .ignore()
        .incr(&count_key, 1)
        .ignore();
    match redis_ttl_secs(token_id, value, now_secs()) {
        Some(ttl) => {
            let ttl = ttl.min(i64::MAX as u64) as i64;
            for key in [&token_key, &action_key, &count_key] {
                pipe.expire(key, ttl).ignore();
            }
        }
        None => {
            // Permanent: drop any expiry left by an earlier, shorter
            // revocation of the same token.
            for key in [&token_key, &action_key, &count_key] {
                pipe.persist(key).ignore();
            }
        }
    }
    pipe.query::<()>(&mut con)?;
    Ok(())
}

fn redis_delete_many(client: &Client, keys: &[String]) {
    let Ok(mut con) = client.get_connection_with_timeout(Duration::from_secs(5)) else {
        warn!("[RevokedSync] Redis unreachable; purged entries will expire there on their own");
        return;
    };
    let all: Vec<String> = keys.iter().flat_map(|k| redis_keys(k)).collect();
    if let Err(e) = con.del::<_, ()>(all) {
        warn!("[RevokedSync] Redis purge failed: {e}");
    }
}

/// Applies the revocations other nodes published.
fn pull_from_redis(client: &Client, map: &RevokedTokenMap, now: u64) {
    let mut con = match client.get_connection_with_timeout(Duration::from_secs(5)) {
        Ok(con) => con,
        Err(e) => {
            error!("[RevokedSync] Failed to get Redis connection: {e}. Retrying next tick.");
            return;
        }
    };

    let action_keys: Vec<String> = match con.scan_match::<_, String>("*_action") {
        Ok(iter) => iter.collect(),
        Err(e) => {
            error!("[RevokedSync] Failed to scan Redis: {e}");
            return;
        }
    };

    let mut stale: Vec<String> = Vec::new();

    for action_key in action_keys {
        let token_id = action_key.trim_end_matches("_action").to_string();
        let action: Option<String> = con.get(&action_key).unwrap_or(None);

        match action.as_deref() {
            Some("1") => {
                let value: Option<u64> = con.get(format!("token:{token_id}")).unwrap_or(None);
                match value {
                    // The value is gone: its TTL ran out, so the entry is
                    // over. This used to be read as a *permanent*
                    // revocation, which also defeated every purge.
                    None => stale.push(token_id),
                    Some(value) => {
                        // A "never" entry published by an older node:
                        // bound it, here and on the bus.
                        let value = match (value, migrated_purge_at(now)) {
                            (0, Some(bounded)) => {
                                if let Err(e) = redis_publish(client, &token_id, bounded) {
                                    warn!("[RevokedSync] Could not bound legacy Redis entry {token_id}: {e}");
                                }
                                bounded
                            }
                            (value, _) => value,
                        };
                        let purge_at = revocation_purge_at(&token_id, value);
                        if purge_at != 0 && purge_at <= now {
                            stale.push(token_id);
                            continue;
                        }
                        if lmdb_get(&token_id) != Some(value) {
                            if let Err(e) = lmdb_put(&token_id, value) {
                                error!("[RevokedSync] LMDB put error for {token_id}: {e}");
                            }
                        }
                        map.insert(token_id, value);
                    }
                }
            }
            Some("2") => {
                lmdb_delete_many(std::slice::from_ref(&token_id));
                map.remove(&token_id);
            }
            _ => {}
        }
    }

    if !stale.is_empty() {
        let keys: Vec<String> = stale.iter().flat_map(|k| redis_keys(k)).collect();
        if let Err(e) = con.del::<_, ()>(keys) {
            warn!("[RevokedSync] Failed to drop stale Redis keys: {e}");
        } else {
            debug!("[RevokedSync] Dropped {} stale Redis revocations", stale.len());
        }
    }
}

// ───────────────────────────── LMDB ─────────────────────────────

pub fn encode_record(record: RevocationRecord) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&record.revoked_at.to_be_bytes());
    out[8..].copy_from_slice(&record.value.to_be_bytes());
    out
}

/// Reads every layout ever written (see the module notes).
pub fn decode_record(bytes: &[u8]) -> Option<RevocationRecord> {
    let u64_at = |range: std::ops::Range<usize>| {
        bytes.get(range)?.try_into().ok().map(u64::from_be_bytes)
    };
    match bytes.len() {
        0 => Some(RevocationRecord { revoked_at: 0, value: 0 }),
        8 => Some(RevocationRecord { revoked_at: 0, value: u64_at(0..8)? }),
        16 => Some(RevocationRecord {
            revoked_at: u64_at(0..8)?,
            value: u64_at(8..16)?,
        }),
        _ => None,
    }
}

/// Writes one entry, recorded now.
pub fn lmdb_put(token_id: &str, value: u64) -> Result<(), Error> {
    lmdb_put_record(
        token_id,
        RevocationRecord {
            revoked_at: now_secs(),
            value,
        },
    )
}

pub fn lmdb_put_record(token_id: &str, record: RevocationRecord) -> Result<(), Error> {
    let _guard = LMDB_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let env = LMDB_ENV
        .get()
        .ok_or_else(|| anyhow::anyhow!("LMDB is not initialized"))?;
    let db = env.open_db(Some("revoke"))?;
    let mut txn = env.begin_rw_txn()?;
    txn.put(db, &token_id.as_bytes(), &encode_record(record), WriteFlags::empty())?;
    txn.commit()?;
    Ok(())
}

/// Reads one entry's value.
pub fn lmdb_get(token_id: &str) -> Option<u64> {
    lmdb_get_record(token_id).map(|r| r.value)
}

/// Reads one entry, with its recording date.
pub fn lmdb_get_record(token_id: &str) -> Option<RevocationRecord> {
    let _guard = LMDB_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let env = LMDB_ENV.get()?;
    let db = env.open_db(Some("revoke")).ok()?;
    let txn = env.begin_ro_txn().ok()?;
    let bytes = txn.get(db, &token_id.as_bytes()).ok()?;
    decode_record(bytes)
}

/// Deletes several entries in one transaction.
pub fn lmdb_delete_many(keys: &[String]) {
    let _guard = LMDB_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let Some(env) = LMDB_ENV.get() else {
        return;
    };
    let result = (|| -> Result<(), Error> {
        let db = env.open_db(Some("revoke"))?;
        let mut txn = env.begin_rw_txn()?;
        for key in keys {
            match txn.del(db, &key.as_bytes(), None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        txn.commit()?;
        Ok(())
    })();
    if let Err(e) = result {
        error!("[RevokedSync] LMDB delete error: {e}");
    }
}

/// Loads LMDB into `map`, bounding legacy "never" entries on the way.
fn lmdb_read_all_into(map: &RevokedTokenMap) {
    let loaded = match load_revoked_tokens() {
        Ok(loaded) => loaded,
        Err(e) => {
            debug!("[RevokedSync] LMDB read skipped: {e}");
            return;
        }
    };

    let now = now_secs();
    let mut migrated = 0usize;
    for entry in loaded.iter() {
        let (key, mut value) = (entry.key().clone(), *entry.value());
        if value == 0 {
            if let Some(bounded) = migrated_purge_at(now) {
                match lmdb_put_record(&key, RevocationRecord { revoked_at: now, value: bounded }) {
                    Ok(()) => {
                        value = bounded;
                        migrated += 1;
                    }
                    Err(e) => error!("[RevokedSync] Could not bound legacy entry {key}: {e}"),
                }
            }
        }
        map.insert(key, value);
    }
    if migrated > 0 {
        info!(
            "[RevokedSync] {migrated} revocation(s) kept forever by an older version now expire with the tokens they refer to"
        );
    }
}

pub fn load_revoked_tokens() -> Result<Arc<DashMap<String, u64>>, Error> {
    let map = DashMap::new();

    let _guard = LMDB_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let env = LMDB_ENV
        .get()
        .ok_or_else(|| anyhow::anyhow!("LMDB is not initialized"))?;
    let db = env.open_db(Some("revoke"))?;
    let txn = env.begin_ro_txn()?;
    let mut cursor = txn.open_ro_cursor(db)?;

    for result in cursor.iter() {
        let (key, value) = match result {
            Ok(pair) => pair,
            Err(e) => {
                error!("[LMDB] Error while iterating LMDB: {e}");
                continue;
            }
        };
        let Ok(token_id) = std::str::from_utf8(key) else {
            continue;
        };
        if let Some(record) = decode_record(value) {
            map.insert(token_id.to_string(), record.value);
        }
    }

    Ok(Arc::new(map))
}
