//! The revocation store's persistence and sync loop, against a real LMDB
//! and, when `PROXYAUTH_TEST_REDIS` is set (for example
//! `redis://127.0.0.1:6379/15`), a real Redis.
//!
//! A separate test binary: LMDB and Redis clients are process-wide, and
//! these tests read and purge them.
//!
//! ```bash
//! cargo test --test revoke_sync
//! PROXYAUTH_TEST_REDIS=redis://127.0.0.1:6379/15 cargo test --test revoke_sync
//! ```

use dashmap::DashMap;
use proxyauth::revoke::db::{
    LMDB_ENV, REDIS, REDIS_MIN_TTL_SECS, RevokedTokenMap, lmdb_get, lmdb_get_record, lmdb_put,
    set_token_lifetime, start_revoked_token_ttl, sync_tick,
};
use proxyauth::revoke::load::{is_token_revoked, pack_rotation, revoke_token, rotated_key};
use redis::Commands;
use serial_test::serial;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LIFETIME: u64 = 3600;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn map() -> RevokedTokenMap {
    Arc::new(DashMap::new())
}

fn redis_url() -> Option<String> {
    std::env::var("PROXYAUTH_TEST_REDIS").ok().filter(|u| !u.is_empty())
}

/// Opens a throwaway LMDB (and Redis, if configured) once for the binary.
async fn setup() {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = LOCK.lock().await;
    if LMDB_ENV.get().is_some() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("proxyauth-revoke-sync-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // SAFETY: set once, before the store reads it, under the lock above.
    unsafe {
        std::env::set_var("LMDB_PATH", &dir);
    }
    if let Some(url) = redis_url() {
        let client = redis::Client::open(url.as_str()).unwrap();
        let mut con = client.get_connection().expect("PROXYAUTH_TEST_REDIS is not reachable");
        let _: () = redis::cmd("FLUSHDB").query(&mut con).unwrap();
    }
    set_token_lifetime(LIFETIME as i64);
    start_revoked_token_ttl(map(), Duration::from_secs(3600), redis_url()).await;
}

fn redis() -> Option<redis::Connection> {
    REDIS.get().map(|c| c.get_connection().unwrap())
}

macro_rules! require_redis {
    () => {
        match redis() {
            Some(con) => con,
            None => {
                eprintln!("PROXYAUTH_TEST_REDIS not set: skipping");
                return;
            }
        }
    };
}

// ── LMDB ─────────────────────────────────────────────────────

#[actix_web::test]
#[serial]
async fn a_revocation_is_written_to_lmdb_immediately() {
    setup().await;
    let m = map();
    revoke_token("lmdb-now", Some(now() + 600), &m).await.unwrap();
    assert!(is_token_revoked("lmdb-now", &m));
    assert_eq!(lmdb_get("lmdb-now"), Some(*m.get("lmdb-now").unwrap()));

    let record = lmdb_get_record("lmdb-now").unwrap();
    let t = now();
    assert!(record.revoked_at <= t && record.revoked_at + 5 >= t, "recording date kept");
}

/// Writes raw bytes, the way an older version stored its entries.
fn lmdb_put_raw(key: &str, bytes: &[u8]) {
    use lmdb::Transaction;
    let env = LMDB_ENV.get().unwrap();
    let db = env.open_db(Some("revoke")).unwrap();
    let mut txn = env.begin_rw_txn().unwrap();
    txn.put(db, &key.as_bytes(), &bytes, lmdb::WriteFlags::empty()).unwrap();
    txn.commit().unwrap();
}

#[actix_web::test]
#[serial]
async fn entries_kept_forever_by_older_versions_get_an_end_date() {
    setup().await;
    lmdb_put_raw("legacy-forever", &[]);
    lmdb_put_raw("legacy-dated", &(now() + 120).to_be_bytes());

    let m = map();
    let before = now();
    sync_tick(&m);

    let forever = lmdb_get_record("legacy-forever").unwrap();
    assert!(forever.value >= before + LIFETIME && forever.value <= now() + LIFETIME);
    assert!(forever.revoked_at >= before);
    assert_eq!(*m.get("legacy-forever").unwrap(), forever.value);
    assert!(is_token_revoked("legacy-forever", &m), "still refused until then");

    let dated = lmdb_get_record("legacy-dated").unwrap();
    assert_eq!(dated.revoked_at, 0, "an old dated entry is read as-is");
    assert!(is_token_revoked("legacy-dated", &m));
}

#[actix_web::test]
#[serial]
async fn the_purge_cleans_memory_and_lmdb() {
    setup().await;
    let m = map();
    let t = now();
    revoke_token("purge-old", Some(t - 10), &m).await.unwrap();
    revoke_token("purge-future", Some(t + 600), &m).await.unwrap();
    revoke_token(&rotated_key("purge-rot"), Some(pack_rotation(t - 20, t - 10)), &m)
        .await
        .unwrap();

    sync_tick(&m);

    assert!(!m.contains_key("purge-old"));
    assert_eq!(lmdb_get("purge-old"), None);
    assert!(!m.contains_key("rotated:purge-rot"));
    assert_eq!(lmdb_get("rotated:purge-rot"), None);

    assert!(m.contains_key("purge-future"));
    assert!(lmdb_get("purge-future").is_some());
}

#[actix_web::test]
#[serial]
async fn another_process_on_the_host_is_picked_up_from_lmdb() {
    setup().await;
    lmdb_put("other-process", now() + 600).unwrap();
    let m = map();
    sync_tick(&m);
    assert!(is_token_revoked("other-process", &m));
}

#[actix_web::test]
#[serial]
async fn the_loop_purges_without_redis_configured() {
    setup().await;
    if REDIS.get().is_some() {
        eprintln!("Redis configured: covered by the Redis tests instead");
        return;
    }
    // The loop used to start only when `redis` was set.
    let m = map();
    lmdb_put("no-redis-expired", now() - 1).unwrap();
    start_revoked_token_ttl(m.clone(), Duration::from_millis(50), None).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(lmdb_get("no-redis-expired"), None, "purged by the running loop");
}

// ── Redis ────────────────────────────────────────────────────

#[actix_web::test]
#[serial]
async fn all_redis_keys_expire_with_the_revocation() {
    setup().await;
    let mut con = require_redis!();
    let m = map();

    revoke_token("r-ttl", Some(now() + 1200), &m).await.unwrap();
    for key in ["token:r-ttl", "r-ttl_action", "r-ttl_count"] {
        let ttl: i64 = con.ttl(key).unwrap();
        assert!((1190..=1200).contains(&ttl), "{key}: ttl {ttl}");
    }

    revoke_token("r-short", Some(now() + 5), &m).await.unwrap();
    let ttl: i64 = con.ttl("r-short_action").unwrap();
    assert!(ttl >= REDIS_MIN_TTL_SECS as i64 - 2, "short entries still reach every node: {ttl}");

}

#[actix_web::test]
#[serial]
async fn a_forever_entry_from_an_older_node_is_bounded_on_the_bus() {
    setup().await;
    let mut con = require_redis!();
    let _: () = con.set("token:peer-forever", 0).unwrap();
    let _: () = con.set("peer-forever_action", 1).unwrap();

    let m = map();
    let before = now();
    sync_tick(&m);

    let value = *m.get("peer-forever").expect("applied");
    assert!(value >= before + LIFETIME, "bounded, not forever");
    assert_eq!(lmdb_get("peer-forever"), Some(value));
    let stored: u64 = con.get("token:peer-forever").unwrap();
    assert_eq!(stored, value, "republished with its end date");
    let ttl: i64 = con.ttl("peer-forever_action").unwrap();
    assert!(ttl > 0 && ttl <= LIFETIME as i64, "and an expiry: {ttl}");
}

#[actix_web::test]
#[serial]
async fn a_revocation_from_another_node_is_applied_and_persisted() {
    setup().await;
    let mut con = require_redis!();
    let exp = now() + 900;
    // What another node's revoke_token publishes.
    let _: () = con.set_ex("token:from-peer", exp, 900).unwrap();
    let _: () = con.set_ex("from-peer_action", 1, 900).unwrap();

    let m = map();
    sync_tick(&m);

    assert!(is_token_revoked("from-peer", &m));
    assert_eq!(*m.get("from-peer").unwrap(), exp);
    assert_eq!(lmdb_get("from-peer"), Some(exp));
}

#[actix_web::test]
#[serial]
async fn an_orphan_action_key_is_dropped_not_made_permanent() {
    setup().await;
    let mut con = require_redis!();
    // Left by earlier versions: `token:` expired after 300s, the action
    // key never did. It used to come back as a permanent revocation on
    // every tick.
    let _: () = con.set("orphan_action", 1).unwrap();
    let _: () = con.set("orphan_count", 3).unwrap();

    let m = map();
    sync_tick(&m);

    assert!(!m.contains_key("orphan"));
    assert_eq!(lmdb_get("orphan"), None);
    let exists: bool = con.exists("orphan_action").unwrap();
    assert!(!exists, "stale keys are removed from Redis");
    let exists: bool = con.exists("orphan_count").unwrap();
    assert!(!exists);
}

#[actix_web::test]
#[serial]
async fn an_expired_entry_left_in_redis_is_dropped() {
    setup().await;
    let mut con = require_redis!();
    let _: () = con.set("token:old-entry", now() - 60).unwrap();
    let _: () = con.set("old-entry_action", 1).unwrap();

    let m = map();
    sync_tick(&m);

    assert!(!m.contains_key("old-entry"));
    assert_eq!(lmdb_get("old-entry"), None);
    let exists: bool = con.exists("token:old-entry").unwrap();
    assert!(!exists);
}

#[actix_web::test]
#[serial]
async fn the_purge_also_cleans_redis() {
    setup().await;
    let mut con = require_redis!();
    let m = map();
    // Published with the minimum TTL, but already past its purge date
    // for this node.
    revoke_token("r-purge", Some(now() + 1), &m).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;

    sync_tick(&m);

    assert!(!m.contains_key("r-purge"));
    assert_eq!(lmdb_get("r-purge"), None);
    for key in ["token:r-purge", "r-purge_action", "r-purge_count"] {
        let exists: bool = con.exists(key).unwrap();
        assert!(!exists, "{key} removed from Redis");
    }
}

#[actix_web::test]
#[serial]
async fn a_revocation_survives_every_tick_until_its_date() {
    setup().await;
    let m = map();
    revoke_token("r-keep", Some(now() + 600), &m).await.unwrap();
    for _ in 0..3 {
        sync_tick(&m);
    }
    assert!(is_token_revoked("r-keep", &m));
    assert!(lmdb_get("r-keep").is_some());
}

#[actix_web::test]
#[serial]
async fn refresh_generations_travel_between_instances() {
    setup().await;
    let _con = require_redis!();
    use proxyauth::revoke::load::{
        GenerationStep, advance_generation, current_generation, publish_generation,
    };
    let node_a = map();
    let GenerationStep::Advanced { value, .. } =
        advance_generation("api-session", 0, now() + 600, &node_a)
    else {
        panic!("first refresh must advance");
    };
    publish_generation("api-session", value, &node_a).await.unwrap();

    // Another instance, starting from nothing, learns the generation
    // on its next tick.
    let node_b = map();
    sync_tick(&node_b);
    assert_eq!(current_generation("api-session", &node_b), 1);
    assert!(lmdb_get("refresh:api-session").is_some());
}

