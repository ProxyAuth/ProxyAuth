use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::thread::{self, sleep};
use lmdb::Transaction;
use lmdb::Cursor;
use std::path::Path;

use redis::{Client, Commands};
use once_cell::sync::OnceCell;
use lmdb::{Environment, DatabaseFlags};

pub static REDIS: OnceCell<Client> = OnceCell::new();
pub static LMDB_ENV: OnceCell<lmdb::Environment> = OnceCell::new();

pub type RevokedTokenMap = Arc<RwLock<HashMap<String, u64>>>;

pub async fn start_revoked_token_ttl(
    revoked_tokens: RevokedTokenMap,
    every: Duration,
    redis_url: Option<String>,
) {

    let opt_path: Option<String> = Some("/opt/proxyauth/db/".to_string());


    if let Some(url) = redis_url {
        if REDIS.get().is_none() {
            let client = Client::open(url).expect("Invalid Redis URL");
            REDIS.set(client).expect("REDIS client already initialized");
        }

        thread::spawn(move || {
            loop {
                let client = match REDIS.get() {
                    Some(c) => c,
                      None => {
                          eprintln!("[RevokedSync] REDIS client not initialized");
                          sleep(every);
                          continue;
                      }
                };

                let mut con = match client.get_connection() {
                    Ok(c) => c,
                      Err(e) => {
                          eprintln!("[RevokedSync] Redis connection error: {}", e);
                          sleep(every);
                          continue;
                      }
                };

                let keys: Vec<String> = match con.keys("token:*") {
                    Ok(k) => k,
                      Err(e) => {
                          eprintln!("[RevokedSync] Redis key scan error: {}", e);
                          sleep(every);
                          continue;
                      }
                };

                let mut map = HashMap::new();
                for key in &keys {
                    let token_id = key.trim_start_matches("token:").to_string();
                    if let Ok(exp) = con.get::<_, u64>(key) {
                        map.insert(token_id, exp);
                    }
                }

                {
                    let mut cache = revoked_tokens.write().unwrap();
                    *cache = map;
                }

                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let mut cache = revoked_tokens.write().unwrap();
                let before = cache.len();
                cache.retain(|_, &mut exp| exp == 0 || exp > now);
                let after = cache.len();

                if before != after {
                    println!("[RevokedSync] Purged {} expired tokens", before - after);
                }

                sleep(every);
            }
        });
    } else if let Some(path) = opt_path {
        println!("[RevokedSync] Redis not configured, LMDB used from '{}'", path);
    }
}

pub fn load_revoked_tokens() -> Result<RevokedTokenMap, anyhow::Error> {

    let opt_path: Option<String> = Some("/opt/proxyauth/db/".to_string());

    if let Some(client) = REDIS.get() {
        let mut con = client.get_connection()?;
        let keys: Vec<String> = con.keys("token:*")?;
        let mut map = HashMap::new();

        for key in keys {
            let token_id = key.trim_start_matches("token:").to_string();
            match con.get::<_, u64>(&key) {
                Ok(exp) => {
                    map.insert(token_id, exp);
                }
                Err(e) => {
                    eprintln!("Error read token for {}: {}", key, e);
                }
            }
        }

        Ok(Arc::new(RwLock::new(map)))
    } else if let Some(path) = opt_path {
        let env = Environment::new()
        .set_max_dbs(1)
        .open(Path::new(&path))?;

        let db = env.create_db(Some("revoke"), DatabaseFlags::empty())?;
        let txn = env.begin_ro_txn()?;
        let mut map = HashMap::new();
        let mut cursor = txn.open_ro_cursor(db)?;

        for (key, value) in cursor.iter() {
            let token_id = match std::str::from_utf8(key) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            let exp = if value.len() == 8 {
                match value.try_into().map(u64::from_be_bytes) {
                    Ok(exp) => exp,
                    Err(_) => continue,
                }
            } else if value.is_empty() {
                0
            } else {
                continue;
            };

            map.insert(token_id, exp);
        }

        Ok(Arc::new(RwLock::new(map)))
    } else {
        Err(anyhow::anyhow!("No Redis or LMDB configuration provided"))
    }
}
