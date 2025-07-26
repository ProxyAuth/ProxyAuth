use crate::revoke::db::{RevokedTokenMap, REDIS, LMDB_ENV};
use redis::Commands;
use std::time::{SystemTime, UNIX_EPOCH};
use lmdb::{WriteFlags, Transaction};

pub fn is_token_revoked(token_id: &str, revoked_tokens: &RevokedTokenMap) -> bool {
    let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();

    let map = revoked_tokens.read().unwrap();
    match map.get(token_id) {
        Some(&0) => true,
        Some(&exp) if now >= exp => true,
        _ => false,
    }
}

pub async fn revoke_token(
    token_id: &str,
    token_exp: Option<u64>,
    revoked_tokens: &RevokedTokenMap,
) -> anyhow::Result<()> {
    let value = token_exp.unwrap_or(0);

    {
        let mut map = revoked_tokens.write().unwrap();
        map.insert(token_id.to_string(), value);
    }

    if let Some(client) = REDIS.get() {
        let mut con = client.get_connection()?;
        let redis_key = format!("token:{}", token_id);
        let _: () = con.set(&redis_key, value)?;
        return Ok(());
    }

    if let Some(env) = LMDB_ENV.get() {
        let db = env.open_db(Some("revoke"))?;
        let mut txn = env.begin_rw_txn()?;
        let key = token_id.as_bytes();

        let bytes = if value == 0 {
            &[][..]
        } else {
            &value.to_be_bytes()[..]
        };

        txn.put(db, &key, &bytes, WriteFlags::empty())?;
        txn.commit()?;

        return Ok(());
    }

    Err(anyhow::anyhow!("No Redis or LMDB backend configured"))
}
