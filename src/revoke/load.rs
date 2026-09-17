use crate::revoke::db::{LMDB_ENV, REDIS, RevokedTokenMap};
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

/// Whether a token must be refused.
///
/// A token is refused as soon as its id is in the store. The stored value
/// is **not** a start date: it is when the entry may be forgotten (see
/// [`revocation_purge_at`], used by the purge in the sync loop).
///
/// This used to read the value as "refuse from": an entry dated in the
/// future did not revoke anything yet, and the purge deleted it at that
/// very date — so `/adm/revoke` with an `exp` never revoked the token at
/// all. Delayed refusal, needed by session renewal, has its own entries
/// (`rotated:<id>`, below).
pub fn is_token_revoked(token_id: &str, revoked_tokens: &RevokedTokenMap) -> bool {
    if revoked_tokens.contains_key(token_id) {
        return true;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    is_rotated_out(token_id, revoked_tokens, now)
}

/// How long `/adm/revoke` keeps a revocation record.
///
/// A token lives at most `token_lifetime_secs`, so every token that
/// exists at `now` has expired by `now + token_lifetime_secs`: past that
/// date the record protects nothing and can be dropped safely. The admin
/// endpoint only knows the token id, so that bound is the one it can
/// prove. Nothing is kept forever.
pub fn revocation_record_until(now: u64, token_lifetime_secs: u64) -> u64 {
    now.saturating_add(token_lifetime_secs).max(1)
}

/// How long `/logout` keeps the record of the token it revokes: until
/// that token's own expiry, which is known there. Never `0`, so a logout
/// never creates a permanent entry.
pub fn logout_record_until(token_expires_at: u64, now: u64) -> u64 {
    token_expires_at.max(now).max(1)
}

/// Whether `token_id` names a regular token rather than one of the
/// store's internal keys.
pub fn is_plain_token_id(token_id: &str) -> bool {
    !token_id.trim().is_empty() && !token_id.starts_with(ROTATED_PREFIX)
}

// ───────────────────────── delayed revocation ─────────────────────────
//
// A renewed session keeps its previous token alive for a short grace
// period, then refuses it until that token would have expired anyway.
// Two instants are needed — when refusal starts and when the record can
// be forgotten — while the revocation store holds one `u64` per key
// (in memory, in LMDB and on the Redis bus alike).
//
// Such entries therefore live under their own key, `rotated:<token id>`,
// with both instants packed into the value: refusal start in the high
// 32 bits, purge time in the low 32 bits (Unix seconds, valid until
// 2106). Plain revocations keep their key and format untouched, so the
// sync loop, LMDB and Redis carry these entries without any change.

const ROTATED_PREFIX: &str = "rotated:";

/// Key under which a renewed token's delayed revocation is stored.
pub fn rotated_key(token_id: &str) -> String {
    format!("{ROTATED_PREFIX}{token_id}")
}

/// Packs `(refuse_from, purge_at)` into one store value.
pub fn pack_rotation(refuse_from: u64, purge_at: u64) -> u64 {
    (refuse_from.min(u32::MAX as u64) << 32) | purge_at.min(u32::MAX as u64)
}

/// Unpacks a value written by [`pack_rotation`].
pub fn unpack_rotation(value: u64) -> (u64, u64) {
    (value >> 32, value & u32::MAX as u64)
}

fn is_rotated_out(token_id: &str, revoked_tokens: &RevokedTokenMap, now: u64) -> bool {
    match revoked_tokens.get(&rotated_key(token_id)) {
        Some(value) => now >= unpack_rotation(*value).0,
        None => false,
    }
}

/// When a store entry can be forgotten, whatever its kind. `0` ("never")
/// only comes from data written by older versions, and is bounded as soon
/// as the sync loop reads it. Used by the purge in the sync loop, which would otherwise read
/// a packed rotation value as a date centuries away.
pub fn revocation_purge_at(key: &str, value: u64) -> u64 {
    if key.starts_with(ROTATED_PREFIX) {
        unpack_rotation(value).1
    } else {
        value
    }
}

/// Records that `token_id` stops being accepted at `refuse_from`, and
/// that the record can be dropped at `purge_at` (the token's own
/// expiry). Goes through the same store as any revocation, so every
/// node sharing Redis applies it.
pub async fn revoke_token_after(
    token_id: &str,
    refuse_from: u64,
    purge_at: u64,
    revoked_tokens: &RevokedTokenMap,
) -> Result<()> {
    let purge_at = purge_at.max(refuse_from).max(1);
    revoke_token(
        &rotated_key(token_id),
        Some(pack_rotation(refuse_from, purge_at)),
        revoked_tokens,
    )
    .await
}

/// Records a revocation: in memory at once (the token is refused from
/// the next request), then in LMDB and, when configured, on the Redis
/// bus for the other instances.
///
/// `token_exp` is when the entry may be forgotten. Callers always pass
/// one; `None` is only kept for compatibility and stores `0`, which the
/// sync loop bounds on its next pass.
pub async fn revoke_token(
    token_id: &str,
    token_exp: Option<u64>,
    revoked_tokens: &RevokedTokenMap,
) -> Result<()> {
    let value = token_exp.unwrap_or(0);

    revoked_tokens.insert(token_id.to_string(), value);

    let mut persisted = false;

    if LMDB_ENV.get().is_some() {
        crate::revoke::db::lmdb_put(token_id, value)?;
        persisted = true;
    }

    if let Some(client) = REDIS.get() {
        crate::revoke::db::redis_publish(client, token_id, value)?;
        persisted = true;
    }

    if persisted {
        Ok(())
    } else {
        Err(anyhow::anyhow!("No Redis or LMDB backend configured"))
    }
}
