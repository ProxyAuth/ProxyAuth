use proxyauth::revoke::load::is_token_revoked;
use proxyauth::revoke::db::RevokedTokenMap;
use dashmap::DashMap;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_revoked_map() -> RevokedTokenMap {
        Arc::new(DashMap::new())
    }

    #[test]
    fn token_not_in_map_is_not_revoked() {
        let map = make_revoked_map();
        assert!(!is_token_revoked("token-abc", &map));
    }

    #[test]
    fn token_with_zero_exp_is_revoked() {
        let map = make_revoked_map();
        map.insert("tok-1".into(), 0);
        assert!(is_token_revoked("tok-1", &map));
    }

    #[test]
    fn token_with_past_exp_is_revoked() {
        let map = make_revoked_map();
        // Unix timestamp 1 is in the past
        map.insert("tok-2".into(), 1);
        assert!(is_token_revoked("tok-2", &map));
    }

    #[test]
    fn token_with_future_exp_is_not_revoked() {
        let map = make_revoked_map();
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour from now
        map.insert("tok-3".into(), future);
        assert!(!is_token_revoked("tok-3", &map));
    }

    #[test]
    fn multiple_tokens_independent() {
        let map = make_revoked_map();
        map.insert("revoked-1".into(), 0);
        map.insert("revoked-2".into(), 1);
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 7200;
        map.insert("valid-1".into(), future);

        assert!(is_token_revoked("revoked-1", &map));
        assert!(is_token_revoked("revoked-2", &map));
        assert!(!is_token_revoked("valid-1", &map));
        assert!(!is_token_revoked("unknown", &map));
    }

    #[test]
    fn empty_map_revokes_nothing() {
        let map = make_revoked_map();
        assert!(!is_token_revoked("anything", &map));
        assert!(!is_token_revoked("", &map));
    }
}
