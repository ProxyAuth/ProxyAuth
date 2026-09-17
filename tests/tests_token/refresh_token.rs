//! Refresh tokens for API sessions: token format, generations, expiries.

#[cfg(test)]
mod tests {
    use dashmap::DashMap;
    use proxyauth::config::config::{AppConfig, RouteConfig, max_token_lifetime};
    use proxyauth::revoke::load::{
        GenerationStep, advance_generation, current_generation, is_plain_token_id, pack_rotation,
        refresh_key, revocation_purge_at, unpack_rotation,
    };
    use proxyauth::token::refresh_token::pair_expiries;
    use proxyauth::token::security::{TokenData, TokenKind};
    use std::sync::Arc;

    const NOW: u64 = 1_900_000_000;

    // ── token format ─────────────────────────────────────────

    #[test]
    fn a_refresh_token_is_marked_as_such() {
        let data = TokenData {
            index_user: 4,
            issued_at: NOW,
            session_started_at: NOW,
            kind: TokenKind::Refresh,
            ..TokenData::default()
        };
        assert_eq!(data.encode(), format!("4:{NOW}:{NOW};r"));
        assert_eq!(TokenData::parse(&data.encode()), Some(data));
    }

    #[test]
    fn a_refreshed_pair_carries_its_generation() {
        let access = TokenData {
            index_user: 4,
            issued_at: NOW,
            session_started_at: NOW - 60,
            generation: 3,
            ..TokenData::default()
        };
        assert_eq!(access.encode(), format!("4:{NOW}:{};g=3", NOW - 60));
        assert_eq!(TokenData::parse(&access.encode()), Some(access.clone()));

        let refresh = TokenData { kind: TokenKind::Refresh, ..access };
        assert_eq!(refresh.encode(), format!("4:{NOW}:{};r;g=3", NOW - 60));
        assert_eq!(TokenData::parse(&refresh.encode()), Some(refresh));
    }

    #[test]
    fn a_plain_access_token_keeps_the_older_format() {
        let data = TokenData {
            index_user: 1,
            issued_at: NOW,
            session_started_at: NOW,
            ..TokenData::default()
        };
        assert_eq!(data.encode(), format!("1:{NOW}:{NOW}"));
        assert_eq!(TokenData::parse("1").unwrap().kind, TokenKind::Access);
    }

    #[test]
    fn unknown_or_repeated_extensions_are_refused() {
        for raw in [
            "1:2:3;x",
            "1:2:3;r;r",
            "1:2:3;g=1;g=2",
            "1:2:3;g=",
            "1:2:3;g=-1",
            "1:2:3;g=99999999999",
            "1:2:3;",
        ] {
            assert_eq!(TokenData::parse(raw), None, "{raw:?}");
        }
    }

    // ── generations ──────────────────────────────────────────

    fn map() -> proxyauth::revoke::db::RevokedTokenMap {
        Arc::new(DashMap::new())
    }

    #[test]
    fn a_session_starts_at_generation_zero() {
        assert_eq!(current_generation("abc", &map()), 0);
    }

    #[test]
    fn a_refresh_moves_the_session_forward() {
        let m = map();
        let step = advance_generation("abc", 0, NOW + 3600, &m);
        assert_eq!(
            step,
            GenerationStep::Advanced { generation: 1, value: pack_rotation(1, NOW + 3600) }
        );
        assert_eq!(current_generation("abc", &m), 1);

        let step = advance_generation("abc", 1, NOW + 7200, &m);
        assert!(matches!(step, GenerationStep::Advanced { generation: 2, .. }));
        assert_eq!(unpack_rotation(*m.get(&refresh_key("abc")).unwrap()), (2, NOW + 7200));
    }

    #[test]
    fn a_used_refresh_token_is_stale() {
        let m = map();
        advance_generation("abc", 0, NOW + 3600, &m);
        assert_eq!(
            advance_generation("abc", 0, NOW + 3600, &m),
            GenerationStep::Stale { current: 1 }
        );
        assert_eq!(current_generation("abc", &m), 1, "a stale attempt changes nothing");
    }

    #[test]
    fn a_generation_ahead_of_this_instance_is_stale_too() {
        assert_eq!(
            advance_generation("unknown", 2, NOW + 3600, &map()),
            GenerationStep::Stale { current: 0 }
        );
    }

    #[test]
    fn generation_records_are_purged_with_their_last_refresh_token() {
        assert_eq!(revocation_purge_at(&refresh_key("abc"), pack_rotation(5, NOW + 99)), NOW + 99);
    }

    #[test]
    fn generation_records_cannot_be_revoked_as_token_ids() {
        assert!(!is_plain_token_id("refresh:abc"));
        assert!(is_plain_token_id("abc"));
    }

    // ── expiries ─────────────────────────────────────────────

    #[test]
    fn pair_expiries_follow_their_lifetimes() {
        assert_eq!(pair_expiries(NOW, 600, 86400, NOW, 0), (NOW + 600, NOW + 86400));
    }

    #[test]
    fn pair_expiries_never_pass_the_session_end() {
        // Session began an hour ago and is capped at two hours.
        let started = NOW - 3600;
        assert_eq!(
            pair_expiries(NOW, 600, 86400, started, 7200),
            (NOW + 600, started + 7200)
        );
        assert_eq!(
            pair_expiries(NOW, 7200, 86400, started, 7200),
            (started + 7200, started + 7200)
        );
    }

    // ── configuration ────────────────────────────────────────

    fn config(extra: serde_json::Value) -> AppConfig {
        let mut json = serde_json::json!({
            "token_expiry_seconds": 600,
            "secret": "refresh-token-config-test-secret-refresh-token-config-test",
            "users": [],
            "log": { "type": "disabled" },
            "smtp": null
        });
        json.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::from_value(json).unwrap()
    }

    fn routes(yaml: &str) -> RouteConfig {
        serde_yaml::from_str::<RouteConfig>(yaml).unwrap().expand_vhost_groups()
    }

    #[test]
    fn disabled_by_default() {
        let cfg = config(serde_json::json!({}));
        assert_eq!(cfg.refresh_token_expiry_seconds, 0);
    }

    #[test]
    fn vhosts_and_routes_override_the_global_lifetime() {
        let cfg = config(serde_json::json!({ "refresh_token_expiry_seconds": 86400 }));
        let r = routes(
            r#"
vhosts:
  - vhost: ["api.example.com"]
    refresh_token_expiry_seconds: 604800
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
  - vhost: ["internal.example.com"]
    refresh_token_expiry_seconds: 0
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
routes:
  - prefix: "/"
    target: "http://127.0.0.1:1"
"#,
        );
        let lifetime = |host: &str| {
            r.routes
                .iter()
                .find(|x| x.vhost.iter().any(|v| v == host) || (host.is_empty() && x.vhost.is_empty()))
                .unwrap()
                .resolved_refresh_token_expiry(&cfg)
        };
        assert_eq!(lifetime("api.example.com"), 604800);
        assert_eq!(lifetime("internal.example.com"), 0);
        assert_eq!(lifetime(""), 86400);
    }

    #[test]
    fn revocations_outlive_the_longest_token() {
        let cfg = config(serde_json::json!({ "refresh_token_expiry_seconds": 86400 }));
        let r = routes(
            r#"
vhosts:
  - vhost: ["api.example.com"]
    refresh_token_expiry_seconds: 604800
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
"#,
        );
        assert_eq!(max_token_lifetime(&cfg, &r.routes), 604800);
        assert_eq!(max_token_lifetime(&config(serde_json::json!({})), &[]), 600);
    }

    #[test]
    fn the_setting_survives_a_config_rewrite() {
        let cfg = config(serde_json::json!({ "refresh_token_expiry_seconds": 86400 }));
        assert_eq!(serde_json::to_value(&cfg).unwrap()["refresh_token_expiry_seconds"], 86400);
    }
}
