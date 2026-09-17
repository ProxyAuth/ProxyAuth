//! Session renewal: the renewal decision, the token data format, the
//! delayed revocation of a replaced token, and the renewed cookie.

#[cfg(test)]
mod tests {
    use dashmap::DashMap;
    use proxyauth::config::config::{RouteConfig, SessionRefreshPolicy};
    use proxyauth::revoke::load::{
        is_token_revoked, pack_rotation, revocation_purge_at, revoke_token_after, rotated_key,
        unpack_rotation,
    };
    use proxyauth::token::refresh::{RenewalDecision, decide, renewed_expiry, session_cookie};
    use proxyauth::token::security::{TokenData, ValidSession, now_secs};
    use std::sync::Arc;

    const LIFETIME: u64 = 3600;
    const NOW: u64 = 1_900_000_000;

    fn policy(interval: u64, grace: u64, max_lifetime: u64) -> SessionRefreshPolicy {
        SessionRefreshPolicy {
            interval_secs: interval,
            grace_secs: grace,
            max_lifetime_secs: max_lifetime,
        }
    }

    /// A session whose token was issued `age` seconds before `NOW`, in a
    /// session that began `session_age` seconds before `NOW`.
    fn session(age: u64, session_age: u64) -> ValidSession {
        let issued_at = NOW - age;
        ValidSession {
            username: "admin".into(),
            token_id: "old-token".into(),
            remaining_secs: LIFETIME - age,
            expires_at: issued_at + LIFETIME,
            data: TokenData {
                index_user: 0,
                issued_at,
                session_started_at: NOW - session_age,
            },
        }
    }

    // ── decision ─────────────────────────────────────────────

    #[test]
    fn disabled_by_default() {
        let p = policy(0, 30, 0);
        assert!(!p.enabled());
        assert_eq!(decide(&p, &session(3000, 3000), LIFETIME, NOW), RenewalDecision::Keep);
    }

    #[test]
    fn keeps_a_token_younger_than_the_interval() {
        let p = policy(900, 30, 0);
        assert_eq!(decide(&p, &session(0, 0), LIFETIME, NOW), RenewalDecision::Keep);
        assert_eq!(decide(&p, &session(899, 899), LIFETIME, NOW), RenewalDecision::Keep);
    }

    #[test]
    fn renews_once_the_interval_has_passed() {
        let p = policy(900, 30, 0);
        assert_eq!(decide(&p, &session(900, 900), LIFETIME, NOW), RenewalDecision::Renew);
        assert_eq!(decide(&p, &session(3500, 3500), LIFETIME, NOW), RenewalDecision::Renew);
    }

    #[test]
    fn the_interval_counts_from_the_last_renewal_not_the_login() {
        let p = policy(900, 30, 0);
        // Logged in 5 hours ago, token renewed 10 minutes ago.
        assert_eq!(decide(&p, &session(600, 18_000), LIFETIME, NOW), RenewalDecision::Keep);
    }

    #[test]
    fn a_session_past_its_max_lifetime_is_too_old() {
        let p = policy(900, 30, 8 * 3600);
        assert_eq!(
            decide(&p, &session(100, 8 * 3600), LIFETIME, NOW),
            RenewalDecision::TooOld
        );
        assert_eq!(
            decide(&p, &session(100, 8 * 3600 - 1), LIFETIME, NOW),
            RenewalDecision::Keep
        );
    }

    #[test]
    fn max_lifetime_applies_even_without_renewal() {
        let p = policy(0, 30, 600);
        assert_eq!(decide(&p, &session(700, 700), LIFETIME, NOW), RenewalDecision::TooOld);
    }

    #[test]
    fn no_renewal_when_the_current_token_already_reaches_the_hard_limit() {
        // Session limit in 35 minutes; current token expires in 43: a
        // new token could not last longer, so none is issued.
        let p = policy(900, 30, 3600);
        let s = session(1000, 1500);
        assert!(s.expires_at >= s.data.session_started_at + 3600);
        assert_eq!(decide(&p, &s, LIFETIME, NOW), RenewalDecision::Keep);
    }

    #[test]
    fn legacy_tokens_are_aged_from_their_remaining_lifetime() {
        let p = policy(900, 30, 0);
        let mut s = session(1200, 1200);
        s.data.issued_at = 0;
        s.data.session_started_at = 0;
        assert_eq!(decide(&p, &s, LIFETIME, NOW), RenewalDecision::Renew);

        let mut fresh = session(60, 60);
        fresh.data.issued_at = 0;
        fresh.data.session_started_at = 0;
        assert_eq!(decide(&p, &fresh, LIFETIME, NOW), RenewalDecision::Keep);
    }

    #[test]
    fn renewed_tokens_get_a_full_lifetime_capped_by_the_hard_limit() {
        assert_eq!(renewed_expiry(&policy(900, 30, 0), NOW - 5000, LIFETIME, NOW), NOW + LIFETIME);
        let capped = renewed_expiry(&policy(900, 30, 6000), NOW - 5000, LIFETIME, NOW);
        assert_eq!(capped, NOW - 5000 + 6000);
    }

    // ── token data ───────────────────────────────────────────

    #[test]
    fn token_data_round_trips() {
        let data = TokenData {
            index_user: 7,
            issued_at: 1_800_000_000,
            session_started_at: 1_790_000_000,
        };
        assert_eq!(data.encode(), "7:1800000000:1790000000");
        assert_eq!(TokenData::parse(&data.encode()), Some(data));
    }

    #[test]
    fn tokens_issued_before_renewal_existed_still_parse() {
        assert_eq!(
            TokenData::parse("3"),
            Some(TokenData {
                index_user: 3,
                issued_at: 0,
                session_started_at: 0
            })
        );
    }

    #[test]
    fn malformed_token_data_is_refused() {
        for raw in ["", "x", "1:y", "1:2:z", "1:2:3:4", "-1:2:3"] {
            assert_eq!(TokenData::parse(raw), None, "{raw:?}");
        }
    }

    // ── delayed revocation ───────────────────────────────────

    #[test]
    fn rotation_values_pack_and_unpack() {
        let v = pack_rotation(1_900_000_030, 1_900_003_600);
        assert_eq!(unpack_rotation(v), (1_900_000_030, 1_900_003_600));
        assert_ne!(v, 0, "0 would mean a permanent revocation");
    }

    #[test]
    fn purge_time_depends_on_the_kind_of_entry() {
        let v = pack_rotation(100, 200);
        assert_eq!(revocation_purge_at(&rotated_key("abc"), v), 200);
        assert_eq!(revocation_purge_at("abc", 12345), 12345);
        assert_eq!(revocation_purge_at("abc", 0), 0);
    }

    #[test]
    fn a_replaced_token_works_until_the_grace_ends() {
        let map = Arc::new(DashMap::new());
        let now = now_secs();

        map.insert(rotated_key("in-grace"), pack_rotation(now + 30, now + 3600));
        assert!(!is_token_revoked("in-grace", &map));

        map.insert(rotated_key("after-grace"), pack_rotation(now - 1, now + 3600));
        assert!(is_token_revoked("after-grace", &map));

        assert!(!is_token_revoked("unrelated", &map));
    }

    #[test]
    fn plain_revocations_are_unchanged() {
        let map = Arc::new(DashMap::new());
        map.insert("forever".to_string(), 0);
        assert!(is_token_revoked("forever", &map));
    }

    #[actix_web::test]
    async fn revoke_token_after_records_both_instants() {
        let map = Arc::new(DashMap::new());
        // No Redis or LMDB in this test: the in-memory entry is still
        // written before the backend error is reported.
        let _ = revoke_token_after("abc", 1_900_000_030, 1_900_003_600, &map).await;
        let value = *map.get(&rotated_key("abc")).expect("entry written in memory");
        assert_eq!(unpack_rotation(value), (1_900_000_030, 1_900_003_600));
        assert!(map.get("abc").is_none(), "the token id itself is not revoked outright");
    }

    // ── renewed cookie ───────────────────────────────────────

    #[test]
    fn renewed_cookie_has_the_login_cookie_attributes() {
        let cookie = session_cookie("NEWTOKEN", 1800, LIFETIME, 3600);
        assert!(cookie.starts_with("session_token=NEWTOKEN"));
        for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=1800"] {
            assert!(cookie.contains(attr), "{attr} missing in {cookie}");
        }
    }

    #[test]
    fn renewed_cookie_never_outlives_its_token() {
        assert!(session_cookie("T", 7200, LIFETIME, 900).contains("Max-Age=900"));
        assert!(session_cookie("T", 7200, 1800, 3600).contains("Max-Age=1800"));
    }

    // ── configuration ────────────────────────────────────────

    fn app_config(extra: serde_json::Value) -> proxyauth::AppConfig {
        let mut json = serde_json::json!({
            "token_expiry_seconds": 3600,
            "secret": "session-refresh-config-test-secret-session-refresh-config",
            "users": [],
            "log": { "type": "disabled" },
            "smtp": null
        });
        json.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(json).expect("AppConfig")
    }

    #[test]
    fn global_defaults() {
        let cfg = app_config(serde_json::json!({}));
        assert_eq!(cfg.session_refresh_interval_secs, 0);
        assert_eq!(cfg.session_refresh_grace_secs, 30);
        assert_eq!(cfg.session_max_lifetime_secs, 0);
    }

    #[test]
    fn vhost_overrides_global_and_routes_override_vhost() {
        let cfg = app_config(serde_json::json!({
            "session_refresh_interval_secs": 900,
            "session_refresh_grace_secs": 20,
            "session_max_lifetime_secs": 86400
        }));
        let routes: RouteConfig = serde_yaml::from_str::<RouteConfig>(
            r#"
vhosts:
  - vhost: ["a.example.com"]
    session_refresh_interval_secs: 300
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:1"
      - prefix: "/api"
        target: "http://127.0.0.1:1"
        session_refresh_interval_secs: 0
        session_refresh_grace_secs: 5
routes:
  - prefix: "/"
    target: "http://127.0.0.1:1"
"#,
        )
        .unwrap()
        .expand_vhost_groups();

        let find = |p: &str| routes.routes.iter().find(|r| r.prefix == p).unwrap();

        assert_eq!(find("/admin").resolved_session_refresh(&cfg), policy(300, 20, 86400));
        assert_eq!(find("/api").resolved_session_refresh(&cfg), policy(0, 5, 86400));
        assert_eq!(find("/").resolved_session_refresh(&cfg), policy(900, 20, 86400));
    }

    #[test]
    fn settings_survive_a_config_rewrite() {
        let cfg = app_config(serde_json::json!({
            "session_refresh_interval_secs": 900,
            "session_refresh_grace_secs": 15,
            "session_max_lifetime_secs": 43200,
            "trust_proxy_forward_for": ["10.0.0.10"],
            "max_body_size": 1234
        }));
        let written = serde_json::to_value(&cfg).unwrap();
        assert_eq!(written["session_refresh_interval_secs"], 900);
        assert_eq!(written["session_refresh_grace_secs"], 15);
        assert_eq!(written["session_max_lifetime_secs"], 43200);
        assert_eq!(written["trust_proxy_forward_for"][0], "10.0.0.10");
        assert_eq!(written["max_body_size"], 1234);
    }
}
