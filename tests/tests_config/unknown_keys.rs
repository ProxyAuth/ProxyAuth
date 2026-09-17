//! Unknown keys in config.json and routes.yml are reported, with the
//! setting that was most likely meant.

#[cfg(test)]
mod tests {
    use proxyauth::config::config::{AppConfig, RouteConfig};
    use proxyauth::config::unknown_keys::{check_app_config, check_routes};
    use proxyauth::token::refresh::describe_policies;

    fn app_config(json: &serde_json::Value) -> AppConfig {
        serde_json::from_value(json.clone()).expect("AppConfig")
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "token_expiry_seconds": 3600,
            "secret": "unknown-keys-test-secret-unknown-keys-test-secret-0123",
            "users": [],
            "log": { "type": "disabled" },
            "smtp": null
        })
    }

    fn with(extra: serde_json::Value) -> serde_json::Value {
        let mut json = base();
        json.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json
    }

    #[test]
    fn a_valid_config_reports_nothing() {
        let json = with(serde_json::json!({
            "session_refresh_interval_secs": 900,
            "session_refresh_grace_secs": 30,
            "max_age_session_cookie": 1800
        }));
        assert!(check_app_config(&json, &app_config(&json)).is_empty());
    }

    #[test]
    fn every_key_proxyauth_writes_back_is_known() {
        // What load_config rewrites into config.json must never be
        // reported as unknown on the next start — including the
        // `letsencrypt` block, also accepted as `acme`.
        let cfg = app_config(&base());
        let written = serde_json::to_value(&cfg).unwrap();
        assert!(check_app_config(&written, &cfg).is_empty());

        let mut renamed = written.clone();
        let acme = renamed.as_object_mut().unwrap().remove("letsencrypt").unwrap();
        renamed.as_object_mut().unwrap().insert("acme".into(), acme);
        assert!(check_app_config(&renamed, &cfg).is_empty());
    }

    #[test]
    fn misnamed_renewal_settings_point_to_the_real_one() {
        for key in [
            "session_refresh",
            "session_refresh_interval",
            "refresh_interval",
            "renew_session_after",
            "session_token_refresh",
        ] {
            let json = with(serde_json::json!({ key: 900 }));
            let found = check_app_config(&json, &app_config(&json));
            assert_eq!(found.len(), 1, "{key}");
            assert_eq!(found[0].key, key);
            assert_eq!(
                found[0].suggestion.as_deref(),
                Some("session_refresh_interval_secs"),
                "{key}"
            );
        }
    }

    #[test]
    fn other_common_names_are_mapped() {
        for (key, expected) in [
            ("session_cookie_ttl", "max_age_session_cookie"),
            ("token_ttl", "token_expiry_seconds"),
            ("refresh_grace", "session_refresh_grace_secs"),
            ("max_session_lifetime", "session_max_lifetime_secs"),
            ("token_expiry_second", "token_expiry_seconds"),
            ("sesion_cookie", "session_cookie"),
        ] {
            let json = with(serde_json::json!({ key: 1 }));
            let found = check_app_config(&json, &app_config(&json));
            assert_eq!(found[0].suggestion.as_deref(), Some(expected), "{key}");
        }
    }

    #[test]
    fn misnamed_refresh_token_settings_point_to_the_real_one() {
        for key in ["refresh_token", "token_refresh", "refresh_token_ttl", "refresh_token_expiry"] {
            let json = with(serde_json::json!({ key: 86400 }));
            let found = check_app_config(&json, &app_config(&json));
            assert_eq!(found.len(), 1, "{key}");
            assert_eq!(
                found[0].suggestion.as_deref(),
                Some("refresh_token_expiry_seconds"),
                "{key}"
            );
        }
    }

    #[test]
    fn the_message_says_what_happens() {
        let json = with(serde_json::json!({ "refresh_token": 900 }));
        let found = check_app_config(&json, &app_config(&json));
        assert_eq!(
            found[0].to_string(),
            "config.json: unknown key `refresh_token` is ignored — did you mean `refresh_token_expiry_seconds`?"
        );
    }

    #[test]
    fn routes_yml_is_checked_at_every_level() {
        let yaml = r#"
vhosts:
  - vhost: ["blog.example.com"]
    session_refresh_intervall: 900
    session_cookie_age: 1800
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:1"
        required_login: true
        redirect_login: "/login"
      - prefix: "/login"
        static: "/var/www/login/"
        static_index: "login.html"
        csrf_token: true
routes:
  - prefix: "/"
    target: "http://127.0.0.1:1"
    requierd_login: true
extra_section: {}
"#;
        let found = check_routes(yaml);
        let summary: Vec<(String, String, Option<String>)> = found
            .iter()
            .map(|u| (u.location.clone(), u.key.clone(), u.suggestion.clone()))
            .collect();

        assert_eq!(
            summary,
            vec![
                ("routes.yml".into(), "extra_section".into(), None),
                (
                    "routes.yml › routes[0] (/)".into(),
                    "requierd_login".into(),
                    Some("required_login".into())
                ),
                (
                    "routes.yml › vhosts[0] (blog.example.com)".into(),
                    "session_refresh_intervall".into(),
                    Some("session_refresh_interval_secs".into())
                ),
                (
                    "routes.yml › vhosts[0] (blog.example.com) › routes[0] (/admin)".into(),
                    "redirect_login".into(),
                    Some("redirect_login_url".into())
                ),
            ]
        );
    }

    #[test]
    fn aliases_and_static_are_not_reported() {
        let yaml = r#"
vhosts:
  - vhost: ["a.example.com"]
    certbot_rew: true
    login_page_url: "/login"
    routes:
      - prefix: "/"
        static: "/var/www/"
        csrf_token: false
"#;
        assert_eq!(check_routes(yaml), vec![]);
    }

    #[test]
    fn unparsable_yaml_is_left_to_the_real_parser() {
        assert!(check_routes("vhosts: [").is_empty());
    }

    // ── startup summary ──────────────────────────────────────

    fn routes(yaml: &str) -> RouteConfig {
        serde_yaml::from_str::<RouteConfig>(yaml)
            .unwrap()
            .expand_vhost_groups()
    }

    #[test]
    fn summary_says_when_renewal_is_off() {
        let cfg = app_config(&base());
        let lines = describe_policies(&cfg, &routes("routes: []").routes);
        assert_eq!(lines, vec!["session renewal off (session_refresh_interval_secs = 0)"]);
    }

    #[test]
    fn summary_lists_the_global_policy_and_vhost_overrides() {
        let cfg = app_config(&with(serde_json::json!({
            "session_refresh_interval_secs": 900,
            "session_refresh_grace_secs": 30
        })));
        let r = routes(
            r#"
vhosts:
  - vhost: ["api.example.com"]
    session_refresh_interval_secs: 0
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:1"
        required_login: true
  - vhost: ["blog.example.com"]
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:1"
        required_login: true
"#,
        );
        assert_eq!(
            describe_policies(&cfg, &r.routes),
            vec![
                "session renewal every 900s, previous token accepted 30s more".to_string(),
                "session renewal on api.example.com/admin: off (session_refresh_interval_secs = 0)".to_string(),
            ]
        );
    }

    #[test]
    fn summary_warns_when_renewal_can_never_happen() {
        let cfg = app_config(&with(serde_json::json!({
            "session_refresh_interval_secs": 3600
        })));
        let r = routes(
            r#"
routes:
  - prefix: "/admin"
    target: "http://127.0.0.1:1"
    required_login: true
"#,
        );
        let lines = describe_policies(&cfg, &r.routes);
        assert!(
            lines.iter().any(|l| l.starts_with("warning: session renewal on /admin never happens")),
            "{lines:?}"
        );
    }
}
