#[cfg(test)]
mod tests {
    use proxyauth::config::config::{RouteAccessDecision, RouteConfig, RouteRule, VhostGroup};

    fn default_route(prefix: &str, target: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: target.to_string(),
            vhost: vec![],
            vhost_cert: std::collections::HashMap::new(),
            certbot_renew: false,
            headers: std::collections::HashMap::new(),
            tag_csrf_token: None,
            session_cookie: None,
            max_age_session_cookie: None,
            login_redirect_url: None,
            logout_redirect_url: None,
            login_via_otp: None,
            page_change_password: None,
            cors_origins: None,
            smtp: None,
            tag_proxyauth: None,
            allow_users: vec![],
            allow_groups: vec![],
            allow_roles: vec![],
            exclude_users: vec![],
            allow_totp_reenroll: None,
            allow_ips: vec![],
            deny_ips: vec![],
            allow_ips_compiled: vec![],
            deny_ips_compiled: vec![],
            static_path: None,
            static_index: "index.html".into(),
            regex: None,
            regex_compiled: None,
            static_rewrite: None,
            username: vec![],
            groups: vec![],
            roles: vec![],
            required_login: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: None,
            log: None,
            log_file: None,
            compression: None,
            cache: Some(true),
            cache_duration_secs: None,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
            forward_proxy_headers: None,
            oidc: None,
            redirect_protect: None,
        }
    }

    // ── requires_csrf ────────────────────────────────────────

    #[test]
    fn requires_csrf_none_defaults_to_true() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(r.requires_csrf());
    }

    #[test]
    fn requires_csrf_explicit_true() {
        let mut r = default_route("/api", "http://localhost:3000");
        r.need_csrf = Some(true);
        assert!(r.requires_csrf());
    }

    #[test]
    fn requires_csrf_explicit_false() {
        let mut r = default_route("/api", "http://localhost:3000");
        r.need_csrf = Some(false);
        assert!(!r.requires_csrf());
    }

    // ── RouteRule defaults ──────────────────────────────────

    #[test]
    fn route_rule_cache_default_true() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(r.cache_enabled());
    }

    #[test]
    fn route_rule_cache_duration_secs_none() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(r.cache_duration_secs.is_none());
    }

    #[test]
    fn route_rule_required_login_default_false() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(!r.required_login);
    }

    #[test]
    fn route_rule_proxy_default_false() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(!r.proxy);
    }

    #[test]
    fn route_rule_secure_path_default_false() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(!r.secure_path);
    }

    #[test]
    fn route_rule_preserve_prefix_default_false() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(!r.preserve_prefix);
    }

    #[test]
    fn route_rule_static_index_default() {
        let r = default_route("/api", "http://localhost:3000");
        assert_eq!(r.static_index, "index.html");
    }

    #[test]
    fn route_rule_log_none() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(r.log.is_none());
    }

    #[test]
    fn route_rule_log_file_none() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(r.log_file.is_none());
    }

    #[test]
    fn route_rule_compression_none() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(r.compression.is_none());
    }

    #[test]
    fn route_rule_allow_methods_none() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(r.allow_methods.is_none());
    }

    #[test]
    fn route_rule_filters_none() {
        let r = default_route("/api", "http://localhost:3000");
        assert!(r.filters.is_none());
    }

    // ── expand_vhost_groups ─────────────────────────────────

    #[test]
    fn expand_vhost_groups_moves_routes() {
        let yaml = r#"
            vhosts:
              - vhost:
                  - app.example.com
                routes:
                  - prefix: "/a"
                    target: "http://localhost:3000"
                  - prefix: "/b"
                    target: "http://localhost:3001"
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.routes.is_empty());
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes.len(), 2);
    }

    #[test]
    fn expand_vhost_groups_propagates_vhost() {
        let yaml = r#"
            vhosts:
              - vhost:
                  - app.example.com
                routes:
                  - prefix: "/a"
                    target: "http://localhost:3000"
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes[0].vhost, vec!["app.example.com"]);
    }

    #[test]
    fn expand_vhost_groups_route_can_override_vhost() {
        let yaml = r#"
            vhosts:
              - vhost:
                  - app.example.com
                routes:
                  - prefix: "/a"
                    target: "http://localhost:3000"
                    vhost:
                      - custom.example.com
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes[0].vhost, vec!["custom.example.com"]);
    }

    #[test]
    fn expand_vhost_groups_propagates_need_csrf() {
        let yaml = r#"
            vhosts:
              - vhost:
                  - app.example.com
                need_csrf: false
                routes:
                  - prefix: "/a"
                    target: "http://localhost:3000"
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes[0].need_csrf, Some(false));
        assert!(!cfg.routes[0].requires_csrf());
    }

    #[test]
    fn expand_vhost_groups_route_need_csrf_overrides_group() {
        let yaml = r#"
            vhosts:
              - vhost:
                  - app.example.com
                need_csrf: false
                routes:
                  - prefix: "/a"
                    target: "http://localhost:3000"
                    need_csrf: true
                  - prefix: "/b"
                    target: "http://localhost:3001"
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes[0].need_csrf, Some(true));
        assert_eq!(cfg.routes[1].need_csrf, Some(false));
    }

    #[test]
    fn expand_vhost_groups_empty_vhosts_no_op() {
        let yaml = r#"
            routes:
              - prefix: "/flat"
                target: "http://localhost:4000"
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].prefix, "/flat");
    }

    #[test]
    fn expand_preserves_flat_routes() {
        let yaml = r#"
            routes:
              - prefix: "/flat"
                target: "http://localhost:4000"
            vhosts:
              - vhost:
                  - app.example.com
                routes:
                  - prefix: "/group"
                    target: "http://localhost:3000"
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes.len(), 2);
        let prefixes: Vec<&str> = cfg.routes.iter().map(|r| r.prefix.as_str()).collect();
        assert!(prefixes.contains(&"/flat"));
        assert!(prefixes.contains(&"/group"));
    }

    // ── route_access_decision ───────────────────────────────

    fn mk_cfg_with_users() -> proxyauth::AppConfig {
        let json = r#"{
            "token_expiry_seconds": 3600,
            "secret": "s",
            "users": [
                {"username": "alice", "password": "h1", "roles": ["admin"], "groups": ["ops"]},
                {"username": "bob", "password": "h2"}
            ],
            "log": {}
        }"#;
        let cfg: proxyauth::AppConfig = serde_json::from_str(json).unwrap();
        cfg.roles_index
            .write()
            .unwrap()
            .insert("alice".into(), vec!["admin".into()]);
        cfg.groups_index
            .write()
            .unwrap()
            .insert("alice".into(), vec!["ops".into()]);
        cfg
    }

    #[test]
    fn route_access_allowed_by_username() {
        let cfg = mk_cfg_with_users();
        let rule = RouteRule {
            username: vec!["alice".into()],
            ..default_route("/admin", "http://localhost:3000")
        };
        let decision = cfg.route_access_decision(&rule, "alice");
        assert_eq!(decision, RouteAccessDecision::AllowedByUsername);
        assert!(decision.is_allowed());
    }

    #[test]
    fn route_access_denied_wrong_username() {
        let cfg = mk_cfg_with_users();
        let rule = RouteRule {
            username: vec!["alice".into()],
            ..default_route("/admin", "http://localhost:3000")
        };
        let decision = cfg.route_access_decision(&rule, "bob");
        assert_eq!(decision, RouteAccessDecision::Denied);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn route_access_allowed_by_group() {
        let cfg = mk_cfg_with_users();
        let rule = RouteRule {
            groups: vec!["ops".into()],
            ..default_route("/ops", "http://localhost:3000")
        };
        let decision = cfg.route_access_decision(&rule, "alice");
        assert_eq!(decision, RouteAccessDecision::AllowedByGroup("ops".into()));
        assert!(decision.is_allowed());
    }

    #[test]
    fn route_access_denied_wrong_group() {
        let cfg = mk_cfg_with_users();
        let rule = RouteRule {
            groups: vec!["dev".into()],
            ..default_route("/ops", "http://localhost:3000")
        };
        let decision = cfg.route_access_decision(&rule, "alice");
        assert_eq!(decision, RouteAccessDecision::Denied);
    }

    #[test]
    fn route_access_allowed_by_role() {
        let cfg = mk_cfg_with_users();
        let rule = RouteRule {
            roles: vec!["admin".into()],
            ..default_route("/admin", "http://localhost:3000")
        };
        let decision = cfg.route_access_decision(&rule, "alice");
        assert_eq!(decision, RouteAccessDecision::AllowedByRole("admin".into()));
        assert!(decision.is_allowed());
    }

    #[test]
    fn route_access_denied_wrong_role() {
        let cfg = mk_cfg_with_users();
        let rule = RouteRule {
            roles: vec!["superadmin".into()],
            ..default_route("/admin", "http://localhost:3000")
        };
        let decision = cfg.route_access_decision(&rule, "alice");
        assert_eq!(decision, RouteAccessDecision::Denied);
    }

    #[test]
    fn route_access_no_restriction_configured() {
        let cfg = mk_cfg_with_users();
        let rule = default_route("/public", "http://localhost:3000");
        let decision = cfg.route_access_decision(&rule, "alice");
        assert_eq!(
            decision,
            RouteAccessDecision::AllowedNoRestrictionConfigured
        );
        assert!(decision.is_allowed());
    }

    #[test]
    fn route_access_no_restriction_for_unknown_user() {
        let cfg = mk_cfg_with_users();
        let rule = default_route("/public", "http://localhost:3000");
        let decision = cfg.route_access_decision(&rule, "unknown");
        assert_eq!(
            decision,
            RouteAccessDecision::AllowedNoRestrictionConfigured
        );
    }

    #[test]
    fn route_access_empty_username_list_is_no_restriction() {
        let cfg = mk_cfg_with_users();
        let rule = RouteRule {
            username: vec![],
            groups: vec!["dev".into()],
            ..default_route("/dev", "http://localhost:3000")
        };
        // user doesn't have "dev" group
        let decision = cfg.route_access_decision(&rule, "bob");
        assert_eq!(decision, RouteAccessDecision::Denied);
    }

    #[test]
    fn route_access_priority_username_over_group() {
        let cfg = mk_cfg_with_users();
        let rule = RouteRule {
            username: vec!["bob".into()],
            groups: vec!["ops".into()],
            ..default_route("/mixed", "http://localhost:3000")
        };
        let decision = cfg.route_access_decision(&rule, "bob");
        assert_eq!(decision, RouteAccessDecision::AllowedByUsername);
    }

    // ── expand_vhost_groups propagation ──────────────────────

    #[test]
    fn expand_vhost_groups_propagates_log() {
        let yaml = r#"
            vhosts:
              - vhost:
                  - app.example.com
                log: false
                routes:
                  - prefix: "/a"
                    target: "http://localhost:3000"
                  - prefix: "/b"
                    target: "http://localhost:3001"
                    log: true
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes[0].log, Some(false));
        assert_eq!(cfg.routes[1].log, Some(true));
    }

    #[test]
    fn expand_vhost_groups_propagates_log_file() {
        let yaml = r#"
            vhosts:
              - vhost:
                  - app.example.com
                log_file: group.log
                routes:
                  - prefix: "/a"
                    target: "http://localhost:3000"
                  - prefix: "/b"
                    target: "http://localhost:3001"
                    log_file: override.log
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        assert_eq!(cfg.routes[0].log_file.as_deref(), Some("group.log"));
        assert_eq!(cfg.routes[1].log_file.as_deref(), Some("override.log"));
    }

    // ── BackendInput ────────────────────────────────────────

    #[test]
    fn backend_input_simple_string() {
        let yaml = r#"
            routes:
              - prefix: "/"
                target: "http://localhost:3000"
                backends:
                  - "http://10.0.0.1:3000"
                  - "http://10.0.0.2:3000"
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        let r = &cfg.routes[0];
        assert_eq!(r.backends.len(), 2);
        match &r.backends[0] {
            proxyauth::config::config::BackendInput::Simple(url) => {
                assert_eq!(url, "http://10.0.0.1:3000");
            }
            _ => panic!("expected Simple variant"),
        }
    }

    #[test]
    fn backend_input_detailed() {
        let yaml = r#"
            routes:
              - prefix: "/"
                target: "http://localhost:3000"
                backends:
                  - url: "http://10.0.0.1:3000"
                    weight: 3
        "#;
        let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg.expand_vhost_groups();
        let r = &cfg.routes[0];
        assert_eq!(r.backends.len(), 1);
        match &r.backends[0] {
            proxyauth::config::config::BackendInput::Detailed(bc) => {
                assert_eq!(bc.url, "http://10.0.0.1:3000");
                assert_eq!(bc.weight, 3);
            }
            _ => panic!("expected Detailed variant"),
        }
    }

    // ── VhostGroup defaults ─────────────────────────────────

    #[test]
    fn vhost_group_defaults() {
        let g = VhostGroup::default();
        assert!(g.vhost.is_empty());
        assert!(g.vhost_cert.is_empty());
        assert!(g.need_csrf.is_none());
        assert!(g.log.is_none());
        assert!(g.log_file.is_none());
        assert!(g.compression.is_none());
        assert!(g.cache_duration_secs.is_none());
        assert!(g.routes.is_empty());
    }

    // ── RouteRule serde from YAML ───────────────────────────

    #[test]
    fn route_rule_from_yaml_minimal() {
        let yaml = r#"
            prefix: "/api"
            target: "http://localhost:3000"
        "#;
        let rule: RouteRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.prefix, "/api");
        assert_eq!(rule.target, "http://localhost:3000");
        assert!(rule.vhost.is_empty());
        assert!(!rule.required_login);
        assert!(!rule.proxy);
        assert!(rule.cache_enabled());
    }

    #[test]
    fn route_rule_from_yaml_full() {
        let yaml = r#"
            prefix: "/api"
            target: "http://localhost:3000"
            vhost: ["app.example.com"]
            required_login: true
            username: ["alice"]
            groups: ["ops"]
            roles: ["admin"]
            cache: false
            cache_duration_secs: 60
            secure_path: true
            preserve_prefix: true
            need_csrf: false
            log: false
            log_file: "api.log"
        "#;
        let rule: RouteRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.prefix, "/api");
        assert_eq!(rule.vhost, vec!["app.example.com"]);
        assert!(rule.required_login);
        assert_eq!(rule.username, vec!["alice"]);
        assert_eq!(rule.groups, vec!["ops"]);
        assert_eq!(rule.roles, vec!["admin"]);
        assert!(!rule.cache_enabled());
        assert_eq!(rule.cache_duration_secs, Some(60));
        assert!(rule.secure_path);
        assert!(rule.preserve_prefix);
        assert_eq!(rule.need_csrf, Some(false));
        assert_eq!(rule.log, Some(false));
        assert_eq!(rule.log_file.as_deref(), Some("api.log"));
    }
}
