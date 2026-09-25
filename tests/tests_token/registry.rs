//! `/auth/registry` — configuration parsing, input validation, route
//! resolution and every handler path that doesn't need a live database
//! (the database write itself is covered by `insert_new_user`'s
//! transaction and is exercised against a real Postgres/MySQL only).

#[cfg(test)]
mod tests {
    use actix_web::Responder;
    use actix_web::http::StatusCode;
    use actix_web::test;
    use dashmap::DashMap;
    use proxyauth::config::config::{
        AppConfig, BlakegateEndpoint, DatabaseConfig, EmailEntry, RouteConfig, RouteRule, User,
    };
    use proxyauth::network::stats::RequestStats;
    use proxyauth::revoke::db::RevokedTokenMap;
    use proxyauth::token::csrf::make_csrf_token;
    use proxyauth::token::registry::{
        EitherRegistry, RegistryConfig, RegistryRequest, build_new_user, describe_registry,
        find_registry_route, registry_route, validate_email, validate_password,
        validate_username,
    };
    use proxyauth::{AppState, CounterToken};
    use std::sync::Arc;

    // ── helpers ────────────────────────────────────────────────

    fn route(vhost: &[&str], registry: Option<RegistryConfig>) -> RouteRule {
        let mut r: RouteRule = serde_json::from_str(r#"{"prefix": "/"}"#).unwrap();
        r.vhost = vhost.iter().map(|s| s.to_string()).collect();
        r.registry = registry;
        r
    }

    fn enabled(groups: &[&str], roles: &[&str]) -> RegistryConfig {
        RegistryConfig {
            enabled: true,
            default_groups: groups.iter().map(|s| s.to_string()).collect(),
            default_roles: roles.iter().map(|s| s.to_string()).collect(),
            redirect_url: None,
        }
    }

    /// Points at a port nothing listens on: every test below must get
    /// its answer *before* the handler ever tries to connect.
    fn unreachable_db() -> DatabaseConfig {
        serde_json::from_value(serde_json::json!({
            "type": "postgres",
            "host": "127.0.0.1",
            "port": 1,
            "db_name": "proxyauth_test",
            "connect_timeout_secs": 1
        }))
        .unwrap()
    }

    fn cfg(with_db: bool) -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "registry-test-secret".into(),
            timezone: "UTC".into(),
            csrf_token: false,
            databases: if with_db { Some(unreachable_db()) } else { None },
            ..Default::default()
        }
    }

    fn state(routes: Vec<RouteRule>, cfg: AppConfig) -> actix_web::web::Data<AppState> {
        actix_web::web::Data::new(AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig {
                routes,
                ..Default::default()
            }),
            counter: Arc::new(CounterToken::new()),
            revoked_tokens: Arc::new(DashMap::new()) as RevokedTokenMap,
            stats: RequestStats::new(),
            otp_overrides: Arc::new(DashMap::new()),
            password_overrides: Arc::new(DashMap::new()),
            must_change_overrides: Arc::new(DashMap::new()),
            ip_blocklist: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            redirect_protect_url_ips: Arc::new(DashMap::new()),
        })
    }

    fn body(username: &str, password: &str, email: &str) -> RegistryRequest {
        RegistryRequest {
            username: username.into(),
            password: password.into(),
            verif_password: None,
            email: email.into(),
            csrf_token: None,
        }
    }

    async fn call(
        data: actix_web::web::Data<AppState>,
        host: &str,
        payload: EitherRegistry,
    ) -> (StatusCode, String) {
        let req = test::TestRequest::post()
            .uri("/auth/registry")
            .insert_header(("host", host))
            .to_http_request();
        let resp = registry_route(req.clone(), data, payload)
            .await
            .respond_to(&req)
            .map_into_boxed_body();
        let status = resp.status();
        let bytes = actix_web::body::to_bytes(resp.into_body())
            .await
            .unwrap_or_default();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    const GOOD_PW: &str = "correct-horse-battery";

    // ── configuration ──────────────────────────────────────────

    #[test]
    async fn registry_block_parses_from_routes_yml() {
        let yml = r#"
routes:
  - prefix: "/"
    target: "http://127.0.0.1:8080"
    registry:
      enabled: true
      default_groups: ["members"]
      default_roles: ["reader", "commenter"]
      redirect_url: "/login?registered=1"
"#;
        let rc: RouteConfig = serde_yaml::from_str(yml).unwrap();
        let reg = rc.routes[0].registry.as_ref().expect("registry parsed");
        assert!(reg.enabled);
        assert_eq!(reg.default_groups, vec!["members"]);
        assert_eq!(reg.default_roles, vec!["reader", "commenter"]);
        assert_eq!(reg.redirect_url.as_deref(), Some("/login?registered=1"));
    }

    #[test]
    async fn registry_is_off_unless_enabled_is_written() {
        let reg: RegistryConfig =
            serde_yaml::from_str("default_groups: [\"members\"]").unwrap();
        assert!(!reg.enabled);
    }

    #[test]
    async fn route_without_registry_has_none() {
        assert!(route(&[], None).registry.is_none());
    }

    #[test]
    async fn vhost_group_registry_propagates_and_route_override_wins() {
        let yml = r#"
vhosts:
  - vhost: ["app.example.com"]
    registry:
      enabled: true
      default_groups: ["members"]
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:8080"
      - prefix: "/beta"
        target: "http://127.0.0.1:8081"
        registry:
          enabled: true
          default_groups: ["beta-testers"]
"#;
        let rc: RouteConfig = serde_yaml::from_str::<RouteConfig>(yml)
            .unwrap()
            .expand_vhost_groups();
        let root = rc.routes.iter().find(|r| r.prefix == "/").unwrap();
        let beta = rc.routes.iter().find(|r| r.prefix == "/beta").unwrap();
        assert_eq!(root.registry.as_ref().unwrap().default_groups, vec!["members"]);
        assert_eq!(beta.registry.as_ref().unwrap().default_groups, vec!["beta-testers"]);
    }

    #[test]
    async fn registry_is_not_reported_as_an_unknown_key() {
        let yml = r#"
routes:
  - prefix: "/"
    target: "http://127.0.0.1:8080"
    registry:
      enabled: true
"#;
        let unknown = proxyauth::config::unknown_keys::check_routes(yml);
        assert!(
            unknown.iter().all(|u| u.key != "registry"),
            "registry flagged as unknown: {unknown:?}"
        );
    }

    // ── validation ─────────────────────────────────────────────

    #[test]
    async fn usernames() {
        for ok in ["bob", "alice.smith", "user_42", "a-b", "X9z"] {
            assert!(validate_username(ok).is_ok(), "{ok} should be accepted");
        }
        let too_long = "a".repeat(65);
        for bad in ["", "ab", ".bob", "-bob", "bob smith", "bob@x", "bób", "a/b", too_long.as_str()] {
            assert!(validate_username(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    async fn emails() {
        for ok in ["a@example.com", "first.last+tag@sub.example.org", "x@a-b.io"] {
            assert!(validate_email(ok).is_ok(), "{ok} should be accepted");
        }
        for bad in [
            "",
            "plain",
            "@example.com",
            "a@",
            "a@localhost",
            "a@@example.com",
            "a b@example.com",
            "a@exa mple.com",
            ".a@example.com",
            "a..b@example.com",
            "a@-example.com",
            "a@example..com",
            "<a>@example.com",
        ] {
            assert!(validate_email(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    async fn passwords() {
        assert!(validate_password(GOOD_PW, None).is_ok());
        assert!(validate_password(GOOD_PW, Some(GOOD_PW)).is_ok());
        assert!(validate_password("short", None).is_err());
        assert!(validate_password(GOOD_PW, Some("something-else-entirely")).is_err());
        assert!(validate_password(&"x".repeat(1025), None).is_err());
    }

    #[test]
    async fn new_user_takes_groups_and_roles_from_config_only() {
        let reg = enabled(&["members", " "], &["reader"]);
        let u = build_new_user("bob", "$argon2id$fake".into(), "bob@example.com", &reg);
        assert_eq!(u.groups, Some(vec!["members".to_string()]));
        assert_eq!(u.roles, Some(vec!["reader".to_string()]));
        assert_eq!(
            u.email,
            Some(vec![EmailEntry { address: "bob@example.com".into(), primary: true }])
        );
        assert!(u.otpkey.is_none());
        assert!(u.allow.is_none());
        assert!(!u.must_change_password);

        let none = build_new_user("bob", "h".into(), "bob@example.com", &enabled(&[], &[]));
        assert!(none.groups.is_none() && none.roles.is_none());
    }

    // ── route resolution ───────────────────────────────────────

    #[test]
    async fn resolution_prefers_exact_then_wildcard_then_catch_all() {
        let routes = vec![
            route(&[], Some(enabled(&["catch-all"], &[]))),
            route(&["*.example.com"], Some(enabled(&["wildcard"], &[]))),
            route(&["app.example.com"], Some(enabled(&["exact"], &[]))),
        ];
        let pick = |h| {
            find_registry_route(Some(h), &routes)
                .and_then(|r| r.registry.as_ref())
                .map(|r| r.default_groups[0].clone())
        };
        assert_eq!(pick("app.example.com").as_deref(), Some("exact"));
        assert_eq!(pick("APP.example.com:443").as_deref(), Some("exact"));
        assert_eq!(pick("other.example.com").as_deref(), Some("wildcard"));
        assert_eq!(pick("unrelated.org").as_deref(), Some("catch-all"));
    }

    #[test]
    async fn resolution_ignores_routes_without_a_registry_block() {
        let routes = vec![
            route(&["app.example.com"], None),
            route(&["app.example.com"], Some(enabled(&["second"], &[]))),
        ];
        let r = find_registry_route(Some("app.example.com"), &routes).unwrap();
        assert_eq!(r.registry.as_ref().unwrap().default_groups, vec!["second"]);
        assert!(find_registry_route(Some("nope.org"), &routes).is_none());
    }

    // ── startup summary ────────────────────────────────────────

    #[test]
    async fn describe_warns_about_missing_db_and_login_mismatch() {
        let mut r = route(&["app.example.com"], Some(enabled(&["members"], &[])));
        r.allow_groups = vec!["staff".into()];
        let lines = describe_registry(&cfg(false), &[r.clone()]).join("\n");
        assert!(lines.contains("enabled"));
        assert!(lines.contains("databases"));
        assert!(lines.contains("refused at login"));

        r.allow_groups = vec!["members".into()];
        let lines = describe_registry(&cfg(true), &[r]).join("\n");
        assert!(!lines.contains("WARNING"), "{lines}");
    }

    #[test]
    async fn describe_reports_a_disabled_block() {
        let r = route(&["app.example.com"], Some(RegistryConfig::default()));
        let lines = describe_registry(&cfg(true), &[r]).join("\n");
        assert!(lines.contains("stays disabled"));
    }

    // ── handler ────────────────────────────────────────────────

    #[actix_web::test]
    async fn not_found_when_no_route_has_registry() {
        let data = state(vec![route(&["app.example.com"], None)], cfg(true));
        let (s, _) = call(data, "app.example.com", EitherRegistry::Json(body("bob", GOOD_PW, "b@example.com"))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn not_found_when_registry_disabled() {
        let data = state(
            vec![route(&["app.example.com"], Some(RegistryConfig::default()))],
            cfg(true),
        );
        let (s, _) = call(data, "app.example.com", EitherRegistry::Json(body("bob", GOOD_PW, "b@example.com"))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn not_found_on_another_vhost() {
        let data = state(
            vec![route(&["app.example.com"], Some(enabled(&["members"], &[])))],
            cfg(true),
        );
        let (s, _) = call(data, "other.org", EitherRegistry::Json(body("bob", GOOD_PW, "b@example.com"))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn unavailable_without_database() {
        let data = state(
            vec![route(&["app.example.com"], Some(enabled(&["members"], &[])))],
            cfg(false),
        );
        let (s, b) = call(data, "app.example.com", EitherRegistry::Json(body("bob", GOOD_PW, "b@example.com"))).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert!(b.contains("database"));
    }

    #[actix_web::test]
    async fn unavailable_in_blakegate_backup_mode() {
        let mut c = cfg(true);
        c.blakegate = vec![BlakegateEndpoint::Simple("wss://blakegate.invalid/ws".into())];
        let data = state(
            vec![route(&["app.example.com"], Some(enabled(&["members"], &[])))],
            c,
        );
        let (s, _) = call(data, "app.example.com", EitherRegistry::Json(body("bob", GOOD_PW, "b@example.com"))).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[actix_web::test]
    async fn bad_input_is_rejected_before_touching_the_database() {
        let routes = vec![route(&["app.example.com"], Some(enabled(&["members"], &[])))];
        for (u, p, e) in [
            ("x", GOOD_PW, "b@example.com"),
            ("bob", "short", "b@example.com"),
            ("bob", GOOD_PW, "not-an-email"),
        ] {
            let data = state(routes.clone(), cfg(true));
            let (s, _) = call(data, "app.example.com", EitherRegistry::Json(body(u, p, e))).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{u}/{p}/{e}");
        }

        let mut mismatch = body("bob", GOOD_PW, "b@example.com");
        mismatch.verif_password = Some("another-long-password".into());
        let data = state(routes, cfg(true));
        let (s, b) = call(data, "app.example.com", EitherRegistry::Json(mismatch)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(b.contains("do not match"));
    }

    #[actix_web::test]
    async fn cannot_register_over_a_config_json_user() {
        let mut c = cfg(true);
        c.users = vec![User {
            username: "Alice".into(),
            password: "$argon2id$placeholder".into(),
            otpkey: None,
            allow: None,
            roles: Some(vec!["admin".into()]),
            groups: None,
            email: Some(vec![EmailEntry { address: "alice@example.com".into(), primary: true }]),
            must_change_password: false,
        }];
        let routes = vec![route(&["app.example.com"], Some(enabled(&["members"], &[])))];

        // Same username, different case.
        let data = state(routes.clone(), c);
        let (s, b) = call(data.clone(), "app.example.com", EitherRegistry::Json(body("alice", GOOD_PW, "new@example.com"))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(b, "Username or email already in use");

        // Same email, different username — same (non-enumerating) answer.
        let (s, b) = call(data, "app.example.com", EitherRegistry::Json(body("mallory", GOOD_PW, "ALICE@example.com"))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(b, "Username or email already in use");
    }

    #[actix_web::test]
    async fn csrf_is_required_when_enabled_for_the_vhost() {
        let mut r = route(&["app.example.com"], Some(enabled(&["members"], &[])));
        r.tag_csrf_token = Some(true);
        let data = state(vec![r], cfg(false));

        let (s, _) = call(data.clone(), "app.example.com", EitherRegistry::Json(body("bob", GOOD_PW, "b@example.com"))).await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        // With a valid token the request gets past CSRF — here it then
        // stops at "no database", proving the token was accepted.
        let mut ok = body("bob", GOOD_PW, "b@example.com");
        ok.csrf_token = Some(make_csrf_token("registry-test-secret"));
        let (s, _) = call(data, "app.example.com", EitherRegistry::Json(ok)).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[actix_web::test]
    async fn payload_accepts_json_and_form() {
        use actix_web::FromRequest;

        let (req, mut pl) = test::TestRequest::post()
            .insert_header(("content-type", "application/json"))
            .set_payload(r#"{"username":"bob","password":"p","email":"b@example.com"}"#)
            .to_http_parts();
        match EitherRegistry::from_request(&req, &mut pl).await.unwrap() {
            EitherRegistry::Json(j) => {
                assert_eq!(j.username, "bob");
                assert!(j.verif_password.is_none());
            }
            _ => panic!("expected JSON"),
        }

        let (req, mut pl) = test::TestRequest::post()
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("username=bob&password=p&verif_password=p&email=b%40example.com")
            .to_http_parts();
        match EitherRegistry::from_request(&req, &mut pl).await.unwrap() {
            EitherRegistry::Form(f) => {
                assert_eq!(f.email, "b@example.com");
                assert_eq!(f.verif_password.as_deref(), Some("p"));
            }
            _ => panic!("expected form"),
        }

        let (req, mut pl) = test::TestRequest::post()
            .insert_header(("content-type", "text/plain"))
            .set_payload("x")
            .to_http_parts();
        assert!(EitherRegistry::from_request(&req, &mut pl).await.is_err());
    }
}
