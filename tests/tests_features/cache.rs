use proxyauth::config::config::{RouteConfig, RouteRule, VhostGroup};

fn default_route(prefix: &str, target: &str) -> RouteRule {
    RouteRule {
        prefix: prefix.to_string(),
        target: target.to_string(),
        vhost: vec![],
        vhost_cert: std::collections::HashMap::new(),
        certbot_renew: false,
        headers: std::collections::HashMap::new(),
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
        cache: true,
        cache_duration_secs: None,
        secure_path: false,
        preserve_prefix: false,
        allow_methods: None,
        filters: None,
        filters_compiled: None,
    }
}

// ── cache_duration_secs default ────────────────────────────────

#[test]
fn app_config_default_cache_duration_is_300() {
    let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
    let cfg: proxyauth::AppConfig = serde_json::from_str(json).unwrap();
    assert_eq!(cfg.cache_duration_secs, 300);
}

#[test]
fn route_cache_defaults_to_true() {
    let r = default_route("/api", "http://localhost:3000");
    assert!(r.cache);
}

#[test]
fn route_cache_duration_secs_is_none_by_default() {
    let r = default_route("/api", "http://localhost:3000");
    assert!(r.cache_duration_secs.is_none());
}

// ── VhostGroup cache_duration_secs ─────────────────────────────

#[test]
fn vhost_group_cache_duration_secs_none_by_default() {
    let g = VhostGroup::default();
    assert!(g.cache_duration_secs.is_none());
}

#[test]
fn vhost_group_cache_duration_secs_from_yaml() {
    let yaml = r#"
        vhosts:
          - vhost:
              - app.example.com
            cache_duration_secs: 60
            routes:
              - prefix: "/"
                target: "http://localhost:3000"
    "#;
    let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.vhosts[0].cache_duration_secs, Some(60));
}

// ── expand_vhost_groups propagates cache fields ─────────────────

#[test]
fn expand_propagates_cache_duration_secs_from_group() {
    let yaml = r#"
        vhosts:
          - vhost:
              - app.example.com
            cache_duration_secs: 120
            routes:
              - prefix: "/a"
                target: "http://localhost:3000"
              - prefix: "/b"
                target: "http://localhost:3001"
                cache_duration_secs: 60
    "#;
    let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
    let cfg = cfg.expand_vhost_groups();

    assert_eq!(cfg.routes.len(), 2);
    assert_eq!(cfg.routes[0].cache_duration_secs, Some(120));
    assert_eq!(cfg.routes[1].cache_duration_secs, Some(60));
}

#[test]
fn expand_does_not_overwrite_route_cache_duration() {
    let yaml = r#"
        vhosts:
          - vhost:
              - app.example.com
            cache_duration_secs: 300
            routes:
              - prefix: "/"
                target: "http://localhost:3000"
                cache_duration_secs: 60
    "#;
    let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
    let cfg = cfg.expand_vhost_groups();
    assert_eq!(cfg.routes[0].cache_duration_secs, Some(60));
}

// ── expand_vhost_groups propagates cache flag ───────────────────

#[test]
fn expand_propagates_cache_flag() {
    let yaml = r#"
        vhosts:
          - vhost:
              - app.example.com
            routes:
              - prefix: "/cached"
                target: "http://localhost:3000"
                cache: true
              - prefix: "/nocache"
                target: "http://localhost:3001"
                cache: false
    "#;
    let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
    let cfg = cfg.expand_vhost_groups();

    let cached = cfg.routes.iter().find(|r| r.prefix == "/cached").unwrap();
    let nocache = cfg.routes.iter().find(|r| r.prefix == "/nocache").unwrap();
    assert!(cached.cache);
    assert!(!nocache.cache);
}

// ── expand_vhost_groups propagates compression ──────────────────

#[test]
fn expand_propagates_compression_from_group() {
    let yaml = r#"
        vhosts:
          - vhost:
              - app.example.com
            compression:
              enabled: true
              algorithm: "gzip"
            routes:
              - prefix: "/a"
                target: "http://localhost:3000"
              - prefix: "/b"
                target: "http://localhost:3001"
                compression:
                  algorithm: "br"
    "#;
    let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
    let cfg = cfg.expand_vhost_groups();

    assert_eq!(cfg.routes.len(), 2);
    let comp_a = cfg.routes[0].compression.as_ref().unwrap();
    assert!(comp_a.is_enabled());
    assert_eq!(comp_a.algorithm.as_deref(), Some("gzip"));

    let comp_b = cfg.routes[1].compression.as_ref().unwrap();
    assert_eq!(comp_b.algorithm.as_deref(), Some("br"));
}

// ── mixed vhost groups + flat routes ────────────────────────────

#[test]
fn expand_mixed_groups_and_flat_routes() {
    let yaml = r#"
        vhosts:
          - vhost:
              - app.example.com
            cache_duration_secs: 120
            routes:
              - prefix: "/from-group"
                target: "http://localhost:3000"
        routes:
          - prefix: "/flat"
            target: "http://localhost:4000"
    "#;
    let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
    let cfg = cfg.expand_vhost_groups();

    assert_eq!(cfg.routes.len(), 2);
    let from_group = cfg.routes.iter().find(|r| r.prefix == "/from-group").unwrap();
    let flat = cfg.routes.iter().find(|r| r.prefix == "/flat").unwrap();

    assert_eq!(from_group.cache_duration_secs, Some(120));
    assert_eq!(from_group.vhost, vec!["app.example.com"]);
    assert!(flat.cache_duration_secs.is_none());
    assert!(flat.vhost.is_empty());
}

// ── group-level compression merging ─────────────────────────────

#[test]
fn group_compression_level_static_propagates() {
    let yaml = r#"
        vhosts:
          - vhost:
              - app.example.com
            compression:
              enabled: true
              level: 5
              level_static: 9
              file_static:
                - .js
                - .css
            routes:
              - prefix: "/"
                target: "http://localhost:3000"
    "#;
    let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
    let cfg = cfg.expand_vhost_groups();

    let comp = cfg.routes[0].compression.as_ref().unwrap();
    assert!(comp.is_enabled());
    assert_eq!(comp.level, 5);
    assert_eq!(comp.level_static, Some(9));
    assert_eq!(comp.file_static, vec![".js", ".css"]);
}

#[test]
fn group_compression_override_allows_partial() {
    let yaml = r#"
        vhosts:
          - vhost:
              - app.example.com
            compression:
              enabled: true
              algorithm: "br"
            routes:
              - prefix: "/"
                target: "http://localhost:3000"
                compression:
                  enabled: false
    "#;
    let cfg: RouteConfig = serde_yaml::from_str(yaml).unwrap();
    let cfg = cfg.expand_vhost_groups();

    let comp = cfg.routes[0].compression.as_ref().unwrap();
    assert!(!comp.is_enabled());
}
