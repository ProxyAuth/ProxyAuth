use actix_web::HttpMessage;
use proxyauth::config::config::{RouteConfig, RouteRule};
use proxyauth::config::logging::{
    LoggingConfig, VhostLogging, LOG_DIR, DEFAULT_FORMAT,
};
use proxyauth::network::accesslog::{LogContext, RequiredFields, compile_format, Field, Segment};

fn minimal_rule(prefix: &str) -> RouteRule {
    RouteRule {
        prefix: prefix.into(),
        target: String::new(),
        vhost: vec![],
        vhost_cert: std::collections::HashMap::new(),
        certbot_renew: false,
        headers: std::collections::HashMap::new(),
        csrf_token: None,
        session_cookie: None,
        max_age_session_cookie: None,
        login_redirect_url: None,
        logout_redirect_url: None,
        login_via_otp: None,
        page_change_password: None,
        cors_origins: None,
        smtp: None,
        tag_proxyauth: None,
        allow_ips: vec![],
        deny_ips: vec![],
        allow_ips_compiled: vec![],
        deny_ips_compiled: vec![],
        static_path: None,
        static_index: String::new(),
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

// ── LoggingConfig defaults ──────────────────────────────────────

#[test]
fn logging_enabled_by_default() {
    assert!(LoggingConfig::default().enabled);
}

#[test]
fn logging_format_is_default() {
    assert_eq!(LoggingConfig::default().format, DEFAULT_FORMAT);
}

#[test]
fn logging_log_file_default() {
    assert_eq!(LoggingConfig::default().log_file, "access.log");
}

#[test]
fn logging_deserialize_empty() {
    let cfg: LoggingConfig = serde_json::from_str("{}").unwrap();
    assert!(cfg.enabled);
    assert_eq!(cfg.format, DEFAULT_FORMAT);
    assert_eq!(cfg.log_file, "access.log");
}

#[test]
fn logging_log_file_custom() {
    let json = r#"{"log_file": "my.log"}"#;
    let cfg: LoggingConfig = serde_json::from_str(json).unwrap();
    assert_eq!(cfg.log_file, "my.log");
}

#[test]
fn logging_log_dir_constant() {
    assert_eq!(LOG_DIR, "/var/log/proxyauth");
}

// ── VhostLogging ────────────────────────────────────────────────

#[test]
fn vhost_logging_log_file_none_by_default() {
    let vh = VhostLogging::default();
    assert!(vh.log_file.is_none());
}

#[test]
fn vhost_logging_deserialize() {
    let json = r#"{"enabled": false, "log_file": "quiet.log"}"#;
    let vh: VhostLogging = serde_json::from_str(json).unwrap();
    assert_eq!(vh.enabled, Some(false));
    assert_eq!(vh.log_file.as_deref(), Some("quiet.log"));
}

// ── vhost_enabled ───────────────────────────────────────────────

#[test]
fn vhost_enabled_empty_map() {
    assert!(LoggingConfig::default().vhost_enabled("anything"));
}

#[test]
fn vhost_enabled_disabled_entry() {
    let mut cfg = LoggingConfig::default();
    cfg.vhosts.insert(
        "quiet.example.com".into(),
        VhostLogging { enabled: Some(false), ..Default::default() },
    );
    assert!(!cfg.vhost_enabled("quiet.example.com"));
    assert!(cfg.vhost_enabled("other.example.com"));
}

#[test]
fn vhost_enabled_entry_without_explicit_toggle() {
    let mut cfg = LoggingConfig::default();
    cfg.vhosts.insert(
        "loud.example.com".into(),
        VhostLogging { enabled: None, log_file: Some("loud.log".into()) },
    );
    assert!(cfg.vhost_enabled("loud.example.com"));
}

// ── route_enabled ───────────────────────────────────────────────

#[test]
fn route_enabled_empty_map() {
    let cfg = LoggingConfig::default();
    assert!(cfg.route_enabled("/api").is_none());
}

#[test]
fn route_enabled_explicit() {
    let mut cfg = LoggingConfig::default();
    cfg.routes.insert("/api".into(), false);
    assert_eq!(cfg.route_enabled("/api"), Some(false));
    assert!(cfg.route_enabled("/other").is_none());
}

// ── validate_log_paths ──────────────────────────────────────────

#[test]
fn validate_log_paths_ok() {
    let cfg = LoggingConfig::default();
    assert!(cfg.validate_log_paths().is_ok());
}

#[test]
fn validate_log_paths_global_absolute_rejected() {
    let mut cfg = LoggingConfig::default();
    cfg.log_file = "/etc/passwd".into();
    assert!(cfg.validate_log_paths().is_err());
}

#[test]
fn validate_log_paths_global_traversal_rejected() {
    let mut cfg = LoggingConfig::default();
    cfg.log_file = "../escape.log".into();
    assert!(cfg.validate_log_paths().is_err());
}

#[test]
fn validate_log_paths_global_subdir_rejected() {
    let mut cfg = LoggingConfig::default();
    cfg.log_file = "sub/dir/file.log".into();
    assert!(cfg.validate_log_paths().is_err());
}

#[test]
fn validate_log_paths_vhost_absolute_rejected() {
    let mut cfg = LoggingConfig::default();
    cfg.vhosts.insert(
        "bad.example.com".into(),
        VhostLogging { enabled: None, log_file: Some("/etc/passwd".into()) },
    );
    assert!(cfg.validate_log_paths().is_err());
}

#[test]
fn validate_log_paths_vhost_traversal_rejected() {
    let mut cfg = LoggingConfig::default();
    cfg.vhosts.insert(
        "bad.example.com".into(),
        VhostLogging { enabled: None, log_file: Some("../../escape.log".into()) },
    );
    assert!(cfg.validate_log_paths().is_err());
}

#[test]
fn validate_log_paths_vhost_ok() {
    let mut cfg = LoggingConfig::default();
    cfg.vhosts.insert(
        "good.example.com".into(),
        VhostLogging { enabled: None, log_file: Some("good.log".into()) },
    );
    assert!(cfg.validate_log_paths().is_ok());
}

#[test]
fn validate_log_paths_empty_is_ok() {
    let mut cfg = LoggingConfig::default();
    cfg.log_file = "".into();
    assert!(cfg.validate_log_paths().is_ok());
}

#[test]
fn validate_log_paths_vhost_subdir_rejected() {
    let mut cfg = LoggingConfig::default();
    cfg.vhosts.insert(
        "bad.example.com".into(),
        VhostLogging { enabled: None, log_file: Some("sub/file.log".into()) },
    );
    assert!(cfg.validate_log_paths().is_err());
}

// ── LogContext ──────────────────────────────────────────────────

#[test]
fn log_context_default() {
    let ctx = LogContext::default();
    assert!(ctx.route_idx.is_none());
    assert!(ctx.username.is_none());
    assert!(ctx.token_id.is_none());
    assert!(ctx.error_detail.is_none());
}

#[test]
fn log_context_set_error_detail_creates_extension() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_error_detail(&req, "invalid csrf token");
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert_eq!(ctx.error_detail.as_deref(), Some("invalid csrf token"));
}

#[test]
fn log_context_set_error_detail_merges() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_route(&req, 3);
    LogContext::set_error_detail(&req, "acl filter rejected");
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert_eq!(ctx.route_idx, Some(3));
    assert_eq!(ctx.error_detail.as_deref(), Some("acl filter rejected"));
}

#[test]
fn log_context_set_error_detail_overwrites() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_error_detail(&req, "first error");
    LogContext::set_error_detail(&req, "second error");
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert_eq!(ctx.error_detail.as_deref(), Some("second error"));
}

#[test]
fn log_context_set_route() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_route(&req, 7);
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert_eq!(ctx.route_idx, Some(7));
}

#[test]
fn log_context_set_user() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_user(&req, "alice", "tok_123");
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert_eq!(ctx.username.as_deref(), Some("alice"));
    assert_eq!(ctx.token_id.as_deref(), Some("tok_123"));
}

#[test]
fn log_context_set_user_empty_becomes_none() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_user(&req, "", "");
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert!(ctx.username.is_none());
    assert!(ctx.token_id.is_none());
}

// ── compile_format with [error_detail] ──────────────────────────

#[test]
fn compile_format_error_detail() {
    let segs = compile_format("[error_detail]");
    assert_eq!(segs.len(), 1);
    assert!(matches!(segs[0], Segment::Field(Field::ErrorDetail)));
}

#[test]
fn compile_format_error_detail_alias() {
    for alias in &["[error-detail]", "[error]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::ErrorDetail)));
    }
}

#[test]
fn compile_format_combined() {
    let segs = compile_format("[ip] [error_detail] [status]");
    assert_eq!(segs.len(), 5);
    assert!(matches!(segs[0], Segment::Field(Field::Ip)));
    assert!(matches!(segs[2], Segment::Field(Field::ErrorDetail)));
    assert!(matches!(segs[4], Segment::Field(Field::Status)));
}

// ── RequiredFields ──────────────────────────────────────────────

#[test]
fn required_fields_default_is_all_false() {
    let rf = RequiredFields::default();
    assert!(!rf.ip);
    assert!(!rf.user_agent);
    assert!(!rf.xff);
    assert!(!rf.referer);
    assert!(!rf.query);
    assert!(!rf.protocol);
    assert!(!rf.host);
    assert!(!rf.cpu_usage);
    assert!(!rf.memory_usage);
}

// ── VhostLogWriter ──────────────────────────────────────────────

fn can_write_log_dir() -> bool {
    std::fs::metadata(LOG_DIR).is_ok()
        && std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(format!("{}/.test_probe", LOG_DIR))
            .is_ok()
}

#[test]
fn vhost_log_writer_empty_path_is_noop() {
    let writer = proxyauth::network::accesslog::VhostLogWriter::new();
    writer.write("", "should not panic");
}

#[test]
fn vhost_log_writer_creates_file() {
    if !can_write_log_dir() {
        eprintln!("skipping: {} not writable", LOG_DIR);
        return;
    }
    let writer = proxyauth::network::accesslog::VhostLogWriter::new();
    let fname = "test_accesslog_writer.log";

    let _ = std::fs::remove_file(format!("{}/{}", LOG_DIR, fname));

    writer.write(fname, "line 1");
    writer.write(fname, "line 2");

    let content = std::fs::read_to_string(format!("{}/{}", LOG_DIR, fname)).unwrap();
    assert!(content.contains("line 1"));
    assert!(content.contains("line 2"));

    let _ = std::fs::remove_file(format!("{}/{}", LOG_DIR, fname));
}

#[test]
fn vhost_log_writer_shared_across_writes() {
    if !can_write_log_dir() {
        eprintln!("skipping: {} not writable", LOG_DIR);
        return;
    }
    let writer = proxyauth::network::accesslog::VhostLogWriter::new();
    let fname = "test_shared.log";

    let _ = std::fs::remove_file(format!("{}/{}", LOG_DIR, fname));

    for i in 0..50 {
        writer.write(fname, &format!("entry {i}"));
    }

    let content = std::fs::read_to_string(format!("{}/{}", LOG_DIR, fname)).unwrap();
    let line_count = content.lines().count();
    assert_eq!(line_count, 50);

    let _ = std::fs::remove_file(format!("{}/{}", LOG_DIR, fname));
}

// ── RouteRule log_file and log fields ───────────────────────────

#[test]
fn route_log_file_none_by_default() {
    let r = minimal_rule("/");
    assert!(r.log_file.is_none());
}

#[test]
fn route_log_none_by_default() {
    let r = minimal_rule("/");
    assert!(r.log.is_none());
}

// ── expand_vhost_groups propagation for log_file / log ──────────

#[test]
fn expand_propagates_log_file_from_group() {
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

#[test]
fn expand_propagates_log_from_group() {
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
fn expand_propagates_need_csrf_from_group() {
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

// ── validate_route_log_files ────────────────────────────────────

#[test]
fn validate_route_log_files_ok() {
    let mut r = minimal_rule("/");
    r.log_file = Some("access.log".into());
    proxyauth::network::proxy::validate_route_log_files(&[r]);
}

#[test]
#[should_panic(expected = "must not contain path traversal")]
fn validate_route_log_files_traversal_panics() {
    let mut r = minimal_rule("/");
    r.log_file = Some("../escape.log".into());
    proxyauth::network::proxy::validate_route_log_files(&[r]);
}

#[test]
#[should_panic(expected = "not an absolute path")]
fn validate_route_log_files_absolute_panics() {
    let mut r = minimal_rule("/");
    r.log_file = Some("/etc/passwd".into());
    proxyauth::network::proxy::validate_route_log_files(&[r]);
}

#[test]
#[should_panic(expected = "single filename")]
fn validate_route_log_files_subdir_panics() {
    let mut r = minimal_rule("/");
    r.log_file = Some("sub/dir/file.log".into());
    proxyauth::network::proxy::validate_route_log_files(&[r]);
}

#[test]
fn validate_route_log_files_empty_is_ok() {
    let mut r = minimal_rule("/");
    r.log_file = Some("".into());
    proxyauth::network::proxy::validate_route_log_files(&[r]);
}

#[test]
fn validate_route_log_files_none_is_ok() {
    let r = minimal_rule("/");
    proxyauth::network::proxy::validate_route_log_files(&[r]);
}
