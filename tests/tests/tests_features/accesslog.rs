use actix_web::HttpMessage;
use proxyauth::config::logging::LoggingConfig;
use proxyauth::config::logging::LOG_DIR;
use proxyauth::network::accesslog::{
    compile_format, Field, LogContext, RequiredFields, Segment,
    VhostLogWriter,
};

// ── compile_format: all known placeholders ──────────────────────

#[test]
fn compile_all_placeholders() {
    let fmt = "[vhost] [ip] [method] [path] [status] [length] \
              [user-agent] [x-forwarded-for] [host] [protocol] \
              [query] [referer] [request-time] [cpu-usage] \
              [memory-usage] [username] [token-id] [route] \
              [time] [error_detail]";
    let segs = compile_format(fmt);
    let fields: Vec<_> = segs
        .iter()
        .filter_map(|s| match s {
            Segment::Field(f) => Some(*f),
            _ => None,
        })
        .collect();
    assert_eq!(fields.len(), 20);
    assert!(fields.contains(&Field::Vhost));
    assert!(fields.contains(&Field::Ip));
    assert!(fields.contains(&Field::Method));
    assert!(fields.contains(&Field::Path));
    assert!(fields.contains(&Field::Status));
    assert!(fields.contains(&Field::Length));
    assert!(fields.contains(&Field::UserAgent));
    assert!(fields.contains(&Field::XForwardedFor));
    assert!(fields.contains(&Field::Host));
    assert!(fields.contains(&Field::Protocol));
    assert!(fields.contains(&Field::Query));
    assert!(fields.contains(&Field::Referer));
    assert!(fields.contains(&Field::RequestTime));
    assert!(fields.contains(&Field::CpuUsage));
    assert!(fields.contains(&Field::MemoryUsage));
    assert!(fields.contains(&Field::Username));
    assert!(fields.contains(&Field::TokenId));
    assert!(fields.contains(&Field::Route));
    assert!(fields.contains(&Field::Time));
    assert!(fields.contains(&Field::ErrorDetail));
}

// ── compile_format: error_detail aliases ────────────────────────

#[test]
fn compile_error_detail_aliases() {
    for alias in &["[error_detail]", "[error-detail]", "[error]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1, "alias {alias} should produce exactly one segment");
        assert!(matches!(segs[0], Segment::Field(Field::ErrorDetail)));
    }
}

// ── compile_format: user-agent aliases ──────────────────────────

#[test]
fn compile_user_agent_aliases() {
    for alias in &["[user-agent]", "[user_agent]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::UserAgent)));
    }
}

// ── compile_format: x-forwarded-for aliases ─────────────────────

#[test]
fn compile_xff_aliases() {
    for alias in &["[x-forwarded-for]", "[x_forwarded_for]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::XForwardedFor)));
    }
}

// ── compile_format: referer aliases ─────────────────────────────

#[test]
fn compile_referer_aliases() {
    for alias in &["[referer]", "[referrer]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::Referer)));
    }
}

// ── compile_format: time aliases ────────────────────────────────

#[test]
fn compile_time_aliases() {
    for alias in &["[time]", "[timestamp]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::Time)));
    }
}

// ── compile_format: username aliases ────────────────────────────

#[test]
fn compile_username_aliases() {
    for alias in &["[username]", "[user]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::Username)));
    }
}

// ── compile_format: token-id aliases ────────────────────────────

#[test]
fn compile_token_id_aliases() {
    for alias in &["[token-id]", "[tid]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::TokenId)));
    }
}

// ── compile_format: request-time aliases ────────────────────────

#[test]
fn compile_request_time_aliases() {
    for alias in &["[request-time]", "[request_time]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::RequestTime)));
    }
}

// ── compile_format: cpu-usage aliases ───────────────────────────

#[test]
fn compile_cpu_usage_aliases() {
    for alias in &["[cpu-usage]", "[cpu_usage]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::CpuUsage)));
    }
}

// ── compile_format: memory-usage aliases ────────────────────────

#[test]
fn compile_memory_usage_aliases() {
    for alias in &["[memory-usage]", "[memory_usage]"] {
        let segs = compile_format(alias);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Field(Field::MemoryUsage)));
    }
}

// ── compile_format: edge cases ──────────────────────────────────

#[test]
fn compile_empty_string() {
    assert!(compile_format("").is_empty());
}

#[test]
fn compile_no_brackets() {
    let segs = compile_format("hello world");
    assert_eq!(segs.len(), 1);
    assert!(matches!(&segs[0], Segment::Literal(s) if s == "hello world"));
}

#[test]
fn compile_unknown_placeholder_literal() {
    let segs = compile_format("[UNKNOWN_FIELD]");
    assert_eq!(segs.len(), 1);
    assert!(matches!(&segs[0], Segment::Literal(s) if s == "[UNKNOWN_FIELD]"));
}

#[test]
fn compile_unmatched_open_bracket() {
    let segs = compile_format("[ip");
    assert_eq!(segs.len(), 1);
    assert!(matches!(&segs[0], Segment::Literal(s) if s == "[ip"));
}

#[test]
fn compile_literal_brackets() {
    let segs = compile_format("text [with] [ip] here");
    assert_eq!(segs.len(), 3);
    assert!(matches!(&segs[0], Segment::Literal(s) if s == "text [with] "));
    assert!(matches!(&segs[1], Segment::Field(Field::Ip)));
    assert!(matches!(&segs[2], Segment::Literal(s) if s == " here"));
}

#[test]
fn compile_multibyte_separator() {
    let segs = compile_format("→[ip]←");
    assert_eq!(segs.len(), 3);
    assert!(matches!(&segs[0], Segment::Literal(s) if s == "→"));
    assert!(matches!(&segs[1], Segment::Field(Field::Ip)));
    assert!(matches!(&segs[2], Segment::Literal(s) if s == "←"));
}

#[test]
fn compile_case_insensitive() {
    let segs = compile_format("[IP]");
    assert_eq!(segs.len(), 1);
    assert!(matches!(segs[0], Segment::Field(Field::Ip)));
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
fn writer_empty_path_noop() {
    let w = VhostLogWriter::new();
    w.write("", "this should not appear");
}

#[test]
fn writer_creates_file_and_writes() {
    if !can_write_log_dir() {
        eprintln!("skipping: {} not writable", LOG_DIR);
        return;
    }
    let w = VhostLogWriter::new();
    let fname = "test_writer_basic.log";
    let path = format!("{}/{}", LOG_DIR, fname);
    let _ = std::fs::remove_file(&path);

    w.write(fname, "first line");
    w.write(fname, "second line");

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("first line"));
    assert!(content.contains("second line"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn writer_multiple_files_independent() {
    if !can_write_log_dir() {
        eprintln!("skipping: {} not writable", LOG_DIR);
        return;
    }
    let w = VhostLogWriter::new();
    let f1 = "test_writer_a.log";
    let f2 = "test_writer_b.log";
    let p1 = format!("{}/{}", LOG_DIR, f1);
    let p2 = format!("{}/{}", LOG_DIR, f2);
    let _ = std::fs::remove_file(&p1);
    let _ = std::fs::remove_file(&p2);

    w.write(f1, "file A");
    w.write(f2, "file B");

    assert!(std::fs::read_to_string(&p1).unwrap().contains("file A"));
    assert!(std::fs::read_to_string(&p2).unwrap().contains("file B"));
    assert!(!std::fs::read_to_string(&p1).unwrap().contains("file B"));

    let _ = std::fs::remove_file(&p1);
    let _ = std::fs::remove_file(&p2);
}

#[test]
fn writer_high_volume() {
    if !can_write_log_dir() {
        eprintln!("skipping: {} not writable", LOG_DIR);
        return;
    }
    let w = VhostLogWriter::new();
    let fname = "test_writer_volume.log";
    let path = format!("{}/{}", LOG_DIR, fname);
    let _ = std::fs::remove_file(&path);

    for i in 0..200 {
        w.write(fname, &format!("entry {i:04}"));
    }

    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content.lines().count(), 200);
    assert!(content.contains("entry 0000"));
    assert!(content.contains("entry 0199"));

    let _ = std::fs::remove_file(&path);
}

// ── LogContext field lifecycle ───────────────────────────────────

#[test]
fn log_context_set_route_then_error_detail() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_route(&req, 5);
    LogContext::set_error_detail(&req, "acl filter rejected");
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert_eq!(ctx.route_idx, Some(5));
    assert_eq!(ctx.error_detail.as_deref(), Some("acl filter rejected"));
}

#[test]
fn log_context_set_user_then_error_detail() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_user(&req, "bob", "tok_99");
    LogContext::set_error_detail(&req, "invalid csrf token");
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert_eq!(ctx.username.as_deref(), Some("bob"));
    assert_eq!(ctx.token_id.as_deref(), Some("tok_99"));
    assert_eq!(ctx.error_detail.as_deref(), Some("invalid csrf token"));
}

#[test]
fn log_context_full_lifecycle() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    LogContext::set_route(&req, 3);
    LogContext::set_user(&req, "charlie", "tok_42");
    LogContext::set_error_detail(&req, "method not allowed");
    let ctx = req.extensions().get::<LogContext>().cloned().unwrap();
    assert_eq!(ctx.route_idx, Some(3));
    assert_eq!(ctx.username.as_deref(), Some("charlie"));
    assert_eq!(ctx.token_id.as_deref(), Some("tok_42"));
    assert_eq!(ctx.error_detail.as_deref(), Some("method not allowed"));
}

// ── RequiredFields ──────────────────────────────────────────────

#[test]
fn required_fields_from_default_config() {
    let cfg = LoggingConfig::default();
    let fmt = &cfg.format;
    let segs = compile_format(fmt);

    let mut req = RequiredFields::default();
    for seg in &segs {
        if let Segment::Field(f) = seg {
            match f {
                Field::Ip => req.ip = true,
                Field::UserAgent => req.user_agent = true,
                Field::XForwardedFor => req.xff = true,
                Field::Referer => req.referer = true,
                Field::Query => req.query = true,
                Field::Protocol => req.protocol = true,
                Field::Host => req.host = true,
                Field::CpuUsage => req.cpu_usage = true,
                Field::MemoryUsage => req.memory_usage = true,
                _ => {}
            }
        }
    }

    // DEFAULT_FORMAT = "[time] [[vhost]] [[ip]] - [method] [protocol] [status] [length] [path] [tid:[token-id]] '[user-agent]' '[referer]' [request-time-ns]"
    assert!(req.ip);
    assert!(req.user_agent);
    assert!(!req.xff);
    assert!(req.referer);
    assert!(!req.query);
    assert!(req.protocol);
    assert!(!req.host);
    assert!(!req.cpu_usage);
    assert!(!req.memory_usage);
}

// ── LoggingConfig route-level ───────────────────────────────────

#[test]
fn logging_config_route_enabled_empty() {
    let cfg = LoggingConfig::default();
    assert!(cfg.route_enabled("/api").is_none());
}

#[test]
fn logging_config_route_enabled_set() {
    let mut cfg = LoggingConfig::default();
    cfg.routes.insert("/api".into(), false);
    cfg.routes.insert("/health".into(), true);
    assert_eq!(cfg.route_enabled("/api"), Some(false));
    assert_eq!(cfg.route_enabled("/health"), Some(true));
    assert!(cfg.route_enabled("/other").is_none());
}

// ── LoggingConfig deserialization ───────────────────────────────

#[test]
fn logging_config_full_json() {
    let json = r#"{
        "enabled": false,
        "format": "[ip] [status]",
        "log_file": "custom.log",
        "resource_sample_interval_secs": 5
    }"#;
    let cfg: LoggingConfig = serde_json::from_str(json).unwrap();
    assert!(!cfg.enabled);
    assert_eq!(cfg.format, "[ip] [status]");
    assert_eq!(cfg.log_file, "custom.log");
    assert_eq!(cfg.resource_sample_interval_secs, 5);
}

#[test]
fn logging_config_alias_log() {
    let json = r#"{"log": false}"#;
    let cfg: LoggingConfig = serde_json::from_str(json).unwrap();
    assert!(!cfg.enabled);
}

#[test]
fn logging_config_alias_format_log() {
    let json = r#"{"format-log": "[method] [path]"}"#;
    let cfg: LoggingConfig = serde_json::from_str(json).unwrap();
    assert_eq!(cfg.format, "[method] [path]");
}

// ── Default format compiles without unknown placeholders ────────

#[test]
fn default_format_compiles_all_known() {
    let segs = compile_format(&proxyauth::config::logging::DEFAULT_FORMAT);
    // A genuinely unrecognized placeholder (a typo like "[stauts]")
    // compiles down to one literal segment that starts with '[' and
    // ends with ']', as a self-contained chunk — that's the actual
    // signature of "this looked like a placeholder attempt but didn't
    // match a known field name".
    //
    // A broader check ("contains both characters anywhere in the same
    // literal") used to also flag DEFAULT_FORMAT's own deliberate
    // adjacent-bracket style (`[[vhost]] [[ip]]` compiles to, among
    // other things, a legitimate literal "] [" sitting between two
    // correctly-recognized fields) as a false positive, even though
    // nothing about it is actually unrecognized.
    let has_unknown = segs.iter().any(|s| {
        if let Segment::Literal(l) = s {
            // A well-ordered '[' followed later by a ']' within the
            // SAME literal segment is the real signature of a failed
            // placeholder attempt — regardless of what comes before the
            // '[' or after the ']' in that literal (which can include
            // ordinary separator text absorbed into the same segment
            // before the next recognized field starts, e.g. a trailing
            // space). Checking the whole literal starts-with/ends-with
            // brackets is too strict: an unrecognized placeholder
            // followed by more text — as it usually is in a real format
            // — gets that trailing text folded into the same literal,
            // so the segment rarely ends exactly on ']'.
            l.find('[').is_some_and(|open| l[open + 1..].contains(']'))
        } else {
            false
        }
    });
    assert!(!has_unknown, "DEFAULT_FORMAT should not contain unknown placeholders");
}

// ── Multiple commas in format ───────────────────────────────────

#[test]
fn compile_adjacent_placeholders() {
    let segs = compile_format("[ip][status]");
    assert_eq!(segs.len(), 2);
    assert!(matches!(segs[0], Segment::Field(Field::Ip)));
    assert!(matches!(segs[1], Segment::Field(Field::Status)));
}

#[test]
fn compile_only_placeholders() {
    let segs = compile_format("[ip][status][length]");
    assert_eq!(segs.len(), 3);
    assert!(matches!(segs[0], Segment::Field(Field::Ip)));
    assert!(matches!(segs[1], Segment::Field(Field::Status)));
    assert!(matches!(segs[2], Segment::Field(Field::Length)));
}

// ── VhostLogWriter separate from log enable ─────────────────────

#[test]
fn writer_works_even_with_logging_disabled() {
    if !can_write_log_dir() {
        eprintln!("skipping: {} not writable", LOG_DIR);
        return;
    }
    let w = VhostLogWriter::new();
    let fname = "test_writer_logging_disabled.log";
    let path = format!("{}/{}", LOG_DIR, fname);
    let _ = std::fs::remove_file(&path);

    w.write(fname, "logged even when access log is off");
    assert!(std::fs::read_to_string(&path).unwrap().contains("logged even when access log is off"));

    let _ = std::fs::remove_file(&path);
}
