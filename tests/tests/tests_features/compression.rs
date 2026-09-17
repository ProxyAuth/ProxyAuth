use proxyauth::config::compression::CompressionConfig;

// ── Defaults ────────────────────────────────────────────────────

#[test]
fn compression_disabled_by_default() {
    assert!(!CompressionConfig::default().is_enabled());
}

#[test]
fn compression_level_default() {
    assert_eq!(CompressionConfig::default().level, 5);
}

#[test]
fn compression_level_static_none_by_default() {
    assert!(CompressionConfig::default().level_static.is_none());
}

#[test]
fn compression_min_size_default() {
    assert_eq!(CompressionConfig::default().min_size, 1024);
}

#[test]
fn compression_file_static_empty_by_default() {
    assert!(CompressionConfig::default().file_static.is_empty());
}

#[test]
fn compression_spawn_blocking_threshold_default() {
    assert_eq!(
        CompressionConfig::default().spawn_blocking_threshold,
        262_144
    );
}

// ── effective_level ─────────────────────────────────────────────

#[test]
fn effective_level_no_static_returns_level() {
    let cfg = CompressionConfig {
        level: 7,
        level_static: None,
        ..Default::default()
    };
    assert_eq!(cfg.effective_level(false), 7);
}

#[test]
fn effective_level_static_with_override() {
    let cfg = CompressionConfig {
        level: 3,
        level_static: Some(9),
        ..Default::default()
    };
    assert_eq!(cfg.effective_level(true), 9);
}

#[test]
fn effective_level_static_without_override() {
    let cfg = CompressionConfig {
        level: 3,
        level_static: None,
        ..Default::default()
    };
    assert_eq!(cfg.effective_level(true), 3);
}

#[test]
fn effective_level_static_zero() {
    let cfg = CompressionConfig {
        level: 5,
        level_static: Some(0),
        ..Default::default()
    };
    assert_eq!(cfg.effective_level(true), 0);
}

#[test]
fn effective_level_clamping_gzip() {
    let cfg = CompressionConfig {
        level: 999,
        ..Default::default()
    };
    let clamped = cfg.level.min(9);
    assert_eq!(clamped, 9);
}

#[test]
fn effective_level_clamping_brotli() {
    let cfg = CompressionConfig {
        level: 999,
        ..Default::default()
    };
    let clamped = cfg.level.min(11);
    assert_eq!(clamped, 11);
}

// ── is_static_file ──────────────────────────────────────────────

#[test]
fn is_static_file_matches_with_dot() {
    let cfg = CompressionConfig {
        file_static: vec![".js".into()],
        ..Default::default()
    };
    assert!(cfg.is_static_file("/app.js"));
}

#[test]
fn is_static_file_matches_without_dot() {
    let cfg = CompressionConfig {
        file_static: vec!["js".into()],
        ..Default::default()
    };
    assert!(cfg.is_static_file("/app.js"));
}

#[test]
fn is_static_file_case_insensitive() {
    let cfg = CompressionConfig {
        file_static: vec![".JS".into()],
        ..Default::default()
    };
    assert!(cfg.is_static_file("/app.js"));
    assert!(cfg.is_static_file("/app.JS"));
    assert!(cfg.is_static_file("/app.Js"));
}

#[test]
fn is_static_file_no_match() {
    let cfg = CompressionConfig {
        file_static: vec![".js".into()],
        ..Default::default()
    };
    assert!(!cfg.is_static_file("/app.css"));
}

#[test]
fn is_static_file_empty_list() {
    let cfg = CompressionConfig::default();
    assert!(!cfg.is_static_file("/anything.js"));
}

#[test]
fn is_static_file_no_extension() {
    let cfg = CompressionConfig {
        file_static: vec![".js".into()],
        ..Default::default()
    };
    assert!(!cfg.is_static_file("/noext"));
}

#[test]
fn is_static_file_dot_only() {
    let cfg = CompressionConfig {
        file_static: vec![".js".into()],
        ..Default::default()
    };
    assert!(!cfg.is_static_file("/file."));
}

#[test]
fn is_static_file_multiple_extensions() {
    let cfg = CompressionConfig {
        file_static: vec![".js".into(), ".css".into(), ".svg".into()],
        ..Default::default()
    };
    assert!(cfg.is_static_file("/main.js"));
    assert!(cfg.is_static_file("/style.CSS"));
    assert!(cfg.is_static_file("/img/logo.svg"));
    assert!(!cfg.is_static_file("/api/data.json"));
}

#[test]
fn is_static_file_trailing_slash_no_ext() {
    let cfg = CompressionConfig {
        file_static: vec![".js".into()],
        ..Default::default()
    };
    assert!(!cfg.is_static_file("/assets/"));
}

// ── merged_over ─────────────────────────────────────────────────

#[test]
fn merged_over_inherits_level_static() {
    let global = CompressionConfig {
        level_static: Some(9),
        ..Default::default()
    };
    let route = CompressionConfig::default();
    let merged = route.merged_over(&global);
    assert_eq!(merged.level_static, Some(9));
}

#[test]
fn merged_over_route_level_static_wins() {
    let global = CompressionConfig {
        level_static: Some(5),
        ..Default::default()
    };
    let route = CompressionConfig {
        level_static: Some(11),
        ..Default::default()
    };
    let merged = route.merged_over(&global);
    assert_eq!(merged.level_static, Some(11));
}

#[test]
fn merged_over_inherits_file_static() {
    let global = CompressionConfig {
        file_static: vec![".js".into(), ".css".into()],
        ..Default::default()
    };
    let route = CompressionConfig::default();
    let merged = route.merged_over(&global);
    assert_eq!(merged.file_static, vec![".js", ".css"]);
}

#[test]
fn merged_over_route_file_static_wins() {
    let global = CompressionConfig {
        file_static: vec![".js".into()],
        ..Default::default()
    };
    let route = CompressionConfig {
        file_static: vec![".svg".into()],
        ..Default::default()
    };
    let merged = route.merged_over(&global);
    assert_eq!(merged.file_static, vec![".svg"]);
}

#[test]
fn merged_over_inherits_enabled() {
    let global = CompressionConfig {
        enabled: Some(true),
        ..Default::default()
    };
    let route = CompressionConfig::default();
    let merged = route.merged_over(&global);
    assert!(merged.is_enabled());
}

#[test]
fn merged_over_route_enabled_wins() {
    let global = CompressionConfig {
        enabled: Some(true),
        ..Default::default()
    };
    let route = CompressionConfig {
        enabled: Some(false),
        ..Default::default()
    };
    let merged = route.merged_over(&global);
    assert!(!merged.is_enabled());
}

#[test]
fn merged_over_inherits_level() {
    let global = CompressionConfig {
        level: 9,
        ..Default::default()
    };
    let route = CompressionConfig::default();
    let merged = route.merged_over(&global);
    assert_eq!(merged.level, 9);
}

#[test]
fn merged_over_route_nondefault_level_wins() {
    let global = CompressionConfig {
        level: 3,
        ..Default::default()
    };
    let route = CompressionConfig {
        level: 7,
        ..Default::default()
    };
    let merged = route.merged_over(&global);
    assert_eq!(merged.level, 7);
}

#[test]
fn merged_over_inherits_min_size() {
    let global = CompressionConfig {
        min_size: 4096,
        ..Default::default()
    };
    let route = CompressionConfig::default();
    let merged = route.merged_over(&global);
    assert_eq!(merged.min_size, 4096);
}

#[test]
fn merged_over_inherits_algorithm() {
    let global = CompressionConfig {
        algorithm: Some("br".into()),
        ..Default::default()
    };
    let route = CompressionConfig::default();
    let merged = route.merged_over(&global);
    assert_eq!(merged.algorithms(), vec!["br"]);
}

#[test]
fn merged_over_route_algorithm_wins() {
    let global = CompressionConfig {
        algorithm: Some("br".into()),
        ..Default::default()
    };
    let route = CompressionConfig {
        algorithm: Some("gzip".into()),
        ..Default::default()
    };
    let merged = route.merged_over(&global);
    assert_eq!(merged.algorithms(), vec!["gzip"]);
}

#[test]
fn merged_over_inherits_upstream_identity() {
    let global = CompressionConfig {
        upstream_identity: Some(false),
        ..Default::default()
    };
    let route = CompressionConfig::default();
    let merged = route.merged_over(&global);
    assert!(!merged.strips_upstream_accept_encoding());
}

#[test]
fn merged_over_inherits_spawn_blocking_threshold() {
    let global = CompressionConfig {
        spawn_blocking_threshold: 512_000,
        ..Default::default()
    };
    let route = CompressionConfig::default();
    let merged = route.merged_over(&global);
    assert_eq!(merged.spawn_blocking_threshold, 512_000);
}

// ── algorithms ──────────────────────────────────────────────────

#[test]
fn algorithms_default_order() {
    assert_eq!(
        CompressionConfig::default().algorithms(),
        vec!["br", "gzip", "deflate"]
    );
}

#[test]
fn algorithms_comma_separated() {
    let cfg = CompressionConfig {
        algorithm: Some("gzip, br".into()),
        ..Default::default()
    };
    assert_eq!(cfg.algorithms(), vec!["gzip", "br"]);
}

#[test]
fn algorithms_single() {
    let cfg = CompressionConfig {
        algorithm: Some("deflate".into()),
        ..Default::default()
    };
    assert_eq!(cfg.algorithms(), vec!["deflate"]);
}

#[test]
fn algorithms_empty_string_falls_back() {
    let cfg = CompressionConfig {
        algorithm: Some("".into()),
        ..Default::default()
    };
    assert_eq!(cfg.algorithms(), vec!["br", "gzip", "deflate"]);
}

#[test]
fn algorithms_whitespace_trimmed() {
    let cfg = CompressionConfig {
        algorithm: Some("  gzip ,  br  ".into()),
        ..Default::default()
    };
    assert_eq!(cfg.algorithms(), vec!["gzip", "br"]);
}

// ── upstream_identity ───────────────────────────────────────────

#[test]
fn upstream_identity_defaults_to_true() {
    assert!(CompressionConfig::default().strips_upstream_accept_encoding());
}

#[test]
fn upstream_identity_explicit_false() {
    let cfg = CompressionConfig {
        upstream_identity: Some(false),
        ..Default::default()
    };
    assert!(!cfg.strips_upstream_accept_encoding());
}

// ── Deserialization ─────────────────────────────────────────────

#[test]
fn compression_config_from_json_minimal() {
    let cfg: CompressionConfig = serde_json::from_str("{}").unwrap();
    assert!(!cfg.is_enabled());
    assert_eq!(cfg.level, 5);
}

#[test]
fn compression_config_from_json_full() {
    let json = r#"{
        "enabled": true,
        "algorithm": "br",
        "level": 7,
        "level_static": 11,
        "min_size": 2048,
        "types": ["text/"],
        "upstream_identity": false,
        "file_static": [".js", ".css"],
        "spawn_blocking_threshold": 524288
    }"#;
    let cfg: CompressionConfig = serde_json::from_str(json).unwrap();
    assert!(cfg.is_enabled());
    assert_eq!(cfg.level, 7);
    assert_eq!(cfg.level_static, Some(11));
    assert_eq!(cfg.min_size, 2048);
    assert_eq!(cfg.types.as_ref().unwrap(), &vec!["text/"]);
    assert!(!cfg.strips_upstream_accept_encoding());
    assert_eq!(cfg.file_static, vec![".js", ".css"]);
    assert_eq!(cfg.spawn_blocking_threshold, 524288);
}
