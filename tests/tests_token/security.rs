use actix_web::http::StatusCode;
use chrono::Utc;
use proxyauth::AppConfig;
use proxyauth::config::config::RegexCond;
use proxyauth::network::canonical_url::canonicalize_path_for_match;
use proxyauth::token::security::all_values_match;
use proxyauth::token::security::apply_filters_regex_allow_only;
use proxyauth::token::security::check_date_token;
use proxyauth::token::security::cond_matches_strict;
use proxyauth::token::security::extract_token_user;
use proxyauth::token::security::format_long_date;
use proxyauth::token::security::get_build_datetime;
use proxyauth::token::security::get_build_epochdate;
use proxyauth::token::security::get_build_rand;
use proxyauth::token::security::get_build_seed2;
use proxyauth::token::security::get_build_time;
use proxyauth::token::security::issue_token;
use proxyauth::token::security::parse_query_map;
use serde_json::Value as JsonValue;

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::Method, http::header, test, test::TestRequest};
    use bytes::Bytes;
    use proxyauth::config::config::{AllowRegexCfg, RegexCondCfg, RouteRule};
    use regex::Regex;
    use serde_json::json;

    // ---------- parse_query_map ----------------------------------------------

    #[test]
    async fn parse_query_map_multiple_values_and_missing_value() {
        let q = "a=1&a=2&b=&c";
        let m = parse_query_map(q);
        assert_eq!(m.get("a").unwrap(), &vec!["1".to_string(), "2".to_string()]);
        assert_eq!(m.get("b").unwrap(), &vec!["".to_string()]);
        assert_eq!(m.get("c").unwrap(), &vec!["".to_string()]);
        assert!(m.get("d").is_none());
    }

    fn mk_rule(filters: AllowRegexCfg) -> RouteRule {
        let compiled = filters.compile().ok();
        RouteRule {
            prefix: "/api".into(),
            target: "http://upstream".into(),
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
            need_csrf: Some(false),
            log: None,
            log_file: None,
            compression: None,
            cache: Some(true),
            streaming: None,
            cache_duration_secs: None,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: Some(filters),
            filters_compiled: compiled,
            forward_proxy_headers: None,
            oidc: None,
            redirect_protect: None,
        }
    }

    #[actix_web::test]
    async fn acl_all_must_match_ok() {
        let filters = AllowRegexCfg {
            default_allow: false,
            allow: vec![
                RegexCondCfg::Method {
                    pattern: r"(?i)^POST$".into(),
                },
                RegexCondCfg::Path {
                    pattern: r"^/api/v1/items$".into(),
                },
                RegexCondCfg::Header {
                    name: r"(?i)^x-trace-id$".into(),
                    pattern: r"^[a-f0-9-]{8,}$".into(),
                },
                RegexCondCfg::Query {
                    name: r"(?i)^page$".into(),
                    pattern: r"^\d+$".into(),
                },
                RegexCondCfg::BodyJson {
                    key: "name".into(),
                    pattern: r"^[a-z0-9_-]{3,16}$".into(),
                },
            ],
        };
        let rule = mk_rule(filters);

        let req = test::TestRequest::post()
            .uri("/api/v1/items?page=2")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .insert_header(("x-trace-id", "abcd-1234-ef"))
            .set_payload(r#"{ "name":"hello_123" }"#)
            .to_http_request();

        let status = super::apply_filters_regex_allow_only(
            &rule,
            &req,
            &Bytes::from_static(b"{\"name\":\"hello_123\"}"),
        );
        assert!(status.is_none(), "should be allowed (all conditions match)");
    }

    #[actix_web::test]
    async fn acl_mismatch_denied() {
        let filters = AllowRegexCfg {
            default_allow: false,
            allow: vec![RegexCondCfg::Method {
                pattern: r"(?i)^GET$".into(),
            }],
        };
        let rule = mk_rule(filters);

        let req = test::TestRequest::post().uri("/api/list").to_http_request();

        let status = super::apply_filters_regex_allow_only(&rule, &req, &[]);
        assert_eq!(status, Some(StatusCode::FORBIDDEN));
    }

    #[actix_web::test]
    async fn acl_default_allow_false_and_no_rules_denied() {
        let filters = AllowRegexCfg {
            default_allow: false,
            allow: vec![],
        };
        let rule = mk_rule(filters);
        let req = test::TestRequest::get().uri("/api").to_http_request();
        let status = super::apply_filters_regex_allow_only(&rule, &req, &[]);
        assert_eq!(status, Some(StatusCode::FORBIDDEN));
    }

    #[actix_web::test]
    async fn acl_bodyraw_and_header_and_query() {
        let filters = AllowRegexCfg {
            default_allow: false,
            allow: vec![
                RegexCondCfg::Method {
                    pattern: r"^POST$".into(),
                },
                RegexCondCfg::Header {
                    name: r"(?i)^content-type$".into(),
                    pattern: r"^application/x-www-form-urlencoded".into(),
                },
                RegexCondCfg::Query {
                    name: r"(?i)^lang$".into(),
                    pattern: r"^(en|fr)$".into(),
                },
                RegexCondCfg::BodyRaw {
                    pattern: r"(^|&)name=[a-z]{2,8}(&|$)".into(),
                },
            ],
        };
        let rule = mk_rule(filters);

        let req = test::TestRequest::post()
            .uri("/api/form?lang=fr")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("name=alice&x=1")
            .to_http_request();

        let status = super::apply_filters_regex_allow_only(&rule, &req, b"name=alice&x=1");
        assert!(status.is_none(), "form should pass");
    }

    // ---------- all_values_match ---------------------------------------------

    #[test]
    async fn all_values_match_ok_and_ko() {
        let re_ok = Regex::new("^[a-z]+$").unwrap();
        assert!(all_values_match(["abc", "xyz"], &re_ok));

        let re_ko = Regex::new("^a+$").unwrap();
        assert!(!all_values_match(["a", "b"], &re_ko));
    }

    // ---------- canonicalize + Path ------------------------------------------

    #[test]
    async fn cond_matches_path_with_canonicalization() {
        let raw_path = "/api%2Fadmin";
        let canon = canonicalize_path_for_match(raw_path);
        let cond = RegexCond::Path {
            re: Regex::new("^/api/admin$").unwrap(),
        };

        let ok = cond_matches_strict(
            &cond,
            &Method::GET,
            &canon,
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(),
            None,
            None,
            "",
        );
        assert!(ok);
    }

    // ---------- Method -------------------------------------------------------

    #[test]
    async fn cond_matches_method_exact() {
        let cond = RegexCond::Method {
            re: Regex::new("^POST$").unwrap(),
        };
        assert!(cond_matches_strict(
            &cond,
            &Method::POST,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(),
            None,
            None,
            ""
        ));
        assert!(!cond_matches_strict(
            &cond,
            &Method::GET,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(),
            None,
            None,
            ""
        ));
    }

    // ---------- Header -------------------------------------------------------

    #[test]
    async fn cond_matches_header_name_and_values() {
        let req = TestRequest::default()
            .insert_header(("x-client", "abc_123"))
            .insert_header(("x-client", "def-456"))
            .insert_header(("other", "zzz"))
            .to_http_request();

        let cond_ok = RegexCond::Header {
            name_re: Regex::new("^x-client$").unwrap(),
            re: Regex::new("^[a-z0-9_\\-]+$").unwrap(),
        };
        assert!(cond_matches_strict(
            &cond_ok,
            &Method::GET,
            "/",
            req.headers().clone(),
            &std::collections::HashMap::new(),
            None,
            None,
            ""
        ));

        let req_bad = TestRequest::default()
            .insert_header(("x-client", "ok"))
            .insert_header(("x-client", "NO!"))
            .to_http_request();

        assert!(!cond_matches_strict(
            &cond_ok,
            &Method::GET,
            "/",
            req_bad.headers().clone(),
            &std::collections::HashMap::new(),
            None,
            None,
            ""
        ));

        let cond_name_missing = RegexCond::Header {
            name_re: Regex::new("^x-missing$").unwrap(),
            re: Regex::new(".*").unwrap(),
        };
        assert!(!cond_matches_strict(
            &cond_name_missing,
            &Method::GET,
            "/",
            req.headers().clone(),
            &std::collections::HashMap::new(),
            None,
            None,
            ""
        ));
    }

    // ---------- Query --------------------------------------------------------

    #[test]
    async fn cond_matches_query_all_values_must_match() {
        let q = parse_query_map("foo=a&foo=ab&bar=zzz");

        let cond_ok = RegexCond::Query {
            name_re: Regex::new("^foo$").unwrap(),
            re: Regex::new("^[ab]+$").unwrap(),
        };
        assert!(cond_matches_strict(
            &cond_ok,
            &Method::GET,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &q,
            None,
            None,
            ""
        ));

        let cond_bad = RegexCond::Query {
            name_re: Regex::new("^foo$").unwrap(),
            re: Regex::new("^a$").unwrap(),
        };
        assert!(!cond_matches_strict(
            &cond_bad,
            &Method::GET,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &q,
            None,
            None,
            ""
        ));

        let cond_missing = RegexCond::Query {
            name_re: Regex::new("^qux$").unwrap(),
            re: Regex::new(".*").unwrap(),
        };
        assert!(!cond_matches_strict(
            &cond_missing,
            &Method::GET,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &q,
            None,
            None,
            ""
        ));
    }

    // ---------- BodyRaw ------------------------------------------------------

    #[test]
    async fn cond_matches_body_raw_utf8() {
        let cond = RegexCond::BodyRaw {
            re: Regex::new("^hello[ ]+world$").unwrap(),
        };
        assert!(cond_matches_strict(
            &cond,
            &Method::POST,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(),
            Some("hello world"),
            None,
            "text/plain"
        ));
        assert!(!cond_matches_strict(
            &cond,
            &Method::POST,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(),
            Some("hello  WORLD"),
            None,
            "text/plain"
        ));
    }

    // ---------- BodyJson -----------------------------------------------------

    #[test]
    async fn cond_matches_body_json_with_ct_guard() {
        let body = json!({"role":"admin","n":42,"active":true});
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let body_utf8 = std::str::from_utf8(&body_bytes).ok();
        let body_json: Option<JsonValue> = serde_json::from_slice(&body_bytes).ok();

        let c_role = RegexCond::BodyJson {
            key: "role".into(),
            re: Regex::new("^admin$").unwrap(),
        };
        let c_num = RegexCond::BodyJson {
            key: "n".into(),
            re: Regex::new("^42$").unwrap(),
        };
        let c_bool = RegexCond::BodyJson {
            key: "active".into(),
            re: Regex::new("^true$").unwrap(),
        };

        for cond in [&c_role, &c_num, &c_bool] {
            assert!(cond_matches_strict(
                cond,
                &Method::POST,
                "/",
                actix_web::http::header::HeaderMap::new(),
                &std::collections::HashMap::new(),
                body_utf8,
                body_json.as_ref(),
                "application/json"
            ));
        }

        assert!(!cond_matches_strict(
            &c_role,
            &Method::POST,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(),
            body_utf8,
            body_json.as_ref(),
            "text/plain"
        ));

        let c_missing = RegexCond::BodyJson {
            key: "missing".into(),
            re: Regex::new(".*").unwrap(),
        };
        assert!(!cond_matches_strict(
            &c_missing,
            &Method::POST,
            "/",
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(),
            body_utf8,
            body_json.as_ref(),
            "application/json"
        ));
    }

    // `derive_key_is_32_bytes_and_stable`, `generate_secret_has_secret_
    // and_timestamp_suffix` and `generate_token_is_sha256_hex` used to
    // sit here. All three tested internals that now belong to the
    // `zerocrypt` crate, which covers the same ground: key derivation
    // being stable and secret-dependent, and the signature's shape.
    //
    // `generate_secret` is gone outright rather than moved. It never
    // rotated: its base was the compile-time build date and the clock it
    // read fed only a discarded variable, so it returned the same string
    // for a binary's whole life. The property it looked like it provided
    // was not one it had.

    /// A token issued through the real path is opaque, URL-safe, and
    /// carries nothing readable.
    #[test]
    async fn issued_tokens_are_opaque_and_url_safe() {
        let expiry = (chrono::Utc::now() + chrono::Duration::seconds(600))
            .timestamp()
            .to_string();

        // The vault is initialised for the whole binary by the `#[ctor]`
        // in `tests_token/mod.rs`, so a failure here is a real one.
        let token = issue_token("alice", 0, &expiry, "tid-opaque").expect("issue");

        assert!(!token.contains("alice"));
        assert!(!token.contains("tid-opaque"));
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "token is not URL-safe: {token}"
        );
    }
}

#[cfg(test)]
mod more_unit_tests {
    use super::*;
    use proxyauth::config::config::{AllowRegexCfg, RouteRule};

    fn mk_rule(filters: AllowRegexCfg) -> RouteRule {
        let compiled = filters.compile().ok();
        RouteRule {
            prefix: "/api".into(),
            target: "http://upstream".into(),
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
            need_csrf: Some(false),
            log: None,
            log_file: None,
            compression: None,
            cache: Some(true),
            streaming: None,
            cache_duration_secs: None,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: Some(filters),
            filters_compiled: compiled,
            forward_proxy_headers: None,
            oidc: None,
            redirect_protect: None,
        }
    }

    // ---------------- check_date_token ----------------

    #[test]
    fn check_date_token_accepts_future_iso_in_tz() {
        let exp = (Utc::now() + chrono::Duration::minutes(10))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let res = check_date_token(&exp, "alice", "127.0.0.1", "UTC");
        assert!(res.is_ok());
        assert!(res.unwrap() > 0);
    }

    #[test]
    fn check_date_token_accepts_future_epoch() {
        let exp_epoch = (Utc::now() + chrono::Duration::minutes(5))
            .timestamp()
            .to_string();
        let res = check_date_token(&exp_epoch, "bob", "127.0.0.1", "UTC");
        assert!(res.is_ok());
    }

    #[test]
    fn check_date_token_rejects_expired() {
        let past = (Utc::now() - chrono::Duration::minutes(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let res = check_date_token(&past, "carol", "127.0.0.1", "UTC");
        assert!(res.is_err());
    }

    #[test]
    fn check_date_token_rejects_bad_timezone() {
        let exp = (Utc::now() + chrono::Duration::minutes(2))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let res = check_date_token(&exp, "dave", "127.0.0.1", "Not/AZone");
        assert!(res.is_err());
    }

    // ---------------- format_long_date ----------------

    #[test]
    fn format_long_date_formats_components() {
        assert_eq!(format_long_date(0), "+00000000-01-01T00:00:00Z");
        assert_eq!(format_long_date(3661), "+00000000-01-01T01:01:01Z");
    }

    // ---------------- build helpers ----------------

    #[test]
    fn get_build_helpers_do_not_panic_and_types_match() {
        let _t: u64 = get_build_time();
        let _r: u64 = get_build_rand();
        let _s2: u64 = get_build_seed2();
        let _e: i64 = get_build_epochdate();

        let dt = get_build_datetime();
        assert_eq!(dt.timestamp(), get_build_epochdate());
    }

    // ---------------- apply_filters_regex_allow_only ----------------

    #[actix_web::test]
    async fn acl_default_allow_true_and_no_rules_allows() {
        let filters = AllowRegexCfg {
            default_allow: true,
            allow: vec![],
        };
        let rule = mk_rule(filters);
        let req = actix_web::test::TestRequest::get()
            .uri("/api/anything")
            .to_http_request();
        let status = super::apply_filters_regex_allow_only(&rule, &req, &[]);
        assert!(status.is_none());
    }

    // ---------------- extract_token_user ----------------

    #[test]
    fn extract_token_user_rejects_invalid_format() {
        let cfg = AppConfig {
            secret: "topsecret".into(),
            token_expiry_seconds: 3600,
            users: vec![],
            timezone: "UTC".into(),
            stats: false,
            ..Default::default()
        };
        let err =
            extract_token_user("this-is-not-encrypted", &cfg, "127.0.0.1".into()).unwrap_err();
        assert_eq!(err, "Invalid token format");
    }
}

// ---------------------------------------------------------------------
// `validate_token_from_decrypted` and the `validate_token_path_tests`
// module that used it have been removed.
//
// The helper was a second implementation of `validate_token`, operating
// on hand-written plaintext like `"only|two|parts"`. That only worked
// while the token layout lived in this crate; the layout is now the
// library's, and a test that reproduces it by hand tests the copy rather
// than the code.
//
// The fifteen cases it covered split in two. The layout-level ones — a
// malformed plaintext, a tampered digest, a stable signature for stable
// inputs — are covered inside `zerocrypt`, against the real
// implementation. The behaviour-level ones are ProxyAuth's own and are
// rewritten below against the real public API: mint with `issue_token`,
// verify with `validate_token`, no private layout knowledge.
// ---------------------------------------------------------------------

#[cfg(test)]
mod validate_token_path_tests {
    use actix_web::web;
    use chrono::Utc;
    use dashmap::DashMap;
    use std::sync::Arc;

    use proxyauth::AppConfig;
    use proxyauth::AppState;
    use proxyauth::config::config::{RouteConfig, User};
    use proxyauth::network::stats::{RequestStats, spawn_stats_ticker};
    use proxyauth::revoke::db::RevokedTokenMap;
    use proxyauth::stats::tokencount::CounterToken;
    use proxyauth::token::security::{issue_token, validate_token};

    /// A config with one user at index 0.
    ///
    /// `validate_token` resolves the user *before* it checks the expiry
    /// policy or the revocation list, so a config with no users would
    /// make every case below fail with "User not found" and none of the
    /// assertions would mean anything.
    fn mk_config(expiry: i64, stats: bool) -> AppConfig {
        AppConfig {
            secret: "super-secret".into(),
            timezone: "UTC".into(),
            token_expiry_seconds: expiry,
            stats,
            users: vec![User {
                username: "alice".into(),
                password: "not-checked-on-this-path".into(),
                otpkey: None,
                allow: None,
                roles: None,
                groups: None,
                email: None,
                must_change_password: false,
            }],
            ..Default::default()
        }
    }

    fn mk_state(cfg: AppConfig) -> web::Data<AppState> {
        let stats = RequestStats::new();
        spawn_stats_ticker(stats.clone());

        web::Data::new(AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig {
                routes: vec![],
                ..Default::default()
            }),
            counter: Arc::new(CounterToken::new()),
            revoked_tokens: Arc::new(DashMap::new()) as RevokedTokenMap,
            stats,
            otp_overrides: Arc::new(DashMap::new()),
            password_overrides: Arc::new(DashMap::new()),
            must_change_overrides: Arc::new(DashMap::new()),
            ip_blocklist: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            redirect_protect_url_ips: Arc::new(DashMap::new()),
        })
    }

    fn expiry_in(seconds: i64) -> String {
        (Utc::now() + chrono::Duration::seconds(seconds))
            .timestamp()
            .to_string()
    }

    /// The vault is initialised for the whole binary by the `#[ctor]` in
    /// `tests_token/mod.rs`, so this is expected to succeed.
    fn mint(user: &str, index: usize, expiry: &str, tid: &str) -> String {
        issue_token(user, index, expiry, tid).expect("issue token")
    }

    #[tokio::test]
    async fn garbage_is_rejected() {
        let cfg = mk_config(3600, false);
        let st = mk_state(mk_config(3600, false));

        for junk in ["", "!!!", "not-a-token", &"A".repeat(500)] {
            assert!(validate_token(junk, &st, &cfg, "127.0.0.1").await.is_err());
        }
    }

    #[tokio::test]
    async fn a_tampered_token_is_rejected() {
        let cfg = mk_config(3600, false);
        let st = mk_state(mk_config(3600, false));

        let token = mint("alice", 0, &expiry_in(600), "tid-tamper");

        let mut bytes = token.into_bytes();
        let last = bytes.len() - 5;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).expect("still utf8");

        assert!(
            validate_token(&tampered, &st, &cfg, "127.0.0.1")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_expired_token_says_so() {
        let cfg = mk_config(3600, false);
        let st = mk_state(mk_config(3600, false));

        // Already past: the vault reports Expired, which validate_token
        // maps to its own message rather than the generic failure.
        let token = mint("alice", 0, &expiry_in(-10), "tid-exp");

        let err = validate_token(&token, &st, &cfg, "127.0.0.1")
            .await
            .unwrap_err();
        assert_eq!(err, "Your token is expired");
    }

    #[tokio::test]
    async fn an_expiry_beyond_the_configured_limit_is_refused() {
        // A token whose remaining life exceeds token_expiry_seconds is
        // refused even though it is authentic and unexpired — the policy
        // check that stops a long-lived token surviving a config change.
        let cfg = mk_config(60, false);
        let st = mk_state(mk_config(60, false));

        let token = mint("alice", 0, &expiry_in(3600), "tid-far");

        let err = validate_token(&token, &st, &cfg, "127.0.0.1")
            .await
            .unwrap_err();
        assert_eq!(err, "Bad time token");
    }

    #[tokio::test]
    async fn an_out_of_range_index_is_refused() {
        let cfg = mk_config(3600, false);
        let st = mk_state(mk_config(3600, false));

        let token = mint("alice", 9_999, &expiry_in(600), "tid-idx");

        assert!(
            validate_token(&token, &st, &cfg, "127.0.0.1")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_revoked_token_is_refused() {
        let cfg = mk_config(3600, false);
        let st = mk_state(mk_config(3600, false));

        let token = mint("alice", 0, &expiry_in(600), "tid-revoked");

        // 0 means "revoked, no expiry" in is_token_revoked.
        st.revoked_tokens.insert("tid-revoked".to_string(), 0);

        let err = validate_token(&token, &st, &cfg, "127.0.0.1")
            .await
            .unwrap_err();
        assert_eq!(err, "revoked token");
    }

    #[tokio::test]
    async fn the_stats_path_does_not_panic() {
        let cfg = mk_config(3600, true);
        let st = mk_state(mk_config(3600, true));

        let token = mint("alice", 0, &expiry_in(600), "tid-stats");

        let _ = validate_token(&token, &st, &cfg, "127.0.0.1").await;
    }
}
