#[cfg(test)]
mod tests {
    use proxyauth::AppConfig;

    #[test]
    fn app_config_default_cache_duration_is_300() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.cache_duration_secs, 300);
    }

    #[test]
    fn app_config_default_timezone() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.timezone, "Europe/Paris");
    }

    #[test]
    fn app_config_default_port() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.port, 8080);
    }

    #[test]
    fn app_config_default_host() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.host, "0.0.0.0");
    }

    #[test]
    fn app_config_custom_port() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}, "port": 9090}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.port, 9090);
    }

    #[test]
    fn app_config_custom_timezone() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}, "timezone": "UTC"}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.timezone, "UTC");
    }

    #[test]
    fn app_config_session_cookie_default_false() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.session_cookie);
    }

    #[test]
    fn app_config_csrf_token_default_true() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.csrf_token);
    }

    #[test]
    fn app_config_fast_default_false() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.fast);
    }

    #[test]
    fn app_config_stats_default_false() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.stats);
    }

    #[test]
    fn app_config_tls_default_true() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.tls);
    }

    #[test]
    fn app_config_max_connections_default() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.max_connections, 50_000);
    }

    #[test]
    fn app_config_max_idle_per_host_default() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.max_idle_per_host, 50);
    }

    #[test]
    fn app_config_worker_default() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.worker, 4);
    }

    #[test]
    fn app_config_num_instances_default() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.num_instances, 2);
    }

    #[test]
    fn app_config_login_via_otp_default_false() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.login_via_otp);
    }

    #[test]
    fn app_config_secret_is_preserved() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "my-secret-key", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.secret, "my-secret-key");
    }

    #[test]
    fn app_config_token_expiry_seconds_is_preserved() {
        let json = r#"{"token_expiry_seconds": 7200, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.token_expiry_seconds, 7200);
    }

    #[test]
    fn app_config_cors_origins_default_none() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.cors_origins.is_none());
    }

    #[test]
    fn app_config_cors_origins_set() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}, "cors_origins": ["https://app.example.com"]}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.cors_origins.as_ref().unwrap().len(), 1);
        assert_eq!(cfg.cors_origins.as_ref().unwrap()[0], "https://app.example.com");
    }

    #[test]
    fn app_config_redis_default_none() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.redis.is_none());
    }

    #[test]
    fn app_config_effective_run_user_default() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_run_user(), "proxyauth");
    }

    #[test]
    fn app_config_effective_run_user_custom() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}, "run_user": "www-data"}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_run_user(), "www-data");
    }

    #[test]
    fn app_config_effective_run_user_empty_falls_back() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}, "run_user": ""}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_run_user(), "proxyauth");
    }

    #[test]
    fn app_config_effective_run_user_whitespace_falls_back() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}, "run_user": "  "}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_run_user(), "proxyauth");
    }

    #[test]
    fn app_config_effective_run_group_default_none() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.effective_run_group().is_none());
    }

    #[test]
    fn app_config_effective_run_group_set() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}, "run_group": "www-data"}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_run_group(), Some("www-data"));
    }

    #[test]
    fn app_config_effective_run_group_empty_falls_back() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}, "run_group": ""}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.effective_run_group().is_none());
    }

    #[test]
    fn app_config_bump_generation() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.current_generation(), 0);
        cfg.bump_generation();
        assert_eq!(cfg.current_generation(), 1);
        cfg.bump_generation();
        assert_eq!(cfg.current_generation(), 2);
    }

    #[test]
    fn app_config_blakegate_backup_mode_default_false() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.blakegate_backup_mode_active());
    }

    #[test]
    fn app_config_should_use_database_as_fallback_default_true() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.should_use_database_as_fallback());
    }

    #[test]
    fn app_config_max_age_session_cookie_default() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.max_age_session_cookie, 3600);
    }

    #[test]
    fn app_config_max_body_size_default() {
        let json = r#"{"token_expiry_seconds": 3600, "secret": "s", "users": [], "log": {}}"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.max_body_size, 10 * 1024 * 1024);
    }

    #[test]
    fn app_config_user_in_config() {
        let json = r#"{
            "token_expiry_seconds": 3600,
            "secret": "s",
            "users": [
                {
                    "username": "alice",
                    "password": "hash123",
                    "otpkey": null,
                    "allow": ["10.0.0.0/8"],
                    "roles": ["admin"],
                    "groups": ["ops"]
                }
            ],
            "log": {}
        }"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].username, "alice");
        assert_eq!(cfg.users[0].password, "hash123");
        assert!(cfg.users[0].otpkey.is_none());
        assert_eq!(cfg.users[0].allow.as_ref().unwrap().len(), 1);
        assert_eq!(cfg.users[0].allow.as_ref().unwrap()[0], "10.0.0.0/8");
        assert_eq!(cfg.users[0].roles.as_ref().unwrap().len(), 1);
        assert_eq!(cfg.users[0].roles.as_ref().unwrap()[0], "admin");
        assert_eq!(cfg.users[0].groups.as_ref().unwrap().len(), 1);
        assert_eq!(cfg.users[0].groups.as_ref().unwrap()[0], "ops");
    }

    #[test]
    fn app_config_multiple_users() {
        let json = r#"{
            "token_expiry_seconds": 3600,
            "secret": "s",
            "users": [
                {"username": "alice", "password": "h1"},
                {"username": "bob", "password": "h2"},
                {"username": "carol", "password": "h3"}
            ],
            "log": {}
        }"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.users.len(), 3);
        assert_eq!(cfg.users[0].username, "alice");
        assert_eq!(cfg.users[1].username, "bob");
        assert_eq!(cfg.users[2].username, "carol");
    }

    #[test]
    fn app_config_combined_users() {
        let json = r#"{
            "token_expiry_seconds": 3600,
            "secret": "s",
            "users": [
                {"username": "alice", "password": "h1"}
            ],
            "log": {}
        }"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        let combined = cfg.combined_users();
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].username, "alice");
    }

    #[test]
    fn app_config_roles_for_username_none_when_empty() {
        let json = r#"{
            "token_expiry_seconds": 3600,
            "secret": "s",
            "users": [],
            "log": {}
        }"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.roles_for_username("nonexistent").is_none());
    }

    #[test]
    fn app_config_groups_for_username_none_when_empty() {
        let json = r#"{
            "token_expiry_seconds": 3600,
            "secret": "s",
            "users": [],
            "log": {}
        }"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.groups_for_username("nonexistent").is_none());
    }

    #[test]
    fn app_config_user_index_out_of_bounds() {
        let json = r#"{
            "token_expiry_seconds": 3600,
            "secret": "s",
            "users": [
                {"username": "alice", "password": "h1"}
            ],
            "log": {}
        }"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.user_by_index(0).is_some());
        assert!(cfg.user_by_index(1).is_none());
        assert!(cfg.user_by_index(999).is_none());
    }

    #[test]
    fn app_config_user_by_index_returns_correct_user() {
        let json = r#"{
            "token_expiry_seconds": 3600,
            "secret": "s",
            "users": [
                {"username": "alice", "password": "h1"},
                {"username": "bob", "password": "h2"}
            ],
            "log": {}
        }"#;
        let cfg: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.user_by_index(0).unwrap().username, "alice");
        assert_eq!(cfg.user_by_index(1).unwrap().username, "bob");
    }
}
