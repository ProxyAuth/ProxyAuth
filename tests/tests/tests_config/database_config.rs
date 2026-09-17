#[cfg(test)]
mod tests {
    use proxyauth::config::config::DatabaseConfig;

    #[test]
    fn database_config_from_json() {
        let json = r#"{
            "type": "postgres",
            "host": "localhost",
            "port": 5432,
            "db_name": "proxyauth",
            "user": "admin",
            "password": "secret"
        }"#;
        let cfg: DatabaseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.db_type, "postgres");
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, Some(5432));
        assert_eq!(cfg.db_name, "proxyauth");
        assert_eq!(cfg.user, "admin");
        assert_eq!(cfg.password, "secret");
    }

    #[test]
    fn database_config_effective_port_postgres_default() {
        let json = r#"{
            "type": "postgres",
            "host": "localhost",
            "db_name": "test"
        }"#;
        let cfg: DatabaseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_port(), 5432);
    }

    #[test]
    fn database_config_effective_port_mysql_default() {
        let json = r#"{
            "type": "mysql",
            "host": "localhost",
            "db_name": "test"
        }"#;
        let cfg: DatabaseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_port(), 3306);
    }

    #[test]
    fn database_config_effective_port_mariadb_default() {
        let json = r#"{
            "type": "mariadb",
            "host": "localhost",
            "db_name": "test"
        }"#;
        let cfg: DatabaseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_port(), 3306);
    }

    #[test]
    fn database_config_effective_port_explicit_overrides() {
        let json = r#"{
            "type": "postgres",
            "host": "localhost",
            "port": 15432,
            "db_name": "test"
        }"#;
        let cfg: DatabaseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.effective_port(), 15432);
    }

    #[test]
    fn database_config_defaults() {
        let json = r#"{
            "type": "postgres",
            "host": "localhost",
            "db_name": "test"
        }"#;
        let cfg: DatabaseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.connect_timeout_secs, 5);
        assert_eq!(cfg.refresh_interval_secs, 30);
        assert_eq!(cfg.incremental_window_secs, 300);
        assert_eq!(cfg.full_refresh_interval_secs, 300);
        assert_eq!(cfg.deleted_retention_secs, 86400);
        assert_eq!(cfg.purge_interval_secs, 3600);
        assert!(cfg.user.is_empty());
        assert!(cfg.password.is_empty());
    }

    #[test]
    fn database_config_custom_values() {
        let json = r#"{
            "type": "mysql",
            "host": "db.example.com",
            "port": 3307,
            "db_name": "proxyauth",
            "user": "pa_user",
            "password": "pa_pass",
            "connect_timeout_secs": 10,
            "refresh_interval_secs": 60,
            "incremental_window_secs": 600,
            "full_refresh_interval_secs": 600,
            "deleted_retention_secs": 172800,
            "purge_interval_secs": 7200
        }"#;
        let cfg: DatabaseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.db_type, "mysql");
        assert_eq!(cfg.host, "db.example.com");
        assert_eq!(cfg.port, Some(3307));
        assert_eq!(cfg.effective_port(), 3307);
        assert_eq!(cfg.connect_timeout_secs, 10);
        assert_eq!(cfg.refresh_interval_secs, 60);
        assert_eq!(cfg.incremental_window_secs, 600);
        assert_eq!(cfg.full_refresh_interval_secs, 600);
        assert_eq!(cfg.deleted_retention_secs, 172800);
        assert_eq!(cfg.purge_interval_secs, 7200);
    }
}
