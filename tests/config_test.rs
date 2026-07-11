use acme_dns_rust::config::Config;

fn cleanup_test_db() {
    let _ = std::fs::remove_file("test_db.db");
    let _ = std::fs::remove_file("test_db.db-shm");
    let _ = std::fs::remove_file("test_db.db-wal");
}

#[test]
fn test_config_load_valid() {
    cleanup_test_db();
    let config = Config::load("tests/fixtures/test_config.toml")
        .expect("Should load test config");
    assert_eq!(config.general.domain, "auth.test.local");
    assert_eq!(config.general.nsname, "ns1.auth.test.local");
    assert_eq!(config.database.engine, "sqlite");
    assert_eq!(config.api.port, "8080");
    assert_eq!(config.api.tls, "none");
    assert!(!config.api.hsts_enabled);
    assert!(!config.api.disable_registration);
    assert_eq!(config.logconfig.loglevel, "error");
}

#[test]
fn test_config_load_missing_file() {
    let result = Config::load("nonexistent_path/config.toml");
    assert!(result.is_err(), "Should fail to load missing config");
}

#[test]
fn test_config_defaults() {
    let config = Config::load("tests/fixtures/test_config.toml").unwrap();
    assert!(config.api.trusted_proxies.is_empty());
    assert_eq!(config.api.register_rate_limit_per_min, 0);
}
