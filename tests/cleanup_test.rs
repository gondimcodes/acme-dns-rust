use acme_dns_rust::{config::Config, db::DbPool};

fn cleanup_test_db(db_path: &str) {
    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(format!("{}-shm", db_path));
    let _ = std::fs::remove_file(format!("{}-wal", db_path));
}

#[tokio::test]
async fn test_cleanup_orphan_records() {
    let db_path_str = "/home/gondim/projetos/acme-dns-rust/target/test_db.db".to_string();

    cleanup_test_db(&db_path_str);
    // Create an empty file so SQLite can open it
    let _ = std::fs::File::create(&db_path_str);

    let mut config = Config::load("tests/fixtures/test_config.toml")
        .expect("Should load test config");
    
    // Override connection string to use the absolute target path
    config.database.connection = db_path_str.clone();

    let db = DbPool::new(&config).await.expect("Should init DB");

    // 1. Register a new user
    let (username, _password, _subdomain) = db.register(vec![]).await.expect("Should register");

    // Check user exists
    let user = db.get_user_by_username(&username.to_string()).await.unwrap();
    assert!(user.is_some());

    // 2. Perform cleanup with -1 seconds timeout (simulating immediate timeout)
    let cleaned = db.cleanup_orphan_records(-1).await.expect("Should clean");
    assert_eq!(cleaned, 1);

    // Verify user was deleted (because it had no TXT records)
    let user = db.get_user_by_username(&username.to_string()).await.unwrap();
    assert!(user.is_none());

    // 3. Register another user but add a TXT record for it
    let (username2, _password, subdomain2) = db.register(vec![]).await.unwrap();
    db.update_txt(&subdomain2, "dGhpcyBpcyBhIHZhbGlkIHRva2VuIHRlc3QAcmeToken_").await.unwrap();

    // Perform cleanup again with -1 seconds timeout
    let cleaned = db.cleanup_orphan_records(-1).await.unwrap();
    // Should NOT delete because it has a TXT record
    assert_eq!(cleaned, 0);

    let user2 = db.get_user_by_username(&username2.to_string()).await.unwrap();
    assert!(user2.is_some());
    cleanup_test_db(&db_path_str);
}
