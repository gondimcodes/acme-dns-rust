/// QUAL-01: Unified database layer using enum-based pool for Sqlite and Postgres
/// ARQ-03: Schema managed via embedded migrations baked directly into the binary
use sqlx_sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx_postgres::{PgPool, PgPoolOptions};
use sqlx_core::{
    row::Row,
    error::Error as SqlxError,
    query::query,
};
use uuid::Uuid;
use crate::config::Config;
use tracing::{warn, error};

/// QUAL-WARN-1 fix: Macro para mapear uma row do BD para um Record.
/// Elimina 6 blocos idênticos nos braços Sqlite/Postgres de cada função.
/// Funciona em contexto de `impl DbPool` onde `Self::parse_allow_from` é acessível.
macro_rules! map_record_row {
    ($r:expr) => {{
        let username: String = $r.get("Username");
        let allow_from_raw: String = $r.get("AllowFrom");
        let created_at: String = $r.try_get("CreatedAt").unwrap_or_default();
        let has_updated: i64 = $r.try_get("HasUpdated").unwrap_or(0);
        Record {
            allow_from: Self::parse_allow_from(&allow_from_raw, &username),
            password_hash: $r.get("Password"),
            subdomain: $r.get("Subdomain"),
            created_at,
            has_updated: has_updated != 0,
            username,
        }
    }};
}

#[derive(Debug, Clone)]
pub struct Record {
    pub username: String,
    pub password_hash: String,
    pub subdomain: String,
    pub allow_from: Vec<String>,
    pub created_at: String,
    pub has_updated: bool,
}

#[derive(Clone)]
pub enum DbPool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl DbPool {
    pub async fn new(config: &Config) -> Result<Self, SqlxError> {
        let pool = match config.database.engine.as_str() {
            "postgres" => {
                let pool = PgPoolOptions::new()
                    .max_connections(5)
                    .connect(&config.database.connection)
                    .await?;
                Self::Postgres(pool)
            }
            _ => {
                use sqlx_sqlite::{SqliteConnectOptions, SqliteJournalMode};
                use std::str::FromStr;

                let conn = &config.database.connection;
                let connection_str = if conn == ":memory:" {
                    "sqlite::memory:?cache=shared".to_string()
                } else if conn.starts_with("sqlite://") || conn.starts_with("sqlite:") {
                    conn.clone()
                } else {
                    format!("sqlite://{}", conn)
                };

                let connect_opts = SqliteConnectOptions::from_str(&connection_str)?
                    .journal_mode(SqliteJournalMode::Wal)
                    .busy_timeout(std::time::Duration::from_secs(10));

                let pool = SqlitePoolOptions::new()
                    .max_connections(5)
                    .connect_with(connect_opts)
                    .await?;
                Self::Sqlite(pool)
            }
        };

        pool.run_embedded_migrations().await?;
        Ok(pool)
    }

    async fn execute_sql(&self, sql: &str) -> Result<(), SqlxError> {
        let cleaned: String = sql
            .lines()
            .filter(|line| !line.trim().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");

        for stmt in cleaned.split(';') {
            let stmt = stmt.trim();
            if !stmt.is_empty() {
                // QUAL-WARN-2 fix: loga erros inesperados em vez de silenciar tudo.
                // Erros de "já existe" (idempotência) são ignorados intencionalmente.
                let result = match self {
                    Self::Sqlite(p) => query(stmt).execute(p).await.map(|_| ()),
                    Self::Postgres(p) => query(stmt).execute(p).await.map(|_| ()),
                };
                if let Err(e) = result {
                    let msg = e.to_string();
                    let is_idempotent = msg.contains("already exists")
                        || msg.contains("duplicate column")
                        || msg.contains("table already exists");
                    if !is_idempotent {
                        error!("Unexpected SQL migration error: {} | stmt: {}", e, &stmt[..stmt.len().min(80)]);
                    }
                }
            }
        }
        Ok(())
    }

    async fn run_embedded_migrations(&self) -> Result<(), SqlxError> {
        const M1: &str = include_str!("../migrations/20240101000000_initial_schema.sql");
        const M2: &str = include_str!("../migrations/20260711000000_add_created_at_to_records.sql");
        const M3: &str = include_str!("../migrations/20260715000000_add_has_updated_to_records.sql");

        self.execute_sql(M1).await?;
        self.execute_sql(M2).await?;
        self.execute_sql(M3).await?;
        Ok(())
    }

    // ─── Schema helpers ────────────────────────────────────────────────────────

    fn parse_allow_from(raw: &str, context: &str) -> Vec<String> {
        serde_json::from_str(raw).unwrap_or_else(|e| {
            warn!("AllowFrom JSON parse failed for '{}': {}", context, e);
            vec![]
        })
    }

    // ─── Admin ─────────────────────────────────────────────────────────────────

    pub async fn get_admin_password_hash(&self) -> Result<Option<String>, SqlxError> {
        match self {
            Self::Sqlite(p) => {
                let row = query("SELECT Password FROM admin LIMIT 1").fetch_optional(p).await?;
                Ok(row.and_then(|r| {
                    let pwd: String = r.get("Password");
                    if pwd.is_empty() { None } else { Some(pwd) }
                }))
            }
            Self::Postgres(p) => {
                let row = query("SELECT Password FROM admin LIMIT 1").fetch_optional(p).await?;
                Ok(row.and_then(|r| {
                    let pwd: String = r.get("Password");
                    if pwd.is_empty() { None } else { Some(pwd) }
                }))
            }
        }
    }

    pub async fn set_admin_password(&self, hash: &str) -> Result<(), SqlxError> {
        match self {
            Self::Sqlite(p) => {
                query("DELETE FROM admin").execute(p).await?;
                query("INSERT INTO admin (Password) VALUES (?)").bind(hash).execute(p).await?;
            }
            Self::Postgres(p) => {
                query("DELETE FROM admin").execute(p).await?;
                query("INSERT INTO admin (Password) VALUES ($1)").bind(hash).execute(p).await?;
            }
        }
        Ok(())
    }

    // ─── Records ───────────────────────────────────────────────────────────────

    pub async fn register(
        &self,
        allow_from: Vec<String>,
    ) -> Result<(uuid::Uuid, String, String), SqlxError> {
        let username = Uuid::new_v4();
        let subdomain = Uuid::new_v4().to_string();
        let password = crate::auth::generate_password(40);
        let password_hash = bcrypt::hash(&password, 10)
            .map_err(|e| SqlxError::Configuration(e.to_string().into()))?;
        let allow_from_json = serde_json::to_string(&allow_from)
            .map_err(|e| SqlxError::Configuration(e.to_string().into()))?;

        let now_str = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        match self {
            Self::Sqlite(p) => {
                query("INSERT INTO records (Username, Password, Subdomain, AllowFrom, CreatedAt) VALUES (?, ?, ?, ?, ?)")
                    .bind(username.to_string())
                    .bind(&password_hash)
                    .bind(&subdomain)
                    .bind(&allow_from_json)
                    .bind(&now_str)
                    .execute(p)
                    .await?;
            }
            Self::Postgres(p) => {
                query("INSERT INTO records (Username, Password, Subdomain, AllowFrom, CreatedAt) VALUES ($1, $2, $3, $4, $5)")
                    .bind(username.to_string())
                    .bind(&password_hash)
                    .bind(&subdomain)
                    .bind(&allow_from_json)
                    .bind(&now_str)
                    .execute(p)
                    .await?;
            }
        }

        Ok((username, password, subdomain))
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<Record>, SqlxError> {
        match self {
            Self::Sqlite(p) => {
                let row = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records WHERE Username = ?")
                    .bind(username)
                    .fetch_optional(p)
                    .await?;
                Ok(row.map(|r| map_record_row!(r)))
            }
            Self::Postgres(p) => {
                let row = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records WHERE Username = $1")
                    .bind(username)
                    .fetch_optional(p)
                    .await?;
                Ok(row.map(|r| map_record_row!(r)))
            }
        }
    }

    pub async fn get_user_by_subdomain(&self, subdomain: &str) -> Result<Option<Record>, SqlxError> {
        match self {
            Self::Sqlite(p) => {
                let row = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records WHERE Subdomain = ?")
                    .bind(subdomain)
                    .fetch_optional(p)
                    .await?;
                Ok(row.map(|r| map_record_row!(r)))
            }
            Self::Postgres(p) => {
                let row = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records WHERE Subdomain = $1")
                    .bind(subdomain)
                    .fetch_optional(p)
                    .await?;
                Ok(row.map(|r| map_record_row!(r)))
            }
        }
    }

    pub async fn list_users(&self) -> Result<Vec<Record>, SqlxError> {
        match self {
            Self::Sqlite(p) => {
                let rows = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records")
                    .fetch_all(p)
                    .await?;
                Ok(rows.into_iter().map(|r| map_record_row!(r)).collect())
            }
            Self::Postgres(p) => {
                let rows = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records")
                    .fetch_all(p)
                    .await?;
                Ok(rows.into_iter().map(|r| map_record_row!(r)).collect())
            }
        }
    }

    pub async fn delete_user(&self, username: &str) -> Result<bool, SqlxError> {
        let rows_affected = match self {
            Self::Sqlite(p) => query("DELETE FROM records WHERE Username = ?").bind(username).execute(p).await?.rows_affected(),
            Self::Postgres(p) => query("DELETE FROM records WHERE Username = $1").bind(username).execute(p).await?.rows_affected(),
        };
        Ok(rows_affected > 0)
    }

    pub async fn cleanup_orphan_records(&self, timeout_seconds: i64) -> Result<u64, SqlxError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(timeout_seconds);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        let rows_affected = match self {
            Self::Sqlite(p) => query("DELETE FROM records WHERE CreatedAt < ? AND HasUpdated = 0").bind(&cutoff_str).execute(p).await?.rows_affected(),
            Self::Postgres(p) => query("DELETE FROM records WHERE CreatedAt < $1 AND HasUpdated = 0").bind(&cutoff_str).execute(p).await?.rows_affected(),
        };

        Ok(rows_affected)
    }

    // ─── TXT records ───────────────────────────────────────────────────────────

    pub async fn update_txt(&self, subdomain: &str, txt: &str) -> Result<(), SqlxError> {
        match self {
            Self::Sqlite(p) => {
                query("INSERT INTO txt (Subdomain, Value, LastUpdate) VALUES (?, ?, CURRENT_TIMESTAMP)")
                    .bind(subdomain)
                    .bind(txt)
                    .execute(p)
                    .await?;
                query("DELETE FROM txt WHERE Subdomain = ? AND rowid NOT IN (SELECT rowid FROM txt WHERE Subdomain = ? ORDER BY LastUpdate DESC, rowid DESC LIMIT 2)")
                    .bind(subdomain)
                    .bind(subdomain)
                    .execute(p)
                    .await?;
                query("UPDATE records SET HasUpdated = 1 WHERE Subdomain = ?")
                    .bind(subdomain)
                    .execute(p)
                    .await?;
            }
            Self::Postgres(p) => {
                query("INSERT INTO txt (Subdomain, Value, LastUpdate) VALUES ($1, $2, CURRENT_TIMESTAMP)")
                    .bind(subdomain)
                    .bind(txt)
                    .execute(p)
                    .await?;
                query("DELETE FROM txt WHERE Subdomain = $1 AND ctid NOT IN (SELECT ctid FROM txt WHERE Subdomain = $1 ORDER BY LastUpdate DESC, ctid DESC LIMIT 2)")
                    .bind(subdomain)
                    .execute(p)
                    .await?;
                query("UPDATE records SET HasUpdated = 1 WHERE Subdomain = $1")
                    .bind(subdomain)
                    .execute(p)
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn get_txt_for_domain(&self, subdomain: &str) -> Result<Vec<String>, SqlxError> {
        match self {
            Self::Sqlite(p) => {
                let rows = query("SELECT Value FROM txt WHERE Subdomain = ? ORDER BY LastUpdate DESC LIMIT 2").bind(subdomain).fetch_all(p).await?;
                Ok(rows.into_iter().map(|r| r.get::<String, _>("Value")).collect())
            }
            Self::Postgres(p) => {
                let rows = query("SELECT Value FROM txt WHERE Subdomain = $1 ORDER BY LastUpdate DESC LIMIT 2").bind(subdomain).fetch_all(p).await?;
                Ok(rows.into_iter().map(|r| r.get::<String, _>("Value")).collect())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, General, Database, Api, LogConfig};

    fn make_sqlite_config() -> Config {
        Config {
            general: General {
                listen: "0.0.0.0:53".to_string(),
                proto: "udp".to_string(),
                domain: "auth.example.com".to_string(),
                nsname: "ns1.example.com".to_string(),
                nsadmin: "admin.example.com".to_string(),
                debug: false,
                static_records: vec![],
            },
            database: Database {
                engine: "sqlite".to_string(),
                connection: ":memory:".to_string(),
            },
            api: Api {
                api_domain: None,
                ip: "127.0.0.1".to_string(),
                disable_registration: false,
                autocert_port: None,
                port: "443".to_string(),
                tls: "none".to_string(),
                tls_cert_privkey: None,
                tls_cert_fullchain: None,
                acme_cache_dir: None,
                notification_email: None,
                corsorigins: vec!["*".to_string()],
                use_header: false,
                header_name: "X-Forwarded-For".to_string(),
                hsts_enabled: false,
                hsts_max_age: None,
                hsts_include_subdomains: false,
                hsts_preload: false,
                trusted_proxies: vec![],
                register_rate_limit_per_min: 0,
                cleanup_orphans: false,
                orphan_timeout_mins: 30,
            },
            logconfig: LogConfig { loglevel: "info".to_string() },
        }
    }

    #[tokio::test]
    async fn test_register_and_get_user() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        let (username, password, subdomain) = db.register(vec![]).await.expect("register failed");
        let record = db.get_user_by_username(&username.to_string()).await
            .expect("query failed")
            .expect("user not found");
        assert_eq!(record.username, username.to_string());
        assert_eq!(record.subdomain, subdomain);
        assert!(!password.is_empty());
        assert!(!record.password_hash.is_empty());
        assert_eq!(record.allow_from, Vec::<String>::new());
        assert!(!record.has_updated);
    }

    #[tokio::test]
    async fn test_register_with_allowfrom() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        let cidrs = vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()];
        let (username, _, _) = db.register(cidrs.clone()).await.expect("register failed");
        let record = db.get_user_by_username(&username.to_string()).await
            .expect("query failed")
            .expect("user not found");
        assert_eq!(record.allow_from, cidrs);
    }

    #[tokio::test]
    async fn test_update_txt_and_get() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        let (_, _, subdomain) = db.register(vec![]).await.expect("register failed");
        db.update_txt(&subdomain, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1").await.expect("update failed");
        let values = db.get_txt_for_domain(&subdomain).await.expect("get_txt failed");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1");
    }

    #[tokio::test]
    async fn test_update_txt_keeps_max_2() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        let (_, _, subdomain) = db.register(vec![]).await.expect("register failed");
        db.update_txt(&subdomain, "TOKEN_1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").await.unwrap();
        db.update_txt(&subdomain, "TOKEN_2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").await.unwrap();
        db.update_txt(&subdomain, "TOKEN_3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").await.unwrap();
        let values = db.get_txt_for_domain(&subdomain).await.expect("get_txt failed");
        assert_eq!(values.len(), 2, "deve manter no máximo 2 TXT records");
        assert!(values.iter().all(|v| v.starts_with("TOKEN_")));
        assert!(!values.iter().any(|v| v.contains("TOKEN_1")), "TOKEN_1 deve ter sido removido");
    }

    #[tokio::test]
    async fn test_delete_user() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        let (username, _, _) = db.register(vec![]).await.expect("register failed");
        let deleted = db.delete_user(&username.to_string()).await.expect("delete failed");
        assert!(deleted);
        let record = db.get_user_by_username(&username.to_string()).await.expect("query failed");
        assert!(record.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_user() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        let deleted = db.delete_user("nonexistent-user").await.expect("delete failed");
        assert!(!deleted);
    }

    #[tokio::test]
    async fn test_admin_password() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        let hash = bcrypt::hash("test_password_123", 4).unwrap();
        db.set_admin_password(&hash).await.expect("set_admin failed");
        let stored = db.get_admin_password_hash().await.expect("get failed").expect("no hash");
        assert_eq!(stored, hash);
    }

    #[tokio::test]
    async fn test_list_users() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        db.register(vec![]).await.unwrap();
        db.register(vec![]).await.unwrap();
        let users = db.list_users().await.expect("list failed");
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn test_get_user_by_subdomain() {
        let config = make_sqlite_config();
        let db = DbPool::new(&config).await.expect("DB init failed");
        let (_, _, subdomain) = db.register(vec![]).await.expect("register failed");
        let record = db.get_user_by_subdomain(&subdomain).await
            .expect("query failed")
            .expect("not found");
        assert_eq!(record.subdomain, subdomain);
    }

    #[tokio::test]
    async fn test_update_txt_concurrent_keeps_max_2() {
        let config = make_sqlite_config();
        let db = std::sync::Arc::new(DbPool::new(&config).await.expect("DB init failed"));
        let (_, _, subdomain) = db.register(vec![]).await.expect("register failed");

        // Dispara 20 updates concorrentes simultâneos
        let mut handles = Vec::new();
        for i in 0..20 {
            let db_clone = std::sync::Arc::clone(&db);
            let sub_clone = subdomain.clone();
            handles.push(tokio::spawn(async move {
                let token = format!("CONCURRENT_TOKEN_{:02}_AAAAAAAAAAAAAAAAAAAAAAAAA", i);
                db_clone.update_txt(&sub_clone, &token).await
            }));
        }

        for h in handles {
            let res = h.await.unwrap();
            assert!(res.is_ok(), "Update concorrente falhou: {:?}", res);
        }

        let values = db.get_txt_for_domain(&subdomain).await.expect("get_txt failed");
        assert_eq!(values.len(), 2, "Mesmo com 20 updates concorrentes, deve manter estritamente 2 TXTs");
    }
}
