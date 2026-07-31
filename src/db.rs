/// QUAL-01: Unified database layer using enum-based pool for Sqlite and Postgres
/// ARQ-03: Schema managed via embedded migrations baked directly into the binary
use sqlx_sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx_postgres::{PgPool, PgPoolOptions};
use sqlx_core::{
    row::Row,
    error::Error as SqlxError,
    query::query,
    query_scalar::query_scalar,
};
use uuid::Uuid;
use crate::config::Config;
use tracing::warn;

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
                let conn = &config.database.connection;
                let connection_str = if conn == ":memory:" {
                    "sqlite::memory:?cache=shared".to_string()
                } else if conn.starts_with("sqlite://") || conn.starts_with("sqlite:") {
                    conn.clone()
                } else {
                    format!("sqlite://{}", conn)
                };

                let pool = SqlitePoolOptions::new()
                    .max_connections(5)
                    .connect(&connection_str)
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
                match self {
                    Self::Sqlite(p) => { let _ = query(stmt).execute(p).await; }
                    Self::Postgres(p) => { let _ = query(stmt).execute(p).await; }
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
                Ok(row.map(|r| {
                    let u: String = r.get("Username");
                    let allow_from_raw: String = r.get("AllowFrom");
                    let created_at: String = r.try_get("CreatedAt").unwrap_or_default();
                    let has_updated: i64 = r.try_get("HasUpdated").unwrap_or(0);
                    Record {
                        username: u.clone(),
                        password_hash: r.get("Password"),
                        subdomain: r.get("Subdomain"),
                        allow_from: Self::parse_allow_from(&allow_from_raw, &u),
                        created_at,
                        has_updated: has_updated != 0,
                    }
                }))
            }
            Self::Postgres(p) => {
                let row = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records WHERE Username = $1")
                    .bind(username)
                    .fetch_optional(p)
                    .await?;
                Ok(row.map(|r| {
                    let u: String = r.get("Username");
                    let allow_from_raw: String = r.get("AllowFrom");
                    let created_at: String = r.try_get("CreatedAt").unwrap_or_default();
                    let has_updated: i64 = r.try_get("HasUpdated").unwrap_or(0);
                    Record {
                        username: u.clone(),
                        password_hash: r.get("Password"),
                        subdomain: r.get("Subdomain"),
                        allow_from: Self::parse_allow_from(&allow_from_raw, &u),
                        created_at,
                        has_updated: has_updated != 0,
                    }
                }))
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
                Ok(row.map(|r| {
                    let u: String = r.get("Username");
                    let allow_from_raw: String = r.get("AllowFrom");
                    let created_at: String = r.try_get("CreatedAt").unwrap_or_default();
                    let has_updated: i64 = r.try_get("HasUpdated").unwrap_or(0);
                    Record {
                        username: u.clone(),
                        password_hash: r.get("Password"),
                        subdomain: r.get("Subdomain"),
                        allow_from: Self::parse_allow_from(&allow_from_raw, &u),
                        created_at,
                        has_updated: has_updated != 0,
                    }
                }))
            }
            Self::Postgres(p) => {
                let row = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records WHERE Subdomain = $1")
                    .bind(subdomain)
                    .fetch_optional(p)
                    .await?;
                Ok(row.map(|r| {
                    let u: String = r.get("Username");
                    let allow_from_raw: String = r.get("AllowFrom");
                    let created_at: String = r.try_get("CreatedAt").unwrap_or_default();
                    let has_updated: i64 = r.try_get("HasUpdated").unwrap_or(0);
                    Record {
                        username: u.clone(),
                        password_hash: r.get("Password"),
                        subdomain: r.get("Subdomain"),
                        allow_from: Self::parse_allow_from(&allow_from_raw, &u),
                        created_at,
                        has_updated: has_updated != 0,
                    }
                }))
            }
        }
    }

    pub async fn list_users(&self) -> Result<Vec<Record>, SqlxError> {
        match self {
            Self::Sqlite(p) => {
                let rows = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records")
                    .fetch_all(p)
                    .await?;
                Ok(rows.into_iter().map(|r| {
                    let u: String = r.get("Username");
                    let allow_from_raw: String = r.get("AllowFrom");
                    let created_at: String = r.try_get("CreatedAt").unwrap_or_default();
                    let has_updated: i64 = r.try_get("HasUpdated").unwrap_or(0);
                    Record {
                        username: u.clone(),
                        password_hash: r.get("Password"),
                        subdomain: r.get("Subdomain"),
                        allow_from: Self::parse_allow_from(&allow_from_raw, &u),
                        created_at,
                        has_updated: has_updated != 0,
                    }
                }).collect())
            }
            Self::Postgres(p) => {
                let rows = query("SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records")
                    .fetch_all(p)
                    .await?;
                Ok(rows.into_iter().map(|r| {
                    let u: String = r.get("Username");
                    let allow_from_raw: String = r.get("AllowFrom");
                    let created_at: String = r.try_get("CreatedAt").unwrap_or_default();
                    let has_updated: i64 = r.try_get("HasUpdated").unwrap_or(0);
                    Record {
                        username: u.clone(),
                        password_hash: r.get("Password"),
                        subdomain: r.get("Subdomain"),
                        allow_from: Self::parse_allow_from(&allow_from_raw, &u),
                        created_at,
                        has_updated: has_updated != 0,
                    }
                }).collect())
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
                let count: i64 = query_scalar("SELECT COUNT(*) FROM txt WHERE Subdomain = ?").bind(subdomain).fetch_one(p).await?;
                if count >= 2 {
                    query("DELETE FROM txt WHERE Subdomain = ? AND rowid = (SELECT MIN(rowid) FROM txt WHERE Subdomain = ?)")
                        .bind(subdomain).bind(subdomain).execute(p).await?;
                }
                query("INSERT INTO txt (Subdomain, Value, LastUpdate) VALUES (?, ?, CURRENT_TIMESTAMP)").bind(subdomain).bind(txt).execute(p).await?;
                query("UPDATE records SET HasUpdated = 1 WHERE Subdomain = ?").bind(subdomain).execute(p).await?;
            }
            Self::Postgres(p) => {
                let count: i64 = query_scalar("SELECT COUNT(*) FROM txt WHERE Subdomain = $1").bind(subdomain).fetch_one(p).await?;
                if count >= 2 {
                    query("DELETE FROM txt WHERE Subdomain = $1 AND ctid IN (SELECT ctid FROM txt WHERE Subdomain = $1 ORDER BY LastUpdate ASC LIMIT 1)")
                        .bind(subdomain).execute(p).await?;
                }
                query("INSERT INTO txt (Subdomain, Value, LastUpdate) VALUES ($1, $2, CURRENT_TIMESTAMP)").bind(subdomain).bind(txt).execute(p).await?;
                query("UPDATE records SET HasUpdated = 1 WHERE Subdomain = $1").bind(subdomain).execute(p).await?;
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
