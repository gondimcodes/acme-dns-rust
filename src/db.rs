/// QUAL-01: Unified database layer using sqlx::AnyPool
/// ARQ-03: Schema managed via sqlx migrations (migrations/ directory)
use sqlx::{AnyPool, any::AnyPoolOptions, Row};
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

pub struct DbPool {
    pool: AnyPool,
}

impl DbPool {
    pub async fn new(config: &Config) -> Result<Self, sqlx::Error> {
        // Register both drivers so AnyPool can pick the correct one from the URL
        sqlx::any::install_default_drivers();

        let connection_str = match config.database.engine.as_str() {
            "postgres" => config.database.connection.clone(),
            _ => {
                // SQLite: sqlx AnyPool expects sqlite:// scheme
                let conn = &config.database.connection;
                if conn == ":memory:" {
                    "sqlite::memory:?cache=shared".to_string()
                } else if conn.starts_with("sqlite://") || conn.starts_with("sqlite:") {
                    conn.clone()
                } else {
                    format!("sqlite://{}", conn)
                }
            }
        };

        let pool = AnyPoolOptions::new()
            .max_connections(5)
            .connect(&connection_str)
            .await?;

        // ARQ-03: run pending migrations automatically at startup
        sqlx::migrate!("./migrations").run(&pool).await
            .map_err(|e| sqlx::Error::Configuration(format!("Migration failed: {}", e).into()))?;

        Ok(Self { pool })
    }

    // ─── Schema helpers ────────────────────────────────────────────────────────

    fn parse_allow_from(raw: &str, context: &str) -> Vec<String> {
        serde_json::from_str(raw).unwrap_or_else(|e| {
            warn!("AllowFrom JSON parse failed for '{}': {}", context, e);
            vec![]
        })
    }

    // ─── Admin ─────────────────────────────────────────────────────────────────

    pub async fn get_admin_password_hash(&self) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query("SELECT Password FROM admin LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| {
            let pwd: String = r.get("Password");
            if pwd.is_empty() { None } else { Some(pwd) }
        }))
    }

    pub async fn set_admin_password(&self, hash: &str) -> Result<(), sqlx::Error> {
        // Clear old entries and insert the new single admin row (safe on all DBs without ID key)
        sqlx::query("DELETE FROM admin")
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT INTO admin (Password) VALUES (?)")
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Records ───────────────────────────────────────────────────────────────

    pub async fn register(
        &self,
        allow_from: Vec<String>,
    ) -> Result<(uuid::Uuid, String, String), sqlx::Error> {
        let username = Uuid::new_v4();
        let subdomain = Uuid::new_v4().to_string();
        let password = crate::auth::generate_password(40);
        let password_hash = bcrypt::hash(&password, 10)
            .map_err(|e| sqlx::Error::Configuration(e.to_string().into()))?;
        let allow_from_json = serde_json::to_string(&allow_from)
            .map_err(|e| sqlx::Error::Configuration(e.to_string().into()))?;

        let now_str = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query(
            "INSERT INTO records (Username, Password, Subdomain, AllowFrom, CreatedAt) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(username.to_string())
        .bind(&password_hash)
        .bind(&subdomain)
        .bind(&allow_from_json)
        .bind(&now_str)
        .execute(&self.pool)
        .await?;

        Ok((username, password, subdomain))
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<Record>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records WHERE Username = ?"
        )
        .bind(username)
        .fetch_optional(&self.pool)
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

    pub async fn get_user_by_subdomain(&self, subdomain: &str) -> Result<Option<Record>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records WHERE Subdomain = ?"
        )
        .bind(subdomain)
        .fetch_optional(&self.pool)
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

    pub async fn list_users(&self) -> Result<Vec<Record>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT Username, Password, Subdomain, AllowFrom, CAST(CreatedAt AS TEXT) as CreatedAt, HasUpdated FROM records"
        )
        .fetch_all(&self.pool)
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

    pub async fn delete_user(&self, username: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM records WHERE Username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn cleanup_orphan_records(&self, timeout_seconds: i64) -> Result<u64, sqlx::Error> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(timeout_seconds);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        let result = sqlx::query(
            "DELETE FROM records WHERE CreatedAt < ? AND HasUpdated = 0"
        )
        .bind(cutoff_str)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ─── TXT records ───────────────────────────────────────────────────────────

    pub async fn update_txt(&self, subdomain: &str, txt: &str) -> Result<(), sqlx::Error> {
        // Rotate: keep at most 2 TXT records per subdomain (for dual-stack challenges)
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM txt WHERE Subdomain = ?"
        )
        .bind(subdomain)
        .fetch_one(&self.pool)
        .await?;

        if count >= 2 {
            // Delete the oldest record
            sqlx::query(
                "DELETE FROM txt WHERE Subdomain = ? AND rowid = (SELECT MIN(rowid) FROM txt WHERE Subdomain = ?)"
            )
            .bind(subdomain)
            .bind(subdomain)
            .execute(&self.pool)
            .await?;
        }

        sqlx::query(
            "INSERT INTO txt (Subdomain, Value, LastUpdate) VALUES (?, ?, CURRENT_TIMESTAMP)"
        )
        .bind(subdomain)
        .bind(txt)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "UPDATE records SET HasUpdated = 1 WHERE Subdomain = ?"
        )
        .bind(subdomain)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_txt_for_domain(&self, subdomain: &str) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT Value FROM txt WHERE Subdomain = ? ORDER BY LastUpdate DESC LIMIT 2"
        )
        .bind(subdomain)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.get::<String, _>("Value")).collect())
    }
}
