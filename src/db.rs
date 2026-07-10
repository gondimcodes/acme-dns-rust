use sqlx::{Pool, Sqlite, Postgres, sqlite::SqlitePoolOptions, postgres::PgPoolOptions};
use uuid::Uuid;
use crate::config::Config;

#[derive(Debug)]
pub enum DbPool {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Record {
    pub username: String,
    pub password_hash: String,
    pub subdomain: String,
    pub allow_from: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxtRecord {
    pub subdomain: String,
    pub value: String,
    pub last_update: i64,
}

impl DbPool {
    pub async fn new(config: &Config) -> Result<Self, sqlx::Error> {
        let pool = match config.database.engine.as_str() {
            "sqlite" => {
                let conn_str = if config.database.connection.starts_with("sqlite:") {
                    config.database.connection.clone()
                } else {
                    format!("sqlite://{}", config.database.connection)
                };
                use std::str::FromStr;
                let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&conn_str)?
                    .create_if_missing(true);

                let pool = SqlitePoolOptions::new()
                    .max_connections(1) // Keep max_connections=1 for SQLite concurrency control
                    .connect_with(opts)
                    .await?;
                
                // Initialize schemas
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS acmedns(Name TEXT, Value TEXT);"
                ).execute(&pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS records(
                        Username TEXT UNIQUE NOT NULL PRIMARY KEY,
                        Password TEXT UNIQUE NOT NULL,
                        Subdomain TEXT UNIQUE NOT NULL,
                        AllowFrom TEXT
                    );"
                ).execute(&pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS txt(
                        Subdomain TEXT NOT NULL,
                        Value TEXT NOT NULL DEFAULT '',
                        LastUpdate INT
                    );"
                ).execute(&pool).await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS idx_txt_subdomain ON txt (Subdomain);"
                ).execute(&pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS admin(Password TEXT NOT NULL);"
                ).execute(&pool).await?;
                
                // Seed db_version
                let row: Option<(String,)> = sqlx::query_as("SELECT Value FROM acmedns WHERE Name = 'db_version'")
                    .fetch_optional(&pool).await?;
                if row.is_none() {
                    sqlx::query("INSERT INTO acmedns (Name, Value) VALUES ('db_version', '1')")
                        .execute(&pool).await?;
                }

                DbPool::Sqlite(pool)
            }
            "postgres" => {
                let pool = PgPoolOptions::new()
                    .max_connections(10)
                    .connect(&config.database.connection)
                    .await?;
                
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS acmedns(Name TEXT, Value TEXT);"
                ).execute(&pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS records(
                        Username TEXT UNIQUE NOT NULL PRIMARY KEY,
                        Password TEXT UNIQUE NOT NULL,
                        Subdomain TEXT UNIQUE NOT NULL,
                        AllowFrom TEXT
                    );"
                ).execute(&pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS txt(
                        rowid SERIAL PRIMARY KEY,
                        Subdomain TEXT NOT NULL,
                        Value TEXT NOT NULL DEFAULT '',
                        LastUpdate INT
                    );"
                ).execute(&pool).await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS idx_txt_subdomain ON txt (Subdomain);"
                ).execute(&pool).await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS admin(Password TEXT NOT NULL);"
                ).execute(&pool).await?;

                let row: Option<(String,)> = sqlx::query_as("SELECT Value FROM acmedns WHERE Name = 'db_version'")
                    .fetch_optional(&pool).await?;
                if row.is_none() {
                    sqlx::query("INSERT INTO acmedns (Name, Value) VALUES ('db_version', '1')")
                        .execute(&pool).await?;
                }

                DbPool::Postgres(pool)
            }
            _ => return Err(sqlx::Error::Configuration("Unsupported database engine".into())),
        };
        Ok(pool)
    }

    pub async fn register(&self, allow_from: Vec<String>) -> Result<(Uuid, String, String), sqlx::Error> {
        let username = Uuid::new_v4();
        let subdomain = Uuid::new_v4().to_string();
        // Generate password matching original 40 chars config
        let password = crate::auth::generate_password(40);
        let password_hash = bcrypt::hash(&password, 10).map_err(|e| sqlx::Error::Configuration(e.to_string().into()))?;
        let allow_from_json = serde_json::to_string(&allow_from).map_err(|e| sqlx::Error::Configuration(e.to_string().into()))?;

        match self {
            DbPool::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("INSERT INTO records (Username, Password, Subdomain, AllowFrom) VALUES (?, ?, ?, ?)")
                    .bind(username.to_string())
                    .bind(&password_hash)
                    .bind(&subdomain)
                    .bind(&allow_from_json)
                    .execute(&mut *tx)
                    .await?;
                
                // Add 2 TXT records for dynamic rotation
                for _ in 0..2 {
                    sqlx::query("INSERT INTO txt (Subdomain, LastUpdate) VALUES (?, 0)")
                        .bind(&subdomain)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
            }
            DbPool::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("INSERT INTO records (Username, Password, Subdomain, AllowFrom) VALUES ($1, $2, $3, $4)")
                    .bind(username.to_string())
                    .bind(&password_hash)
                    .bind(&subdomain)
                    .bind(&allow_from_json)
                    .execute(&mut *tx)
                    .await?;
                
                for _ in 0..2 {
                    sqlx::query("INSERT INTO txt (Subdomain, LastUpdate) VALUES ($1, 0)")
                        .bind(&subdomain)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
            }
        }

        Ok((username, password, subdomain))
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<Record>, sqlx::Error> {
        match self {
            DbPool::Sqlite(pool) => {
                let row: Option<(String, String, String, String)> = sqlx::query_as(
                    "SELECT Username, Password, Subdomain, AllowFrom FROM records WHERE Username = ? LIMIT 1"
                )
                .bind(username)
                .fetch_optional(pool)
                .await?;

                if let Some((u, p, s, a)) = row {
                    let allow_from: Vec<String> = serde_json::from_str(&a).unwrap_or_default();
                    Ok(Some(Record { username: u, password_hash: p, subdomain: s, allow_from }))
                } else {
                    Ok(None)
                }
            }
            DbPool::Postgres(pool) => {
                let row: Option<(String, String, String, String)> = sqlx::query_as(
                    "SELECT Username, Password, Subdomain, AllowFrom FROM records WHERE Username = $1 LIMIT 1"
                )
                .bind(username)
                .fetch_optional(pool)
                .await?;

                if let Some((u, p, s, a)) = row {
                    let allow_from: Vec<String> = serde_json::from_str(&a).unwrap_or_default();
                    Ok(Some(Record { username: u, password_hash: p, subdomain: s, allow_from }))
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub async fn get_txt_for_domain(&self, subdomain: &str) -> Result<Vec<String>, sqlx::Error> {
        match self {
            DbPool::Sqlite(pool) => {
                let rows: Vec<(String,)> = sqlx::query_as(
                    "SELECT Value FROM txt WHERE Subdomain = ? LIMIT 2"
                )
                .bind(subdomain)
                .fetch_all(pool)
                .await?;
                Ok(rows.into_iter().map(|r| r.0).collect())
            }
            DbPool::Postgres(pool) => {
                let rows: Vec<(String,)> = sqlx::query_as(
                    "SELECT Value FROM txt WHERE Subdomain = $1 LIMIT 2"
                )
                .bind(subdomain)
                .fetch_all(pool)
                .await?;
                Ok(rows.into_iter().map(|r| r.0).collect())
            }
        }
    }

    pub async fn update_txt(&self, subdomain: &str, value: &str) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        match self {
            DbPool::Sqlite(pool) => {
                // SQLite uses rowid
                sqlx::query(
                    "UPDATE txt SET Value = ?, LastUpdate = ?
                     WHERE rowid = (
                         SELECT rowid FROM txt WHERE Subdomain = ? ORDER BY LastUpdate LIMIT 1
                     )"
                )
                .bind(value)
                .bind(now)
                .bind(subdomain)
                .execute(pool)
                .await?;
            }
            DbPool::Postgres(pool) => {
                // Postgres also has rowid defined in our schema
                sqlx::query(
                    "UPDATE txt SET Value = $1, LastUpdate = $2
                     WHERE rowid = (
                         SELECT rowid FROM txt WHERE Subdomain = $3 ORDER BY LastUpdate LIMIT 1
                     )"
                )
                .bind(value)
                .bind(now)
                .bind(subdomain)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn list_users(&self) -> Result<Vec<Record>, sqlx::Error> {
        match self {
            DbPool::Sqlite(pool) => {
                let rows: Vec<(String, String, String, String)> = sqlx::query_as(
                    "SELECT Username, Password, Subdomain, AllowFrom FROM records"
                )
                .fetch_all(pool)
                .await?;

                let users = rows.into_iter().map(|(u, p, s, a)| {
                    let allow_from: Vec<String> = serde_json::from_str(&a).unwrap_or_default();
                    Record { username: u, password_hash: p, subdomain: s, allow_from }
                }).collect();
                Ok(users)
            }
            DbPool::Postgres(pool) => {
                let rows: Vec<(String, String, String, String)> = sqlx::query_as(
                    "SELECT Username, Password, Subdomain, AllowFrom FROM records"
                )
                .fetch_all(pool)
                .await?;

                let users = rows.into_iter().map(|(u, p, s, a)| {
                    let allow_from: Vec<String> = serde_json::from_str(&a).unwrap_or_default();
                    Record { username: u, password_hash: p, subdomain: s, allow_from }
                }).collect();
                Ok(users)
            }
        }
    }

    pub async fn delete_user(&self, username: &str) -> Result<bool, sqlx::Error> {
        // Find subdomain first so we can clean up TXT table
        let user = self.get_user_by_username(username).await?;
        if let Some(record) = user {
            match self {
                DbPool::Sqlite(pool) => {
                    let mut tx = pool.begin().await?;
                    sqlx::query("DELETE FROM records WHERE Username = ?")
                        .bind(username)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM txt WHERE Subdomain = ?")
                        .bind(&record.subdomain)
                        .execute(&mut *tx)
                        .await?;
                    tx.commit().await?;
                }
                DbPool::Postgres(pool) => {
                    let mut tx = pool.begin().await?;
                    sqlx::query("DELETE FROM records WHERE Username = $1")
                        .bind(username)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM txt WHERE Subdomain = $1")
                        .bind(&record.subdomain)
                        .execute(&mut *tx)
                        .await?;
                    tx.commit().await?;
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn get_admin_password_hash(&self) -> Result<Option<String>, sqlx::Error> {
        match self {
            DbPool::Sqlite(pool) => {
                let row: Option<(String,)> = sqlx::query_as("SELECT Password FROM admin LIMIT 1")
                    .fetch_optional(pool)
                    .await?;
                Ok(row.map(|r| r.0))
            }
            DbPool::Postgres(pool) => {
                let row: Option<(String,)> = sqlx::query_as("SELECT Password FROM admin LIMIT 1")
                    .fetch_optional(pool)
                    .await?;
                Ok(row.map(|r| r.0))
            }
        }
    }

    pub async fn set_admin_password(&self, password_hash: &str) -> Result<(), sqlx::Error> {
        match self {
            DbPool::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("DELETE FROM admin").execute(&mut *tx).await?;
                sqlx::query("INSERT INTO admin (Password) VALUES (?)")
                    .bind(password_hash)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
            DbPool::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("DELETE FROM admin").execute(&mut *tx).await?;
                sqlx::query("INSERT INTO admin (Password) VALUES ($1)")
                    .bind(password_hash)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }
        Ok(())
    }
}
