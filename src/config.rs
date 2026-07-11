use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub general: General,
    pub database: Database,
    pub api: Api,
    pub logconfig: LogConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct General {
    pub listen: String,
    #[serde(rename = "protocol")]
    pub proto: String,
    pub domain: String,
    pub nsname: String,
    pub nsadmin: String,
    pub debug: bool,
    #[serde(rename = "records")]
    pub static_records: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Database {
    pub engine: String,
    pub connection: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Api {
    #[serde(rename = "api_domain")]
    pub api_domain: Option<String>,
    pub ip: String,
    pub disable_registration: bool,
    pub autocert_port: Option<String>,
    pub port: String,
    pub tls: String,
    pub tls_cert_privkey: Option<String>,
    pub tls_cert_fullchain: Option<String>,
    pub acme_cache_dir: Option<String>,
    pub notification_email: Option<String>,
    pub corsorigins: Vec<String>,
    pub use_header: bool,
    pub header_name: String,
    pub hsts_enabled: bool,
    pub hsts_max_age: Option<u32>,
    pub hsts_include_subdomains: bool,
    pub hsts_preload: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub register_rate_limit_per_min: u32,
    #[serde(default = "default_cleanup_orphans")]
    pub cleanup_orphans: bool,
    #[serde(default = "default_orphan_timeout_mins")]
    pub orphan_timeout_mins: u32,
}

fn default_cleanup_orphans() -> bool { true }
fn default_orphan_timeout_mins() -> u32 { 30 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    pub loglevel: String,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
