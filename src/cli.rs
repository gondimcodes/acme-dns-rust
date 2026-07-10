/// QUAL-02: CLI module extracted from main.rs
/// QUAL-04: Replaces manual arg parsing with clap derive API
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "acme-dns-rust",
    version,
    about = "ACME DNS server with REST API for automated certificate challenges",
    long_about = None
)]
pub struct Cli {
    /// Path to the configuration file
    #[arg(short, long, default_value = "./config.toml", global = true)]
    pub config: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage registered API users
    Users {
        #[command(subcommand)]
        action: UserAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserAction {
    /// List all registered users
    List,
    /// Delete a registered user by username
    Delete {
        /// Username to delete
        username: String,
    },
    /// Show active TXT challenge tokens for a user or subdomain
    Txt {
        /// Username or subdomain UUID
        target: String,
    },
    /// Change the administrator CLI password
    Passwd,
}
