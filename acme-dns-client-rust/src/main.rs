use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs::{self, File};
use std::io::{self, Write};
use std::time::Duration;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

const DEFAULT_STORAGE: &str = "/etc/acmedns/clientstorage.json";
const PUBLIC_ACME_DNS: &str = "https://auth.acme-dns.io";

#[derive(Debug, Parser)]
#[command(name = "acme-dns-client-rust", version = "0.1.0", about = "acme-dns client utility in Rust")]
struct Cli {
    #[arg(short, long, default_value = "https://auth.acme-dns.io", help = "Acme-dns server instance to use")]
    server: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    #[command(about = "Register a new acme-dns account for a domain")]
    Register {
        #[arg(short, long, help = "Target domain name")]
        domain: String,

        #[arg(short, long, default_value = "8.8.8.8:53", help = "Fallback DNS server and port to use for CNAME checks")]
        ns: String,

        #[arg(long, help = "Comma separated list of CIDR masks allowed to update this domain")]
        allow: Option<String>,

        #[arg(long, default_value_t = false, help = "Suppresses warning when registering on public instances")]
        dangerous: bool,
    },

    #[command(about = "Check CNAME and CAA configurations for a domain")]
    Check {
        #[arg(short, long, help = "Target domain name")]
        domain: String,

        #[arg(short, long, default_value = "8.8.8.8:53", help = "Fallback DNS server and port to use for checks")]
        ns: String,
    },

    #[command(about = "List all registered accounts and check their CNAME records")]
    List {
        #[arg(short, long, default_value = "8.8.8.8:53", help = "Fallback DNS server and port to use for checks")]
        ns: String,
    },

    #[command(about = "Deregister and remove a local account for a domain from storage")]
    Deregister {
        #[arg(short, long, help = "Target domain name to remove")]
        domain: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Account {
    username: String,
    password: String,
    fulldomain: String,
    subdomain: String,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(rename = "serverurl")]
    server_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterRequest {
    allowfrom: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    username: String,
    password: String,
    fulldomain: String,
    subdomain: String,
    #[serde(rename = "allowfrom")]
    _allowfrom: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UpdateRequest {
    subdomain: String,
    txt: String,
}

struct Storage {
    path: PathBuf,
}

impl Storage {
    fn new(path: &str) -> Self {
        Self {
            path: PathBuf::from(path),
        }
    }

    fn load(&self) -> HashMap<String, Account> {
        if !self.path.exists() {
            return HashMap::new();
        }
        let file = File::open(&self.path).ok();
        if let Some(f) = file {
            serde_json::from_reader(f).unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    fn save(&self, data: &HashMap<String, Account>) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::create(&self.path)?;
        serde_json::to_writer_pretty(file, data)?;
        Ok(())
    }
}

fn get_resolver(ns_addr: &str) -> Option<TokioAsyncResolver> {
    let mut addr_str = ns_addr.to_string();
    // Normalize IPv6 raw addresses
    if addr_str.contains(':') && !addr_str.contains('[') && addr_str.chars().filter(|&c| c == ':').count() > 1 {
        addr_str = format!("[{}]:53", addr_str);
    }
    
    // Add default port 53 if not specified
    if !addr_str.contains(':') {
        addr_str.push_str(":53");
    }

    if let Ok(socket_addr) = addr_str.parse::<std::net::SocketAddr>() {
        let mut config = ResolverConfig::new();
        config.add_name_server(hickory_resolver::config::NameServerConfig {
            socket_addr,
            protocol: hickory_resolver::config::Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        
        // Optimize options: fast timeout (1s) and no retries (1 attempt) to prevent wait latency
        let mut opts = ResolverOpts::default();
        opts.ndots = 0;
        opts.num_concurrent_reqs = 1;
        opts.timeout = Duration::from_secs(1);
        opts.attempts = 1;
        
        Some(TokioAsyncResolver::tokio(config, opts))
    } else {
        None
    }
}

// Recursive resolver helper to find the authoritative nameservers for any TLD structure
async fn find_base_zone_ns(domain: &str) -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    let mut parts: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    
    // Iterate from full subdomain down to the base domains (e.g. bola.circo.uk -> circo.uk)
    while parts.len() >= 2 {
        let current_zone = parts.join(".");
        let query = format!("{}.", current_zone);
        
        if let Ok(ns_lookup) = resolver.lookup(query, hickory_resolver::proto::rr::RecordType::NS).await {
            for record in ns_lookup.iter() {
                if let Some(ns_name) = record.as_ns() {
                    // Resolve NS hostnames to IP addresses
                    if let Ok(ip_lookup) = resolver.lookup_ip(ns_name.to_string()).await {
                        for ip in ip_lookup.iter() {
                            ips.push(ip);
                        }
                    }
                }
            }
            if !ips.is_empty() {
                break;
            }
        }
        parts.remove(0);
    }
    ips
}

async fn check_cname(resolver: &TokioAsyncResolver, domain: &str, target: &str) -> bool {
    let query = format!("_acme-challenge.{}.", domain);
    match resolver.lookup(query, hickory_resolver::proto::rr::RecordType::CNAME).await {
        Ok(lookup) => {
            for record in lookup.iter() {
                let record_str = record.to_string().trim_end_matches('.').to_lowercase();
                let target_str = target.trim_end_matches('.').to_lowercase();
                
                if record_str == target_str || record_str.contains(&target_str) {
                    return true;
                }
                
                if let Some(target_uuid) = target_str.split('.').next() {
                    if record_str.contains(target_uuid) {
                        return true;
                    }
                }
            }
        }
        Err(_e) => {}
    }
    false
}

// Authoritative NS query wrapper for CNAME records validation
async fn check_cname_authoritative(custom_resolver: &Option<TokioAsyncResolver>, fallback_resolver: &TokioAsyncResolver, domain: &str, target: &str) -> bool {
    // 1. Resolve authoritative nameserver IPs for the base domain
    let auth_ips = find_base_zone_ns(domain).await;
    
    // 2. Query each authoritative nameserver directly
    for ns_ip in &auth_ips {
        let mut auth_config = ResolverConfig::new();
        auth_config.add_name_server(hickory_resolver::config::NameServerConfig {
            socket_addr: std::net::SocketAddr::new(*ns_ip, 53),
            protocol: hickory_resolver::config::Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        let mut auth_opts = ResolverOpts::default();
        auth_opts.timeout = Duration::from_secs(1);
        auth_opts.attempts = 1;
        auth_opts.ndots = 0;
        
        let auth_resolver = TokioAsyncResolver::tokio(auth_config, auth_opts);
        if check_cname(&auth_resolver, domain, target).await {
            return true;
        }
    }
    
    // 3. Fallback to custom user DNS resolver (e.g. system custom DNS)
    if let Some(resolver) = custom_resolver {
        if check_cname(resolver, domain, target).await {
            return true;
        }
    }
    
    // 4. Fallback to standard public recursors
    if check_cname(fallback_resolver, domain, target).await {
        return true;
    }
    
    false
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if we are running as a Certbot hook (Environment Variables validation flow)
    let certbot_domain = std::env::var("CERTBOT_DOMAIN").unwrap_or_default();
    let certbot_validation = std::env::var("CERTBOT_VALIDATION").unwrap_or_default();

    let storage_env = std::env::var("ACMEDNS_STORAGE").unwrap_or_else(|_| DEFAULT_STORAGE.to_string());
    let storage = Storage::new(&storage_env);

    if !certbot_domain.is_empty() && !certbot_validation.is_empty() {
        println!("Certbot environment variables detected.");
        let clean_domain = certbot_domain.replace("*.", "");
        let data = storage.load();
        if let Some(account) = data.get(&clean_domain) {
            println!("Updating TXT record for domain: {}", clean_domain);
            let client = reqwest::Client::new();
            let payload = UpdateRequest {
                subdomain: account.subdomain.clone(),
                txt: certbot_validation,
            };
            let res = client.post(format!("{}/update", account.server_url))
                .header("X-Api-User", &account.username)
                .header("X-Api-Key", &account.password)
                .json(&payload)
                .send()
                .await?;

            if res.status().is_success() {
                println!("Successfully updated acme-dns record!");
                println!("Waiting 10 seconds for DNS record propagation...");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                std::process::exit(0);
            } else {
                eprintln!("Error updating acme-dns server: HTTP {}", res.status());
                std::process::exit(1);
            }
        } else {
            eprintln!("Error: No acme-dns account registered for domain '{}' in storage.", clean_domain);
            std::process::exit(1);
        }
    }

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Register { domain, ns, allow, dangerous }) => {
            let clean_domain = domain.replace("*.", "");
            let mut data = storage.load();

            if data.contains_key(&clean_domain) {
                println!("Warning: Domain {} already registered in storage.", clean_domain);
                return Ok(());
            }

            if cli.server == PUBLIC_ACME_DNS && !dangerous {
                println!("WARNING: You are about to register an account on a public acme-dns instance.");
                println!("This authorizes the instance owner to request/validate certificates on your behalf.");
                println!("To suppress this warning, re-run with --dangerous flag.");
                std::process::exit(0);
            }

            println!("Registering account for domain: {}...", clean_domain);
            let allow_from = if let Some(allow_list) = allow {
                allow_list.split(',').map(|s| s.trim().to_string()).collect()
            } else {
                Vec::new()
            };

            let req_client = reqwest::Client::new();
            let reg_payload = RegisterRequest { allowfrom: allow_from.clone() };

            let res = req_client.post(format!("{}/register", cli.server))
                .json(&reg_payload)
                .send()
                .await?;

            if !res.status().is_success() {
                eprintln!("Registration failed: HTTP {}", res.status());
                std::process::exit(1);
            }

            let response: RegisterResponse = res.json().await?;
            let account = Account {
                username: response.username,
                password: response.password,
                fulldomain: response.fulldomain.clone(),
                subdomain: response.subdomain,
                allow: allow_from,
                server_url: cli.server.clone(),
            };

            data.insert(clean_domain.clone(), account.clone());
            storage.save(&data)?;

            println!("\nRegistration successful!");
            println!("------------------------------------------------------------");
            println!("Username:   {}", account.username);
            println!("Password:   {}", account.password);
            println!("FullDomain: {}", account.fulldomain);
            println!("------------------------------------------------------------");

            println!("\nPlease create the following CNAME record in your DNS zone:");
            println!("_acme-challenge.{}. IN CNAME {}.", clean_domain, account.fulldomain);

            // Prebuild public resolver as fallback using strictly IPv4 to prevent IPv6 routing timeouts
            let mut fallback_config = ResolverConfig::new();
            fallback_config.add_name_server(hickory_resolver::config::NameServerConfig {
                socket_addr: "8.8.8.8:53".parse().unwrap(),
                protocol: hickory_resolver::config::Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
            fallback_config.add_name_server(hickory_resolver::config::NameServerConfig {
                socket_addr: "1.1.1.1:53".parse().unwrap(),
                protocol: hickory_resolver::config::Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
            
            // Disable search domains and system suffixes to prevent lookup latency
            let mut fallback_opts = ResolverOpts::default();
            fallback_opts.ndots = 0;
            fallback_opts.timeout = Duration::from_secs(1);
            fallback_opts.attempts = 1;
            
            let fallback_resolver = TokioAsyncResolver::tokio(fallback_config, fallback_opts);
            let custom_resolver = get_resolver(&ns);

            let cname_ok = check_cname_authoritative(&custom_resolver, &fallback_resolver, &clean_domain, &account.fulldomain).await;

            if cname_ok {
                println!("CNAME record seems to already be set up correctly, you are good to go!");
            } else {
                print!("Do you want acme-dns-client-rust to monitor the CNAME record change? [Y/n]: ");
                let _ = io::stdout().flush();
                let mut input = String::new();
                let mut monitor = true;
                let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
                use tokio::io::AsyncBufReadExt;
                if reader.read_line(&mut input).await.is_ok() {
                    let input = input.trim().to_lowercase();
                    if input == "n" {
                        monitor = false;
                    }
                }

                if monitor {
                    println!("\nWaiting for CNAME record propagation...");
                    loop {
                        let verified = check_cname_authoritative(&custom_resolver, &fallback_resolver, &clean_domain, &account.fulldomain).await;
                        if verified {
                            println!("\nCNAME propagation verified successfully!");
                            break;
                        }
                        for i in (1..=15).rev() {
                            print!("\rChecking again in {:2} seconds...", i);
                            let _ = io::stdout().flush();
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        print!("\rChecking...                         ");
                        let _ = io::stdout().flush();
                    }
                } else {
                    println!("\nSkipping CNAME monitoring. You can check it later using: acme-dns-client-rust check -d {}", clean_domain);
                }
            }

            // CAA Record Wizard Step
            println!("\n--- CAA Configuration ---");
            println!("A CAA record allows you to control certificate issuance safeguards.");
            print!("Do you wish to set up a CAA record now? [y/N]: ");
            let _ = io::stdout().flush();
            let mut caa_input = String::new();
            let mut monitor_caa = false;
            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
            use tokio::io::AsyncBufReadExt;
            if reader.read_line(&mut caa_input).await.is_ok() {
                let val = caa_input.trim().to_lowercase();
                if val == "y" {
                    monitor_caa = true;
                }
            }

            if monitor_caa {
                println!("\nExample CAA records to add to your DNS zone:");
                println!("{}.         IN    CAA    0 issue \"letsencrypt.org; validationmethods=dns-01\"", clean_domain);
                println!("{}.         IN    CAA    0 issuewild \"letsencrypt.org; validationmethods=dns-01\"", clean_domain);
                
                let fallback_resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
                if let Some(resolver) = get_resolver(&ns) {
                    println!("\nWaiting for CAA record creation (checking every 15s)...");
                    loop {
                        let query = format!("{}.", clean_domain);
                        let mut has_caa = false;
                        
                        // 1. Check Authoritative Nameservers directly
                        let auth_ips = find_base_zone_ns(&clean_domain).await;
                        for ns_ip in &auth_ips {
                            let mut auth_config = ResolverConfig::new();
                            auth_config.add_name_server(hickory_resolver::config::NameServerConfig {
                                socket_addr: std::net::SocketAddr::new(*ns_ip, 53),
                                protocol: hickory_resolver::config::Protocol::Udp,
                                tls_dns_name: None,
                                trust_negative_responses: false,
                                bind_addr: None,
                            });
                            let mut auth_opts = ResolverOpts::default();
                            auth_opts.timeout = Duration::from_secs(1);
                            auth_opts.attempts = 1;
                            auth_opts.ndots = 0;
                            
                            let auth_resolver = TokioAsyncResolver::tokio(auth_config, auth_opts);
                            if let Ok(lookup) = auth_resolver.lookup(query.clone(), hickory_resolver::proto::rr::RecordType::CAA).await {
                                if !lookup.is_empty() {
                                    has_caa = true;
                                    break;
                                }
                            }
                        }

                        // 2. Check Custom user DNS resolver
                        if !has_caa {
                            if let Ok(lookup) = resolver.lookup(query.clone(), hickory_resolver::proto::rr::RecordType::CAA).await {
                                if !lookup.is_empty() {
                                    has_caa = true;
                                }
                            }
                        }

                        // 3. Check Fallback DNS resolver
                        if !has_caa {
                            if let Ok(lookup) = fallback_resolver.lookup(query.clone(), hickory_resolver::proto::rr::RecordType::CAA).await {
                                if !lookup.is_empty() {
                                    has_caa = true;
                                }
                            }
                        }

                        if has_caa {
                            println!("\nCAA record detected successfully!");
                            break;
                        }
                        for i in (1..=15).rev() {
                            print!("\rChecking CAA again in {:2} seconds...", i);
                            let _ = io::stdout().flush();
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        print!("\rChecking...                             ");
                        let _ = io::stdout().flush();
                    }
                }
            } else {
                println!("Skipping CAA record setup.");
            }
        }
        Some(Commands::Check { domain, ns }) => {
            let clean_domain = domain.replace("*.", "");
            let data = storage.load();

            if let Some(account) = data.get(&clean_domain) {
                println!("Checking configuration for domain: {}", clean_domain);
                let fallback_resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
                let custom_resolver = get_resolver(&ns);

                let verified = check_cname_authoritative(&custom_resolver, &fallback_resolver, &clean_domain, &account.fulldomain).await;

                if verified {
                    println!("Status: OK (CNAME record set up correctly)");
                } else {
                    println!("Status: ERROR (CNAME record not propagated or pointing to wrong target)");
                }
            } else {
                println!("No acme-dns account found in storage for domain: {}", clean_domain);
            }
        }
        Some(Commands::List { ns }) => {
            let data = storage.load();
            if data.is_empty() {
                println!("No acme-dns accounts found in storage.");
                return Ok(());
            }

            println!("Registered domains (checking CNAMEs):");
            let fallback_resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
            let custom_resolver = get_resolver(&ns);

            for (domain, account) in data {
                let verified = check_cname_authoritative(&custom_resolver, &fallback_resolver, &domain, &account.fulldomain).await;

                let status = if verified {
                    "OK"
                } else {
                    "CNAME_MISMATCH"
                };
                println!("- {:<30} [Status: {}] Target: {}", domain, status, account.fulldomain);
            }
        }
        Some(Commands::Deregister { domain }) => {
            let clean_domain = domain.replace("*.", "");
            let mut data = storage.load();
            if data.contains_key(&clean_domain) {
                data.remove(&clean_domain);
                storage.save(&data)?;
                println!("Successfully deregistered domain {} and removed local account from storage.", clean_domain);
            } else {
                println!("No acme-dns account registered locally for domain: {}", clean_domain);
            }
        }
        None => {
            println!("No subcommand specified. Use --help for usage.");
        }
    }

    Ok(())
}
