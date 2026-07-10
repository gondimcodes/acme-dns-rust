mod config;
mod db;
mod dns;
mod api;
mod auth;

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::{UdpSocket, TcpListener as TokioTcpListener};
use hickory_server::ServerFuture;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
use crate::config::Config;
use crate::db::DbPool;
use crate::dns::AcmeDnsHandler;
use crate::api::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    // Default fallback
    let mut config_path = "./config.toml".to_string();
    let mut is_command = false;
    let mut command_args = Vec::new();

    let mut print_help = false;
    if args.len() > 1 {
        if args[1] == "--help" || args[1] == "-h" {
            print_help = true;
        } else if args[1] == "users" {
            is_command = true;
            if args.len() > 2 && (args[2] == "--help" || args[2] == "-h") {
                print_help = true;
            } else {
                command_args = args[1..].to_vec();
            }
        } else if args[1] == "--config" && args.len() > 2 {
            config_path = args[2].clone();
            if args.len() > 3 {
                if args[3] == "users" {
                    is_command = true;
                    if args.len() > 4 && (args[4] == "--help" || args[4] == "-h") {
                        print_help = true;
                    } else {
                        command_args = args[3..].to_vec();
                    }
                } else if args[3] == "--help" || args[3] == "-h" {
                    print_help = true;
                }
            }
        } else {
            // First argument is the raw config path legacy support
            config_path = args[1].clone();
        }
    }

    if print_help {
        println!("acme-dns-rust Server CLI");
        println!();
        println!("Usage:");
        println!("  acme-dns-rust [config_path]                         Start the DNS & HTTPS server");
        println!("  acme-dns-rust --config <path>                       Start the server using a specific config file");
        println!("  acme-dns-rust users list                            List all registered API users");
        println!("  acme-dns-rust users delete <username>               Delete a registered API user");
        println!("  acme-dns-rust users txt <username_or_subdomain>     View active challenge TXT tokens for a user or subdomain");
        println!("  acme-dns-rust users passwd                          Change the administrator CLI password");
        println!("  acme-dns-rust -h, --help                            Print help details");
        std::process::exit(0);
    }



    // Load config
    let config = Config::load(&config_path)
        .unwrap_or_else(|e| {
            eprintln!("Failed to load config from {}: {}", config_path, e);
            std::process::exit(1);
        });

    if is_command {
        // Run database tasks and exit
        let db = DbPool::new(&config).await?;
        
        // Admin Authentication
        let admin_hash_opt = db.get_admin_password_hash().await?;
        match admin_hash_opt {
            None => {
                println!("No Admin password set. Let's configure it now.");
                loop {
                    let pass1 = rpassword::prompt_password("Enter new admin password: ")?;
                    if pass1.len() < 6 {
                        println!("Password must be at least 6 characters long.");
                        continue;
                    }
                    let pass2 = rpassword::prompt_password("Confirm new admin password: ")?;
                    if pass1 != pass2 {
                        println!("Passwords do not match. Please try again.");
                        continue;
                    }
                    
                    let hash = bcrypt::hash(&pass1, 10)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                    db.set_admin_password(&hash).await?;
                    println!("Admin password configured successfully!\n");
                    break;
                }
            }
            Some(hash) => {
                let entered_pass = rpassword::prompt_password("Enter admin password: ")?;
                if !crate::auth::correct_password(&entered_pass, &hash) {
                    eprintln!("Error: Incorrect admin password.");
                    std::process::exit(1);
                }
            }
        }

        if command_args.len() >= 2 {
            match command_args[1].as_str() {
                "list" => {
                    let users = db.list_users().await?;
                    println!("Registered Users List:");
                    println!("------------------------------------------------------------");
                    println!("{:<38} | {:<38}", "Username", "Subdomain");
                    println!("------------------------------------------------------------");
                    for u in users {
                        println!("{:<38} | {:<38}", u.username, u.subdomain);
                    }
                    println!("------------------------------------------------------------");
                }
                "delete" => {
                    if command_args.len() < 3 {
                        eprintln!("Error: delete command requires a username argument.");
                        std::process::exit(1);
                    }
                    let username = &command_args[2];
                    match db.delete_user(username).await {
                        Ok(true) => {
                            println!("Successfully deleted user: {}", username);
                        }
                        Ok(false) => {
                            println!("User not found: {}", username);
                        }
                        Err(e) => {
                            eprintln!("Database error: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "txt" => {
                    if command_args.len() < 3 {
                        eprintln!("Error: txt command requires a username or subdomain argument.");
                        std::process::exit(1);
                    }
                    let input_val = &command_args[2];
                    // Clean suffix if user input a FQDN
                    let clean_val = input_val.split('.').next().unwrap_or(input_val).to_string();

                    // 1. Try to find if input is a Username first to map its Subdomain
                    let target_subdomain = match db.get_user_by_username(&clean_val).await {
                        Ok(Some(user_record)) => {
                            // Found user record, map to its subdomain
                            user_record.subdomain
                        }
                        _ => {
                            // Fallback: assume the input is the subdomain itself
                            clean_val.clone()
                        }
                    };
                    
                    match db.get_txt_for_domain(&target_subdomain).await {
                        Ok(values) => {
                            println!("TXT Records for subdomain UUID: {}", target_subdomain);
                            if target_subdomain != clean_val {
                                println!("(Resolved from username: {})", clean_val);
                            }
                            println!("------------------------------------------------------------");
                            if values.is_empty() {
                                println!("No active TXT records found.");
                            } else {
                                for (i, val) in values.iter().enumerate() {
                                    println!("Record [{}]: {}", i + 1, val);
                                }
                            }
                            println!("------------------------------------------------------------");
                        }
                        Err(e) => {
                            eprintln!("Database error: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "passwd" => {
                    println!("Changing admin password.");
                    loop {
                        let pass1 = rpassword::prompt_password("Enter new admin password: ")?;
                        if pass1.len() < 6 {
                            println!("Password must be at least 6 characters long.");
                            continue;
                        }
                        let pass2 = rpassword::prompt_password("Confirm new admin password: ")?;
                        if pass1 != pass2 {
                            println!("Passwords do not match. Please try again.");
                            continue;
                        }
                        
                        let hash = bcrypt::hash(&pass1, 10)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                        db.set_admin_password(&hash).await?;
                        println!("Admin password changed successfully!");
                        break;
                    }
                }
                _ => {
                    eprintln!("Unknown command. Available commands: users list, users delete <username>, users txt <subdomain>, users passwd");
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("Invalid command. Usage: users [list | delete <username> | txt <subdomain> | passwd]");
            std::process::exit(1);
        }
        return Ok(());
    }

    // Initialize logging
    let log_level = match config.logconfig.loglevel.to_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" | "warning" => Level::WARN,
        "debug" => Level::DEBUG,
        _ => Level::INFO,
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting acme-dns-rust");
    info!("Using config file: {}", config_path);

    // Initialize DB
    let db = Arc::new(DbPool::new(&config).await?);

    // Initialize DNS Servers (UDP & TCP)
    let dns_handler = AcmeDnsHandler::new(&config, Arc::clone(&db));
    let mut catalog = hickory_server::authority::Catalog::new();
    let own_domain_lower = hickory_server::proto::rr::LowerName::new(&dns_handler.own_domain);
    catalog.upsert(own_domain_lower, Box::new(Arc::new(dns_handler.clone())));

    let mut dns_server = ServerFuture::new(catalog);

    // Split listen string by comma to allow dual-stack binds (e.g. "0.0.0.0:53, [::]:53")
    let listen_addrs: Vec<SocketAddr> = config.general.listen
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<_, _>>()?;

    for addr in &listen_addrs {
        // Bind UDP
        let udp_socket = UdpSocket::bind(addr).await?;
        dns_server.register_socket(udp_socket);

        // Bind TCP
        let tcp_listener = TokioTcpListener::bind(addr).await?;
        dns_server.register_listener(
            tcp_listener,
            std::time::Duration::from_secs(5),
        );
        info!("DNS Server listening on {} ({})", addr, config.general.proto);
    }

    // Parse multiple API listen addresses (IPs and Ports)
    let api_ips: Vec<&str> = config.api.ip.split(',').map(|s| s.trim()).collect();
    let api_ports: Vec<&str> = config.api.port.split(',').map(|s| s.trim()).collect();
    
    let mut api_addrs = Vec::new();
    for (i, ip_str) in api_ips.iter().enumerate() {
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            let port_str = api_ports.get(i).or_else(|| api_ports.first()).unwrap_or(&"443");
            if let Ok(port) = port_str.parse::<u16>() {
                api_addrs.push(SocketAddr::new(ip, port));
            }
        }
    }

    if api_addrs.is_empty() {
        return Err("No valid API listen addresses configured".into());
    }

    let state = AppState {
        db: Arc::clone(&db),
        config: config.clone(),
    };
    let api_router = api::create_router(state);

    // Spawn DNS task
    let dns_task = tokio::spawn(async move {
        if let Err(e) = dns_server.block_until_done().await {
            error!("DNS server error: {}", e);
        }
    });

    // Spawn HTTP/HTTPS API tasks for each socket address
    let mut api_tasks = Vec::new();
    for api_addr in api_addrs {
        let api_router = api_router.clone();
        let config = config.clone();
        
        let task = tokio::spawn(async move {
            match config.api.tls.as_str() {
                "cert" => {
                    let cert_file = config.api.tls_cert_fullchain.clone().unwrap_or_default();
                    let key_file = config.api.tls_cert_privkey.clone().unwrap_or_default();

                    info!("Loading TLS certificates from {}", cert_file);
                    let cert_data = std::fs::read(&cert_file);
                    let key_data = std::fs::read(&key_file);

                    if let (Ok(certs), Ok(keys)) = (cert_data, key_data) {
                        match axum_server::tls_rustls::RustlsConfig::from_pem(certs, keys).await {
                            Ok(rustls_config) => {
                                info!("HTTPS API Server listening on {}", api_addr);
                                if let Err(e) = axum_server::bind_rustls(api_addr, rustls_config)
                                    .serve(api_router.into_make_service())
                                    .await 
                                {
                                    error!("HTTPS API server error on {}: {}", api_addr, e);
                                }
                            }
                            Err(e) => {
                                error!("Failed to initialize Rustls configuration: {}", e);
                            }
                        }
                    } else {
                        error!("Failed to read certificate files: {} or {}", cert_file, key_file);
                    }
                }
                "letsencrypt" | "letsencryptstaging" => {
                    use rustls_acme::{AcmeConfig, caches::DirCache};
                    use tokio_stream::StreamExt;

                    let staging = config.api.tls == "letsencryptstaging";
                    let cache_dir = config.api.acme_cache_dir.clone().unwrap_or_else(|| "api-certs".to_string());
                    let contact_email = config.api.notification_email.clone().unwrap_or_default();
                    
                    info!("Starting Automated HTTPS via Let's Encrypt (staging: {}) on {}", staging, api_addr);

                    let mut acme_config = AcmeConfig::new([config.general.domain.clone()])
                        .directory_lets_encrypt(!staging)
                        .cache(DirCache::new(cache_dir));

                    if !contact_email.is_empty() {
                        acme_config = acme_config.contact_push(format!("mailto:{}", contact_email));
                    }

                    let listener = match tokio::net::TcpListener::bind(api_addr).await {
                        Ok(l) => l,
                        Err(e) => {
                            error!("Failed to bind API port {}: {}", api_addr, e);
                            return;
                        }
                    };

                    let mut tls_incoming = acme_config.tokio_incoming(
                        tokio_stream::wrappers::TcpListenerStream::new(listener),
                        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                    );

                    let make_svc = api_router.into_make_service();
                    while let Some(tls_result) = tls_incoming.next().await {
                        match tls_result {
                            Ok(tls_stream) => {
                                let make_svc_clone = make_svc.clone();
                                tokio::spawn(async move {
                                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                                    let service = tower::Service::call(&mut make_svc_clone.clone(), ()).await.unwrap();
                                    let hyper_service = hyper_util::service::TowerToHyperService::new(service);
                                    if let Err(err) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                                        .serve_connection(io, hyper_service)
                                        .await
                                    {
                                        error!("Error serving TLS connection: {:?}", err);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("TLS acceptance / ACME error: {:?}", e);
                            }
                        }
                    }
                }
                _ => {
                    info!("HTTP API Server listening on {}", api_addr);
                    let api_listener = match tokio::net::TcpListener::bind(api_addr).await {
                        Ok(l) => l,
                        Err(e) => {
                            error!("Failed to bind API port {}: {}", api_addr, e);
                            return;
                        }
                    };
                    if let Err(e) = axum::serve(api_listener, api_router).await {
                        error!("HTTP API server error on {}: {}", api_addr, e);
                    }
                }
            }
        });
        api_tasks.push(task);
    }

    let api_task = tokio::spawn(async move {
        for t in api_tasks {
            let _ = t.await;
        }
    });

    // Wait for shutdown signals or failures
    tokio::select! {
        res = dns_task => {
            if let Err(e) = res {
                error!("DNS task failed: {}", e);
            }
        }
        res = api_task => {
            if let Err(e) = res {
                error!("API task failed: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received, shutting down gracefully...");
        }
    }

    Ok(())
}
