use acme_dns_rust::{config::Config, db::DbPool, dns::AcmeDnsHandler, api::{AppState, create_router}, auth};
use clap::Parser;
use cli::{Cli, Commands, UserAction};
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::{UdpSocket, TcpListener};
use hickory_server::ServerFuture;
use tracing::{info, error};
use tracing_subscriber::FmtSubscriber;
use metrics_exporter_prometheus::PrometheusBuilder;

mod cli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config_path = cli.config.clone();

    let config = Config::load(&config_path).unwrap_or_else(|e| {
        eprintln!("Failed to load config from {}: {}", config_path, e);
        std::process::exit(1);
    });

    if let Some(Commands::Users { action }) = cli.command {
        run_user_command(action, config).await?;
        return Ok(());
    }

    // Initialize logging
    let log_level = match config.logconfig.loglevel.to_lowercase().as_str() {
        "error" => tracing::Level::ERROR,
        "warn" | "warning" => tracing::Level::WARN,
        "debug" => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting acme-dns-rust v{}", env!("CARGO_PKG_VERSION"));
    info!("Using config: {}", config_path);

    // Initialize DB
    let db = Arc::new(DbPool::new(&config).await?);

    // SEG-06: AcmeDnsHandler::new now returns Result
    let dns_handler = AcmeDnsHandler::new(&config, Arc::clone(&db)).map_err(|e| {
        error!("Failed to initialize DNS handler: {}", e);
        e
    })?;

    let mut catalog = hickory_server::authority::Catalog::new();
    let own_domain_lower = hickory_server::proto::rr::LowerName::new(&dns_handler.own_domain);
    catalog.upsert(own_domain_lower, Box::new(Arc::new(dns_handler.clone())));

    let mut dns_server = ServerFuture::new(catalog);

    let listen_addrs: Vec<SocketAddr> = config.general.listen
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<_, _>>()?;

    for addr in &listen_addrs {
        let udp = UdpSocket::bind(addr).await?;
        dns_server.register_socket(udp);
        let tcp = TcpListener::bind(addr).await?;
        dns_server.register_listener(tcp, std::time::Duration::from_secs(5));
        info!("DNS listening on {} ({})", addr, config.general.proto);
    }

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

    // ARQ-05: initialise Prometheus recorder
    let metrics_handle = Arc::new(
        PrometheusBuilder::new()
            .install_recorder()
            .expect("Failed to install Prometheus recorder"),
    );

    let config = Arc::new(config);
    let state = AppState {
        db: Arc::clone(&db),
        config: Arc::clone(&config),
        metrics_handle: Arc::clone(&metrics_handle),
    };
    let api_router = create_router(state);

    let dns_task = tokio::spawn(async move {
        if let Err(e) = dns_server.block_until_done().await {
            error!("DNS server error: {}", e);
        }
    });

    let mut api_tasks = Vec::new();
    for api_addr in api_addrs {
        let api_router = api_router.clone();
        let config = Arc::clone(&config);
        let task = tokio::spawn(async move {
            match config.api.tls.as_str() {
                "cert" => {
                    let cert_file = config.api.tls_cert_fullchain.clone().unwrap_or_default();
                    let key_file = config.api.tls_cert_privkey.clone().unwrap_or_default();
                    info!("Loading TLS certificates from {}", cert_file);
                    if let (Ok(certs), Ok(keys)) = (std::fs::read(&cert_file), std::fs::read(&key_file)) {
                        match axum_server::tls_rustls::RustlsConfig::from_pem(certs, keys).await {
                            Ok(rustls_config) => {
                                info!("HTTPS API listening on {}", api_addr);
                                if let Err(e) = axum_server::bind_rustls(api_addr, rustls_config)
                                    .serve(api_router.into_make_service()).await
                                {
                                    error!("HTTPS error on {}: {}", api_addr, e);
                                }
                            }
                            Err(e) => error!("Failed to init Rustls: {}", e),
                        }
                    } else {
                        error!("Failed to read cert files: {} / {}", cert_file, key_file);
                    }
                }
                "letsencrypt" | "letsencryptstaging" => {
                    use rustls_acme::{AcmeConfig, caches::DirCache};
                    use tokio_stream::StreamExt;
                    let staging = config.api.tls == "letsencryptstaging";
                    let cache_dir = config.api.acme_cache_dir.clone().unwrap_or_else(|| "api-certs".to_string());
                    let contact_email = config.api.notification_email.clone().unwrap_or_default();
                    info!("ACME Let's Encrypt (staging: {}) on {}", staging, api_addr);
                    let mut acme_config = AcmeConfig::new([config.general.domain.clone()])
                        .directory_lets_encrypt(!staging)
                        .cache(DirCache::new(cache_dir));
                    if !contact_email.is_empty() {
                        acme_config = acme_config.contact_push(format!("mailto:{}", contact_email));
                    }
                    let listener = match tokio::net::TcpListener::bind(api_addr).await {
                        Ok(l) => l,
                        Err(e) => { error!("Bind failed {}: {}", api_addr, e); return; }
                    };
                    let mut tls_incoming = acme_config.tokio_incoming(
                        tokio_stream::wrappers::TcpListenerStream::new(listener),
                        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                    );
                    let make_svc = api_router.into_make_service();
                    while let Some(tls_result) = tls_incoming.next().await {
                        match tls_result {
                            Ok(tls_stream) => {
                                let make_svc_clone = make_svc.clone();
                                tokio::spawn(async move {
                                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                                    // SEG-06: no unwrap() on service creation
                                    let service = match tower::Service::call(&mut make_svc_clone.clone(), ()).await {
                                        Ok(s) => s,
                                        Err(e) => { error!("Service creation failed: {:?}", e); return; }
                                    };
                                    let hyper_service = hyper_util::service::TowerToHyperService::new(service);
                                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                                        hyper_util::rt::TokioExecutor::new()
                                    ).serve_connection(io, hyper_service).await {
                                        error!("TLS connection error: {:?}", e);
                                    }
                                });
                            }
                            Err(e) => error!("TLS/ACME error: {:?}", e),
                        }
                    }
                }
                _ => {
                    info!("HTTP API listening on {}", api_addr);
                    let listener = match TcpListener::bind(api_addr).await {
                        Ok(l) => l,
                        Err(e) => { error!("Bind failed {}: {}", api_addr, e); return; }
                    };
                    if let Err(e) = axum::serve(listener, api_router).await {
                        error!("HTTP error on {}: {}", api_addr, e);
                    }
                }
            }
        });
        api_tasks.push(task);
    }

    let api_task = tokio::spawn(async move {
        for t in api_tasks { let _ = t.await; }
    });

    // ARQ-02: graceful shutdown — SIGTERM (systemd) + SIGINT (Ctrl-C)
    #[cfg(unix)]
    let shutdown = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler failed");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("SIGINT received, shutting down..."),
            _ = sigterm.recv() => info!("SIGTERM received, shutting down..."),
        }
    };
    #[cfg(not(unix))]
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("Ctrl-C received, shutting down...");
    };

    tokio::select! {
        res = dns_task => { if let Err(e) = res { error!("DNS task failed: {}", e); } }
        res = api_task => { if let Err(e) = res { error!("API task failed: {}", e); } }
        _ = shutdown => {}
    }

    Ok(())
}

async fn run_user_command(action: UserAction, config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let db = DbPool::new(&config).await?;

    let admin_hash_opt = db.get_admin_password_hash().await?;
    match admin_hash_opt {
        None => {
            println!("No admin password set. Configure it now.");
            setup_admin_password(&db).await?;
        }
        Some(hash) => {
            let entered = rpassword::prompt_password("Enter admin password: ")?;
            if !auth::correct_password(&entered, &hash) {
                eprintln!("Error: Incorrect admin password.");
                std::process::exit(1);
            }
        }
    }

    match action {
        UserAction::List => {
            let users = db.list_users().await?;
            println!("{:<38} | {:<38}", "Username", "Subdomain");
            println!("{}", "-".repeat(79));
            for u in users {
                println!("{:<38} | {:<38}", u.username, u.subdomain);
            }
        }
        UserAction::Delete { username } => {
            match db.delete_user(&username).await? {
                true  => println!("Deleted user: {}", username),
                false => println!("User not found: {}", username),
            }
        }
        UserAction::Txt { target } => {
            let clean = target.split('.').next().unwrap_or(&target).to_string();
            let subdomain = match db.get_user_by_username(&clean).await {
                Ok(Some(r)) => r.subdomain,
                _ => clean.clone(),
            };
            let values = db.get_txt_for_domain(&subdomain).await?;
            println!("TXT records for subdomain: {}", subdomain);
            if values.is_empty() {
                println!("  (none)");
            } else {
                for (i, v) in values.iter().enumerate() { println!("  [{}] {}", i + 1, v); }
            }
        }
        UserAction::Passwd => {
            println!("Changing admin password.");
            setup_admin_password(&db).await?;
        }
    }
    Ok(())
}

async fn setup_admin_password(db: &DbPool) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let pass1 = rpassword::prompt_password("Enter new admin password: ")?;
        if pass1.len() < auth::MIN_PASSWORD_LEN {
            println!("Password must be at least {} characters.", auth::MIN_PASSWORD_LEN);
            continue;
        }
        let pass2 = rpassword::prompt_password("Confirm new admin password: ")?;
        if pass1 != pass2 { println!("Passwords do not match."); continue; }
        let hash = bcrypt::hash(&pass1, 10)?;
        db.set_admin_password(&hash).await?;
        println!("Admin password configured successfully!");
        break;
    }
    Ok(())
}
