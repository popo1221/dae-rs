//! dae-rs CLI entry point
//!
//! High-performance transparent proxy in Rust with eBPF integration

use clap::{Parser, Subcommand};
use dae_proxy::{
    Proxy, ProxyConfig,
    shadowsocks::{SsCipherType, SsServerConfig},
    vless::{VlessServerConfig, VlessTlsConfig},
    vmess::{VmessServerConfig, VmessSecurity},
    trojan::{TrojanServerConfig, TrojanTlsConfig},
    rule_engine::{RuleEngine, RuleEngineConfig, new_rule_engine},
    control::{ControlServer, ControlState, connect_and_send, connect_and_get_status},
};
use dae_core::Engine;
use dae_config::{Config, NodeConfig, NodeType, ProxyConfig as DaeProxyConfig};
use dae_cli::api::{ApiServer, AppState};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "dae")]
#[command(version = "0.1.0", about = "High-performance transparent proxy in Rust with eBPF")]
struct Args {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Config file path
    #[arg(short, long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the proxy daemon
    Run {
        /// XDP interface to attach to
        #[arg(long)]
        interface: Option<String>,

        /// XDP object file path
        #[arg(long)]
        xdp_object: Option<PathBuf>,

        /// TCP listen address
        #[arg(long, default_value = "127.0.0.1:1080")]
        tcp_listen: String,

        /// UDP listen address
        #[arg(long, default_value = "127.0.0.1:1080")]
        udp_listen: String,

        /// Connection timeout in seconds
        #[arg(long, default_value = "60")]
        connection_timeout: u64,

        /// UDP session timeout in seconds
        #[arg(long, default_value = "30")]
        udp_timeout: u64,

        /// Disable eBPF integration
        #[arg(long)]
        no_ebpf: bool,

        /// SOCKS5 listen address (e.g., 127.0.0.1:1080) - omit to disable SOCKS5
        #[arg(long)]
        socks5_listen: Option<String>,

        /// HTTP proxy listen address (e.g., 127.0.0.1:8080) - omit to disable HTTP proxy
        #[arg(long)]
        http_listen: Option<String>,

        /// HTTP proxy authentication username (requires --http-password)
        #[arg(long, requires = "http_password")]
        http_username: Option<String>,

        /// HTTP proxy authentication password (requires --http-username)
        #[arg(long, requires = "http_username")]
        http_password: Option<String>,

        /// Enable Shadowsocks proxy mode
        #[arg(long)]
        shadowsocks: bool,

        /// Shadowsocks listen address (e.g., 127.0.0.1:1080)
        #[arg(long, default_value = "127.0.0.1:1080")]
        ss_listen: String,

        /// Shadowsocks server address (IP or domain)
        #[arg(long, requires = "shadowsocks")]
        ss_server: Option<String>,

        /// Shadowsocks server port
        #[arg(long, default_value = "8388", requires = "shadowsocks")]
        ss_port: u16,

        /// Shadowsocks encryption method (chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm)
        #[arg(long, default_value = "chacha20-ietf-poly1305", requires = "shadowsocks")]
        ss_method: String,

        /// Shadowsocks password
        #[arg(long, requires = "shadowsocks")]
        ss_password: Option<String>,

        /// Enable Shadowsocks OTA (One-Time Auth)
        #[arg(long, requires = "shadowsocks")]
        ss_ota: bool,

        /// Enable VLESS proxy mode
        #[arg(long)]
        vless: bool,

        /// VLESS listen address (e.g., 127.0.0.1:1080)
        #[arg(long, default_value = "127.0.0.1:1080", requires = "vless")]
        vless_listen: String,

        /// VLESS server address (IP or domain)
        #[arg(long, requires = "vless")]
        vless_server: Option<String>,

        /// VLESS server port
        #[arg(long, default_value = "443", requires = "vless")]
        vless_port: u16,

        /// VLESS UUID
        #[arg(long, requires = "vless")]
        vless_uuid: Option<String>,

        /// Enable VMess proxy mode
        #[arg(long)]
        vmess: bool,

        /// VMess listen address (e.g., 127.0.0.1:1080)
        #[arg(long, default_value = "127.0.0.1:1080", requires = "vmess")]
        vmess_listen: String,

        /// VMess server address (IP or domain)
        #[arg(long, requires = "vmess")]
        vmess_server: Option<String>,

        /// VMess server port
        #[arg(long, default_value = "10086", requires = "vmess")]
        vmess_port: u16,

        /// VMess security type (aes-128-gcm-aead, chacha20-poly1305-aead)
        #[arg(long, default_value = "aes-128-gcm-aead", requires = "vmess")]
        vmess_security: String,

        /// VMess User ID (UUID)
        #[arg(long, requires = "vmess")]
        vmess_user_id: Option<String>,

        /// Enable Trojan proxy mode
        #[arg(long)]
        trojan: bool,

        /// Trojan listen address (e.g., 127.0.0.1:1080)
        #[arg(long, default_value = "127.0.0.1:1080", requires = "trojan")]
        trojan_listen: String,

        /// Trojan server address (IP or domain)
        #[arg(long, requires = "trojan")]
        trojan_server: Option<String>,

        /// Trojan server port
        #[arg(long, default_value = "443", requires = "trojan")]
        trojan_port: u16,

        /// Trojan password
        #[arg(long, requires = "trojan")]
        trojan_password: Option<String>,

        /// Rules configuration file path
        #[arg(short, long)]
        rules_config: Option<String>,

        /// Run as daemon
        #[arg(long, short = 'd')]
        daemon: bool,

        /// PID file path
        #[arg(long)]
        pid_file: Option<String>,

        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        control_socket: String,
    },
    /// Show proxy status and statistics
    Status {
        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        socket: String,
    },
    /// Hot reload configuration (send SIGUSR1)
    Reload {
        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        socket: String,
    },
    /// Test connectivity to a specific node
    Test {
        /// Node name to test
        #[arg(short, long)]
        node: String,

        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        socket: String,
    },
    /// Shutdown the proxy daemon
    Shutdown {
        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        socket: String,
    },
    /// Validate configuration file
    Validate {
        /// Config file path
        #[arg(short, long)]
        config: String,
    },
    /// Run in engine mode (default)
    RunEngine {
        /// Config file path
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Rule management commands
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },
    /// Start REST API server
    Api {
        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,
        /// Host to bind to
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
    },
}

#[derive(Subcommand, Debug)]
enum RulesCommands {
    /// Reload rules from config file
    Reload {
        /// Rules config file path
        #[arg(short, long)]
        config: String,
    },
    /// List current rules
    List {
        /// Show detailed rule information
        #[arg(short, long)]
        verbose: bool,
    },
    /// Validate rules config file
    Validate {
        /// Rules config file path
        #[arg(short, long)]
        config: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    let level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(level))
        .init();

    match args.command {
        Some(Commands::Run {
            interface,
            xdp_object,
            tcp_listen,
            udp_listen,
            connection_timeout,
            udp_timeout,
            no_ebpf,
            socks5_listen,
            http_listen,
            http_username,
            http_password,
            shadowsocks,
            ss_listen,
            ss_server,
            ss_port,
            ss_method,
            ss_password,
            ss_ota,
            vless,
            vless_listen,
            vless_server,
            vless_port,
            vless_uuid,
            vmess,
            vmess_listen,
            vmess_server,
            vmess_port,
            vmess_security,
            vmess_user_id,
            trojan,
            trojan_listen,
            trojan_server,
            trojan_port,
            trojan_password,
            rules_config,
            daemon,
            pid_file,
            control_socket,
        }) => {
            // Try to load config file if specified
            let config = if let Some(ref config_path) = args.config {
                match Config::from_file(config_path) {
                    Ok(cfg) => {
                        tracing::info!("Loaded configuration from {}", config_path);
                        Some(cfg)
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load config file {}: {}", config_path, e);
                        None
                    }
                }
            } else {
                None
            };

            tracing::info!("Starting dae-rs proxy daemon...");

            // Build proxy configuration
            let tcp_addr: std::net::SocketAddr = tcp_listen.parse()?;
            let udp_addr: std::net::SocketAddr = udp_listen.parse()?;

            let mut proxy_config = ProxyConfig::default();
            proxy_config.tcp.listen_addr = tcp_addr;
            proxy_config.udp.listen_addr = udp_addr;
            proxy_config.pool.tcp_timeout = Duration::from_secs(connection_timeout);
            proxy_config.pool.udp_timeout = Duration::from_secs(udp_timeout);

            if let Some(ref iface) = interface {
                proxy_config.xdp_interface = iface.clone();
            }
            if let Some(ref obj) = xdp_object {
                proxy_config.xdp_object = obj.clone();
            }
            let ebpf_enabled = !no_ebpf;
            proxy_config.ebpf.enabled = ebpf_enabled;

            // SOCKS5 listen address
            proxy_config.socks5_listen = socks5_listen.as_ref().map(|s| s.parse().unwrap_or_else(|_| {
                tracing::warn!("Invalid SOCKS5 listen address: {}, using default", s);
                std::net::SocketAddr::from(([127, 0, 0, 1], 1080))
            }));

            // HTTP proxy listen address
            proxy_config.http_listen = http_listen.as_ref().map(|s| s.parse().unwrap_or_else(|_| {
                tracing::warn!("Invalid HTTP proxy listen address: {}, using default", s);
                std::net::SocketAddr::from(([127, 0, 0, 1], 8080))
            }));

            // HTTP proxy authentication
            if let (Some(username), Some(password)) = (http_username, http_password) {
                proxy_config.http_auth = Some((username, password));
                tracing::info!("HTTP proxy authentication enabled");
            }

            // Shadowsocks configuration
            if shadowsocks {
                let server_addr = ss_server.unwrap_or_else(|| {
                    tracing::warn!("--ss-server not specified, using default 127.0.0.1");
                    "127.0.0.1".to_string()
                });
                let password = ss_password.unwrap_or_else(|| {
                    tracing::warn!("--ss-password not specified, using empty password");
                    String::new()
                });
                let method = SsCipherType::from_str(&ss_method).unwrap_or_else(|| {
                    tracing::warn!("Invalid Shadowsocks method: {}, using chacha20-ietf-poly1305", ss_method);
                    SsCipherType::Chacha20IetfPoly1305
                });
                let ss_listen_addr: std::net::SocketAddr = ss_listen.parse().unwrap_or_else(|_| {
                    tracing::warn!("Invalid Shadowsocks listen address: {}, using 127.0.0.1:1080", ss_listen);
                    std::net::SocketAddr::from(([127, 0, 0, 1], 1080))
                });

                proxy_config.ss_listen = Some(ss_listen_addr);
                proxy_config.ss_server = Some(SsServerConfig {
                    addr: server_addr.clone(),
                    port: ss_port,
                    method,
                    password,
                    ota: ss_ota,
                });
                tracing::info!("Shadowsocks enabled: listen={}, server={}:{}, method={}, ota={}",
                    ss_listen_addr, server_addr, ss_port, method, ss_ota);
            } else {
                proxy_config.ss_listen = None;
                proxy_config.ss_server = None;
            }

            // VLESS configuration
            if vless {
                let server_addr = vless_server.unwrap_or_else(|| {
                    tracing::warn!("--vless-server not specified, using default 127.0.0.1");
                    "127.0.0.1".to_string()
                });
                let uuid = vless_uuid.unwrap_or_else(|| {
                    tracing::warn!("--vless-uuid not specified, using empty UUID");
                    String::new()
                });
                let vless_listen_addr: std::net::SocketAddr = vless_listen.parse().unwrap_or_else(|_| {
                    tracing::warn!("Invalid VLESS listen address: {}, using 127.0.0.1:1080", vless_listen);
                    std::net::SocketAddr::from(([127, 0, 0, 1], 1080))
                });

                proxy_config.vless_listen = Some(vless_listen_addr);
                proxy_config.vless_server = Some(VlessServerConfig {
                    addr: server_addr.clone(),
                    port: vless_port,
                    uuid,
                    tls: VlessTlsConfig {
                        enabled: true,
                        version: "1.3".to_string(),
                        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                        server_name: None,
                        cert_file: None,
                        key_file: None,
                        insecure: false,
                    },
                });
                tracing::info!("VLESS enabled: listen={}, server={}:{}",
                    vless_listen_addr, server_addr, vless_port);
            } else {
                proxy_config.vless_listen = None;
                proxy_config.vless_server = None;
            }

            // VMess configuration
            if vmess {
                let server_addr = vmess_server.unwrap_or_else(|| {
                    tracing::warn!("--vmess-server not specified, using default 127.0.0.1");
                    "127.0.0.1".to_string()
                });
                let user_id = vmess_user_id.unwrap_or_else(|| {
                    tracing::warn!("--vmess-user-id not specified, using empty User ID");
                    String::new()
                });
                let vmess_listen_addr: std::net::SocketAddr = vmess_listen.parse().unwrap_or_else(|_| {
                    tracing::warn!("Invalid VMess listen address: {}, using 127.0.0.1:1080", vmess_listen);
                    std::net::SocketAddr::from(([127, 0, 0, 1], 1080))
                });
                let security = VmessSecurity::from_str(&vmess_security).unwrap_or_else(|| {
                    tracing::warn!("Invalid VMess security: {}, using aes-128-gcm-aead", vmess_security);
                    VmessSecurity::Aes128GcmAead
                });

                proxy_config.vmess_listen = Some(vmess_listen_addr);
                proxy_config.vmess_server = Some(VmessServerConfig {
                    addr: server_addr.clone(),
                    port: vmess_port,
                    user_id,
                    security,
                    enable_aead: true,
                });
                tracing::info!("VMess enabled: listen={}, server={}:{}, security={}",
                    vmess_listen_addr, server_addr, vmess_port, security);
            } else {
                proxy_config.vmess_listen = None;
                proxy_config.vmess_server = None;
            }

            // Trojan configuration
            if trojan {
                let server_addr = trojan_server.unwrap_or_else(|| {
                    tracing::warn!("--trojan-server not specified, using default 127.0.0.1");
                    "127.0.0.1".to_string()
                });
                let password = trojan_password.unwrap_or_else(|| {
                    tracing::warn!("--trojan-password not specified, using empty password");
                    String::new()
                });
                let trojan_listen_addr: std::net::SocketAddr = trojan_listen.parse().unwrap_or_else(|_| {
                    tracing::warn!("Invalid Trojan listen address: {}, using 127.0.0.1:1080", trojan_listen);
                    std::net::SocketAddr::from(([127, 0, 0, 1], 1080))
                });

                proxy_config.trojan_listen = Some(trojan_listen_addr);
                proxy_config.trojan_server = Some(TrojanServerConfig {
                    addr: server_addr.clone(),
                    port: trojan_port,
                    password,
                    tls: TrojanTlsConfig {
                        enabled: true,
                        version: "1.3".to_string(),
                        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                        server_name: None,
                        cert_file: None,
                        key_file: None,
                        insecure: false,
                    },
                });
                tracing::info!("Trojan enabled: listen={}, server={}:{}",
                    trojan_listen_addr, server_addr, trojan_port);
            } else {
                proxy_config.trojan_listen = None;
                proxy_config.trojan_server = None;
            }

            // Log config
            tracing::info!("Proxy configuration:");
            tracing::info!("  TCP listen: {}", proxy_config.tcp.listen_addr);
            tracing::info!("  UDP listen: {}", proxy_config.udp.listen_addr);
            tracing::info!("  XDP interface: {}", proxy_config.xdp_interface);
            tracing::info!("  XDP object: {}", proxy_config.xdp_object.display());
            if let Some(ref socks5) = proxy_config.socks5_listen {
                tracing::info!("  SOCKS5 listen: {}", socks5);
            } else {
                tracing::info!("  SOCKS5 listen: disabled");
            }
            if let Some(ref http) = proxy_config.http_listen {
                tracing::info!("  HTTP proxy listen: {}", http);
            } else {
                tracing::info!("  HTTP proxy listen: disabled");
            }
            if let Some(ref ss) = proxy_config.ss_listen {
                tracing::info!("  Shadowsocks listen: {}", ss);
            } else {
                tracing::info!("  Shadowsocks: disabled");
            }
            tracing::info!("  eBPF enabled: {}", ebpf_enabled);
            tracing::info!("  Control socket: {}", control_socket);

            // Rules configuration
            if let Some(ref rules_cfg) = rules_config {
                tracing::info!("  Rules config: {}", rules_cfg);
            } else {
                tracing::info!("  Rules config: not specified");
            }

            // Write PID file if requested
            if let Some(ref pid_path) = pid_file {
                if let Some(parent) = std::path::Path::new(pid_path).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(pid_path, std::process::id().to_string())?;
                tracing::info!("PID file written to {}", pid_path);
            }

            // Create control server
            let control_server = Arc::new(ControlServer::new(&control_socket));
            let control_state = control_server.state();

            // Start control server
            let control_server_clone = control_server.clone();
            tokio::spawn(async move {
                if let Err(e) = control_server_clone.start().await {
                    tracing::error!("Control server error: {}", e);
                }
            });

            // Create and start proxy
            let proxy = Proxy::new(proxy_config).await?;
            let proxy = Arc::new(proxy);

            // Set running state
            control_state.set_running(true).await;

            // Run with signal handling
            run_proxy_with_signals(proxy, control_state).await?;
        }
        Some(Commands::Status { socket }) => {
            match connect_and_send(&socket, "status").await {
                Ok(response) => {
                    println!("{}", response);
                }
                Err(e) => {
                    eprintln!("Error connecting to control socket: {}", e);
                    eprintln!("Is the daemon running?");
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Reload { socket }) => {
            match connect_and_send(&socket, "reload").await {
                Ok(response) => {
                    println!("{}", response);
                }
                Err(e) => {
                    eprintln!("Error connecting to control socket: {}", e);
                    eprintln!("Is the daemon running?");
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Test { node, socket }) => {
            let command = format!("test {}", node);
            match connect_and_send(&socket, &command).await {
                Ok(response) => {
                    println!("{}", response);
                }
                Err(e) => {
                    eprintln!("Error connecting to control socket: {}", e);
                    eprintln!("Is the daemon running?");
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Shutdown { socket }) => {
            match connect_and_send(&socket, "shutdown").await {
                Ok(response) => {
                    println!("{}", response);
                }
                Err(e) => {
                    eprintln!("Error connecting to control socket: {}", e);
                    eprintln!("Is the daemon running?");
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Validate { config }) => {
            match Config::from_file(&config) {
                Ok(cfg) => {
                    match cfg.validate() {
                        Ok(_) => {
                            println!("Configuration file '{}' is valid", config);
                            println!("  SOCKS5 listen: {}", cfg.proxy.socks5_listen);
                            println!("  HTTP listen: {}", cfg.proxy.http_listen);
                            println!("  eBPF interface: {}", cfg.proxy.ebpf_interface);
                            println!("  Nodes configured: {}", cfg.nodes.len());
                            if let Some(ref rules_file) = cfg.rules.config_file {
                                println!("  Rules file: {}", rules_file);
                            }
                        }
                        Err(e) => {
                            eprintln!("Configuration validation failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse configuration: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Api { port, host: _host }) => {
            tracing::info!("Starting REST API server on port {}", port);
            let server = ApiServer::new(port).await;
            if let Err(e) = server.start().await {
                eprintln!("API server error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::RunEngine { config }) => {
            tracing::info!("dae-rs starting in engine mode...");
            tracing::info!("dae-rs running with config: {}", config);

            let engine = Engine::new();
            engine.start().await;

            // Keep running with signal handling
            run_engine_with_signals(engine).await;
        }
        None => {
            tracing::info!("dae-rs starting in engine mode...");

            let engine = Engine::new();
            engine.start().await;

            // Keep running with signal handling
            run_engine_with_signals(engine).await;
        }
        Some(Commands::Rules { command }) => {
            match command {
                RulesCommands::Reload { config } => {
                    tracing::info!("dae-rs rules reload from: {}", config);
                    
                    let rule_engine = new_rule_engine(RuleEngineConfig::default());
                    if let Err(e) = rule_engine.load_rules(&config).await {
                        eprintln!("Failed to load rules: {}", e);
                        std::process::exit(1);
                    }
                    
                    tracing::info!("Rules reloaded successfully");
                }
                RulesCommands::List { verbose } => {
                    tracing::info!("dae-rs rules list");
                    
                    // Create a temporary rule engine to show stats
                    let rule_engine = new_rule_engine(RuleEngineConfig::default());
                    let stats = rule_engine.get_stats().await;
                    
                    println!("Rule Engine Status:");
                    println!("  Loaded: {}", stats.loaded);
                    println!("  Rule Groups: {}", stats.rule_group_count);
                    println!("  Total Rules: {}", stats.total_rule_count);
                    
                    if verbose {
                        println!("\nRule Groups:");
                        for name in rule_engine.get_rule_groups().await.iter() {
                            println!("  - {}", name);
                        }
                    }
                }
                RulesCommands::Validate { config } => {
                    tracing::info!("dae-rs rules validate: {}", config);
                    
                    use dae_config::rules::parse_and_validate;
                    use std::fs;
                    
                    let content = match fs::read_to_string(&config) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Failed to read rules config: {}", e);
                            std::process::exit(1);
                        }
                    };
                    
                    match parse_and_validate(&content) {
                        Ok(cfg) => {
                            println!("Rules configuration is valid!");
                            println!("  Rule Groups: {}", cfg.rule_groups.len());
                            let total_rules: usize = cfg.rule_groups.iter().map(|g| g.rules.len()).sum();
                            println!("  Total Rules: {}", total_rules);
                        }
                        Err((_, errors)) => {
                            eprintln!("Rules configuration has errors:");
                            for error in errors.iter() {
                                eprintln!("  - {}", error);
                            }
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Run proxy with graceful shutdown on SIGTERM/SIGINT/SIGUSR1
async fn run_proxy_with_signals(proxy: Arc<Proxy>, control_state: Arc<ControlState>) -> std::io::Result<()> {
    // Spawn proxy task
    let proxy_for_handle = proxy.clone();
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy_for_handle.start().await {
            tracing::error!("Proxy error: {}", e);
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        result = proxy_handle => {
            if let Err(e) = result {
                tracing::error!("Proxy task panicked: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down gracefully...");
            control_state.set_running(false).await;
            proxy.stop().await;
        }
    }

    // Wait a bit for graceful cleanup
    tokio::time::sleep(Duration::from_secs(1)).await;

    tracing::info!("Proxy shutdown complete");
    Ok(())
}

/// Run engine with signal handling
async fn run_engine_with_signals(mut engine: Engine) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down...");
        }
    }

    engine.stop().await;
    tracing::info!("dae-rs shutting down");
}
