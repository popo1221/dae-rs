//! dae-rs CLI entry point
//!
//! High-performance transparent proxy in Rust with eBPF integration
//!
//! # Simplified CLI Design
//!
//! All protocol configuration is in the config file. CLI is just for:
//! - `dae run <config.toml>` - Run proxy
//! - `dae status` - Check status
//! - `dae validate <config>` - Validate config
//! - `dae reload` - Hot reload
//! - `dae shutdown` - Stop daemon

use clap::{Parser, Subcommand};
use dae_config::{Config, NodeType};
use dae_proxy::{
    control::{connect_and_send, ControlServer},
    new_dns_hijacker,
    shadowsocks::{SsCipherType, SsServerConfig},
    trojan_protocol::{TrojanServerConfig, TrojanTlsConfig},
    tun::{TunConfig, TunProxy},
    vless::{VlessServerConfig, VlessTlsConfig},
    vmess::{VmessSecurity, VmessServerConfig},
    Proxy, ProxyConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "dae")]
#[command(
    version = "0.1.0",
    about = "dae-rs - High-performance transparent proxy"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run proxy with configuration file
    Run {
        /// Configuration file path (TOML)
        #[arg(short, long)]
        config: PathBuf,

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
    /// Show daemon status
    Status {
        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        socket: String,
    },
    /// Hot reload configuration
    Reload {
        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        socket: String,
    },
    /// Test a specific node
    Test {
        /// Node name to test
        #[arg(short, long)]
        node: String,

        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        socket: String,
    },
    /// Stop the daemon
    Shutdown {
        /// Control socket path
        #[arg(long, default_value = "/var/run/dae/control.sock")]
        socket: String,
    },
    /// Validate configuration file
    Validate {
        /// Config file path
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("dae_rs=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            daemon,
            pid_file,
            control_socket,
        } => {
            run_proxy(config, daemon, pid_file, control_socket).await?;
        }
        Commands::Status { socket } => {
            let response = connect_and_send(&socket, "status").await?;
            println!("{response}");
        }
        Commands::Reload { socket } => {
            let response = connect_and_send(&socket, "reload").await?;
            println!("{response}");
        }
        Commands::Test { node, socket } => {
            let cmd = format!("test:{node}");
            let response = connect_and_send(&socket, &cmd).await?;
            println!("{response}");
        }
        Commands::Shutdown { socket } => {
            let response = connect_and_send(&socket, "shutdown").await?;
            println!("{response}");
        }
        Commands::Validate { config } => match Config::from_file(config.to_str().unwrap_or("")) {
            Ok(cfg) => match cfg.validate() {
                Ok(_) => {
                    println!("✓ Configuration '{config:?}' is valid");
                    println!(
                        "  Listen: {} (SOCKS5), {} (HTTP)",
                        cfg.proxy.socks5_listen, cfg.proxy.http_listen
                    );
                    println!(
                        "  eBPF: {} (enabled={})",
                        cfg.proxy.ebpf_interface, cfg.proxy.ebpf_enabled
                    );
                    println!("  Nodes: {}", cfg.nodes.len());
                    if let Some(ref rules) = cfg.rules.config_file {
                        println!("  Rules: {rules}");
                    }
                }
                Err(e) => {
                    eprintln!("✗ Validation failed: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("✗ Failed to parse config: {e}");
                std::process::exit(1);
            }
        },
    }

    Ok(())
}

async fn run_proxy(
    config: PathBuf,
    daemon: bool,
    pid_file: Option<String>,
    control_socket: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = config.to_str().unwrap_or("");
    let loaded_config = Config::from_file(config_str)?;
    loaded_config.validate()?;

    tracing::info!("Loaded config from {:?}", config);

    // Build ProxyConfig from Config
    let mut proxy_config = ProxyConfig::default();

    // Parse listen addresses
    if let Ok(addr) = loaded_config.proxy.socks5_listen.parse::<SocketAddr>() {
        proxy_config.socks5_listen = Some(addr);
    }
    if let Ok(addr) = loaded_config.proxy.http_listen.parse::<SocketAddr>() {
        proxy_config.http_listen = Some(addr);
    }

    // eBPF settings
    proxy_config.ebpf.enabled = loaded_config.proxy.ebpf_enabled;
    proxy_config.xdp_interface = loaded_config.proxy.ebpf_interface.clone();

    // Save timeouts for TUN before proxy_config is moved
    let tcp_timeout = Duration::from_secs(loaded_config.proxy.tcp_timeout);
    let udp_timeout = Duration::from_secs(loaded_config.proxy.udp_timeout);

    // Transparent proxy (TUN) settings
    let tun_config = if loaded_config.transparent_proxy.enabled {
        Some(TunConfig {
            enabled: true,
            interface: loaded_config.transparent_proxy.tun_interface.clone(),
            tun_ip: loaded_config.transparent_proxy.tun_ip.clone(),
            tun_netmask: loaded_config.transparent_proxy.tun_netmask.clone(),
            mtu: loaded_config.transparent_proxy.mtu,
            dns_hijack: loaded_config
                .transparent_proxy
                .dns_hijack
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            tcp_timeout: Duration::from_secs(loaded_config.transparent_proxy.tcp_timeout),
            udp_timeout: Duration::from_secs(loaded_config.transparent_proxy.udp_timeout),
            ..Default::default()
        })
    } else {
        None
    };

    // Timeouts
    proxy_config.pool.tcp_timeout = Duration::from_secs(loaded_config.proxy.tcp_timeout);
    proxy_config.pool.udp_timeout = Duration::from_secs(loaded_config.proxy.udp_timeout);

    // Build protocol servers from nodes
    for node in &loaded_config.nodes {
        let server_addr = node.server.clone();
        let port = node.port;

        match node.node_type {
            NodeType::Trojan => {
                if let Some(ref password) = node.trojan_password {
                    proxy_config.trojan_listen = Some(
                        "127.0.0.1:1080"
                            .parse()
                            .expect("invalid hardcoded trojan listen address"),
                    );
                    proxy_config.trojan_server = Some(TrojanServerConfig {
                        addr: server_addr,
                        port,
                        password: password.clone(),
                        tls: TrojanTlsConfig::default(),
                    });
                }
            }
            NodeType::Shadowsocks => {
                if let Some(ref password) = node.password {
                    let method_str = node.method.as_deref().unwrap_or("chacha20-ietf-poly1305");
                    let method = SsCipherType::from_str(method_str)
                        .unwrap_or(SsCipherType::Chacha20IetfPoly1305);

                    proxy_config.ss_listen = Some(
                        "127.0.0.1:1080"
                            .parse()
                            .expect("invalid hardcoded shadowsocks listen address"),
                    );
                    proxy_config.ss_server = Some(SsServerConfig {
                        addr: server_addr,
                        port,
                        method,
                        password: password.clone(),
                        ota: false,
                    });
                }
            }
            NodeType::Vless => {
                if let Some(ref uuid) = node.uuid {
                    proxy_config.vless_listen = Some(
                        "127.0.0.1:1080"
                            .parse()
                            .expect("invalid hardcoded vless listen address"),
                    );
                    proxy_config.vless_server = Some(VlessServerConfig {
                        addr: server_addr,
                        port,
                        uuid: uuid.clone(),
                        tls: VlessTlsConfig::default(),
                        reality: None,
                    });
                }
            }
            NodeType::Vmess => {
                if let Some(ref uuid) = node.uuid {
                    let security_str = node.security.as_deref().unwrap_or("aes-128-gcm-aead");
                    let security = VmessSecurity::from_str(security_str)
                        .unwrap_or(VmessSecurity::Aes128GcmAead);

                    proxy_config.vmess_listen = Some(
                        "127.0.0.1:1080"
                            .parse()
                            .expect("invalid hardcoded vmess listen address"),
                    );
                    proxy_config.vmess_server = Some(VmessServerConfig {
                        addr: server_addr,
                        port,
                        user_id: uuid.clone(),
                        security,
                        enable_aead: true,
                    });
                }
            }
        }
    }

    // Tracking configuration
    proxy_config.tracking = loaded_config.tracking.clone();

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
    let proxy = Arc::new(Proxy::new(proxy_config).await?);

    // Create TUN proxy if enabled
    // TunProxy requires: config, rule_engine, connection_pool, dns_hijacker
    let tun_proxy: Option<Arc<TunProxy>> = if let Some(ref tun_cfg) = tun_config {
        tracing::info!(
            "Initializing TUN transparent proxy: {} ({}/{})",
            tun_cfg.tun_ip,
            tun_cfg.tun_netmask,
            tun_cfg.interface
        );

        // Create DNS hijacker with upstream servers
        let dns_upstream: Vec<std::net::SocketAddr> = loaded_config
            .transparent_proxy
            .dns_upstream
            .iter()
            .filter_map(|s| {
                // Parse "8.8.8.8:53" format
                if let Ok(addr) = s.parse() {
                    Some(addr)
                } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                    Some(std::net::SocketAddr::new(ip, 53))
                } else {
                    None
                }
            })
            .collect();

        let dns_hijacker = new_dns_hijacker(dns_upstream);

        // Create rule engine
        let rule_engine = dae_proxy::new_rule_engine(Default::default());

        // Create shared connection pool
        let connection_pool = dae_proxy::connection_pool::new_connection_pool(
            tcp_timeout,
            udp_timeout,
            Duration::from_secs(30), // tcp_keepalive
        );

        Some(Arc::new(TunProxy::new(
            tun_cfg.clone(),
            rule_engine,
            connection_pool,
            dns_hijacker,
        )))
    } else {
        None
    };

    if daemon {
        if let Some(ref pid_path) = pid_file {
            std::fs::write(pid_path, std::process::id().to_string())?;
            tracing::info!("Daemon started, PID: {}", std::process::id());
        }
    }

    // Spawn proxy task
    let proxy_clone = proxy.clone();
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy_clone.start().await {
            tracing::error!("Proxy error: {}", e);
        }
    });

    // Spawn TUN proxy task if enabled
    let tun_proxy_clone = tun_proxy.clone();
    let tun_handle = if tun_proxy.is_some() {
        tracing::info!("Starting TUN proxy task...");
        Some(tokio::spawn(async move {
            if let Some(ref tun) = tun_proxy_clone {
                if let Err(e) = tun.start().await {
                    tracing::error!("TUN proxy error: {}", e);
                }
            }
        }))
    } else {
        None
    };

    // Wait for shutdown
    tokio::select! {
        result = proxy_handle => {
            if let Err(e) = result {
                tracing::error!("Proxy task panicked: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            tracing::info!("Shutting down...");
            control_state.set_running(false).await;
            proxy.stop().await;
        }
    }

    // Wait for TUN handle to finish
    if let Some(h) = tun_handle {
        let _ = h.await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    tracing::info!("Proxy stopped");
    Ok(())
}
