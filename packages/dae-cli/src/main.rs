//! dae-rs CLI entry point

use clap::{Parser, Subcommand};
use dae_proxy::{Proxy, ProxyConfig};
use dae_proxy::shadowsocks::{SsCipherType, SsServerConfig};
use dae_proxy::vless::{VlessServerConfig, VlessTlsConfig};
use dae_proxy::vmess::{VmessServerConfig, VmessSecurity};
use dae_proxy::trojan::{TrojanServerConfig, TrojanTlsConfig};
use dae_core::Engine;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "dae-rs")]
#[command(version, about = "High-performance transparent proxy in Rust")]
struct Args {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Config file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the proxy daemon
    Proxy {
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
    },
    /// Run in engine mode (default)
    Run {
        /// Config file path
        #[arg(short, long, default_value = "config.toml")]
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
        Some(Commands::Proxy {
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
        }) => {
            tracing::info!("Starting dae-rs proxy mode...");

            // Build proxy configuration
            let tcp_addr: std::net::SocketAddr = tcp_listen.parse()?;
            let udp_addr: std::net::SocketAddr = udp_listen.parse()?;

            let mut config = ProxyConfig::default();
            config.tcp.listen_addr = tcp_addr;
            config.udp.listen_addr = udp_addr;
            config.pool.tcp_timeout = Duration::from_secs(connection_timeout);
            config.pool.udp_timeout = Duration::from_secs(udp_timeout);

            if let Some(ref iface) = interface {
                config.xdp_interface = iface.clone();
            }
            if let Some(ref obj) = xdp_object {
                config.xdp_object = obj.clone();
            }
            let ebpf_enabled = !no_ebpf;
            config.ebpf.enabled = ebpf_enabled;

            // SOCKS5 listen address
            config.socks5_listen = socks5_listen.as_ref().map(|s| s.parse().unwrap_or_else(|_| {
                tracing::warn!("Invalid SOCKS5 listen address: {}, using default", s);
                std::net::SocketAddr::from(([127, 0, 0, 1], 1080))
            }));

            // HTTP proxy listen address
            config.http_listen = http_listen.as_ref().map(|s| s.parse().unwrap_or_else(|_| {
                tracing::warn!("Invalid HTTP proxy listen address: {}, using default", s);
                std::net::SocketAddr::from(([127, 0, 0, 1], 8080))
            }));

            // HTTP proxy authentication
            if let (Some(username), Some(password)) = (http_username, http_password) {
                config.http_auth = Some((username, password));
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

                config.ss_listen = Some(ss_listen_addr);
                config.ss_server = Some(SsServerConfig {
                    addr: server_addr.clone(),
                    port: ss_port,
                    method,
                    password,
                    ota: ss_ota,
                });
                tracing::info!("Shadowsocks enabled: listen={}, server={}:{}, method={}, ota={}",
                    ss_listen_addr, server_addr, ss_port, method, ss_ota);
            } else {
                config.ss_listen = None;
                config.ss_server = None;
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

                config.vless_listen = Some(vless_listen_addr);
                config.vless_server = Some(VlessServerConfig {
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
                config.vless_listen = None;
                config.vless_server = None;
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

                config.vmess_listen = Some(vmess_listen_addr);
                config.vmess_server = Some(VmessServerConfig {
                    addr: server_addr.clone(),
                    port: vmess_port,
                    user_id,
                    security,
                    enable_aead: true,
                });
                tracing::info!("VMess enabled: listen={}, server={}:{}, security={}",
                    vmess_listen_addr, server_addr, vmess_port, security);
            } else {
                config.vmess_listen = None;
                config.vmess_server = None;
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

                config.trojan_listen = Some(trojan_listen_addr);
                config.trojan_server = Some(TrojanServerConfig {
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
                config.trojan_listen = None;
                config.trojan_server = None;
            }

            // Log config before moving
            tracing::info!("Proxy configuration:");
            tracing::info!("  TCP listen: {}", config.tcp.listen_addr);
            tracing::info!("  UDP listen: {}", config.udp.listen_addr);
            tracing::info!("  XDP interface: {}", config.xdp_interface);
            tracing::info!("  XDP object: {}", config.xdp_object.display());
            if let Some(ref socks5) = config.socks5_listen {
                tracing::info!("  SOCKS5 listen: {}", socks5);
            } else {
                tracing::info!("  SOCKS5 listen: disabled");
            }
            if let Some(ref http) = config.http_listen {
                tracing::info!("  HTTP proxy listen: {}", http);
            } else {
                tracing::info!("  HTTP proxy listen: disabled");
            }
            if let Some(ref ss) = config.ss_listen {
                tracing::info!("  Shadowsocks listen: {}", ss);
            } else {
                tracing::info!("  Shadowsocks: disabled");
            }
            tracing::info!("  eBPF enabled: {}", ebpf_enabled);

            // Create and start proxy
            let proxy = Proxy::new(config).await?;
            let proxy = std::sync::Arc::new(proxy);

            // Run with signal handling
            run_proxy_with_signals(proxy).await?;
        }
        Some(Commands::Run { config }) => {
            tracing::info!("dae-rs starting in engine mode...");
            tracing::info!("dae-rs running with config: {}", config);

            let engine = Engine::new();
            engine.start().await;

            // Keep running
            tokio::signal::ctrl_c().await?;

            engine.stop().await;
            tracing::info!("dae-rs shutting down");
        }
        None => {
            tracing::info!("dae-rs starting in engine mode...");

            let engine = Engine::new();
            engine.start().await;

            // Keep running
            tokio::signal::ctrl_c().await?;

            engine.stop().await;
            tracing::info!("dae-rs shutting down");
        }
    }

    Ok(())
}

/// Run proxy with graceful shutdown on SIGTERM/SIGINT
async fn run_proxy_with_signals(proxy: std::sync::Arc<Proxy>) -> std::io::Result<()> {
    use tokio::signal;

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
            tracing::info!("Received Ctrl+C, shutting down...");
            proxy.stop().await;
        }
    }

    Ok(())
}
