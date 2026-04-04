//! dae-ebpf - User-space eBPF loader for dae-rs
//!
//! This program loads the XDP or TC eBPF program and manages the eBPF maps.
//!
//! # Architecture
//!
//! The eBPF infrastructure consists of:
//! - `dae-ebpf-common`: Shared types between kernel and user space
//! - `dae-xdp`: The XDP eBPF program (runs in kernel space, fast but limited)
//! - `dae-tc`: The TC eBPF program (runs at traffic control, more flexible)
//! - `dae-ebpf`: The user-space loader (runs in user space, loads and manages eBPF maps)

#![deny(warnings)]

mod loader;
mod maps;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// eBPF program type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgramType {
    /// XDP (Express Data Path) - faster, earlier in packet path
    #[default]
    Xdp,
    /// TC (Traffic Control) - more features, later in packet path
    Tc,
}

impl std::fmt::Display for ProgramType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgramType::Xdp => write!(f, "XDP"),
            ProgramType::Tc => write!(f, "TC"),
        }
    }
}

impl std::str::FromStr for ProgramType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "xdp" => Ok(ProgramType::Xdp),
            "tc" => Ok(ProgramType::Tc),
            _ => Err(format!("Unknown program type: {}. Use 'xdp' or 'tc'.", s)),
        }
    }
}

/// dae-rs eBPF loader arguments
#[derive(Parser, Debug)]
#[command(name = "dae-ebpf")]
#[command(about = "User-space eBPF loader for dae-rs")]
struct Args {
    /// Network interface to attach eBPF program to
    #[arg(short, long)]
    interface: String,

    /// Path to the eBPF object file (xdp_prog_main or tc_prog_main)
    #[arg(short, long)]
    object: Option<String>,

    /// eBPF program type (xdp or tc)
    #[arg(short, long, value_enum, default_value = "xdp")]
    program_type: ProgramType,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse arguments
    let args = Args::parse();

    // Initialize logging
    let filter = match args.verbose {
        0 => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        1 => EnvFilter::new("info,dae_ebpf=debug"),
        2 => EnvFilter::new("debug,dae_ebpf=trace"),
        _ => EnvFilter::new("trace"),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    // Determine object file path
    let object = args.object.unwrap_or_else(|| match args.program_type {
        ProgramType::Xdp => "dae-xdp.o".to_string(),
        ProgramType::Tc => "dae-tc.o".to_string(),
    });

    info!("dae-ebpf loader starting");
    info!(
        "Loading {} program on interface: {}",
        args.program_type, args.interface
    );

    // Check if the object file exists
    let path = std::path::Path::new(&object);
    if !path.exists() {
        info!(
            "{} object file '{}' not found. To build the eBPF program, use:",
            args.program_type, object
        );
        match args.program_type {
            ProgramType::Xdp => {
                info!("1. Install aya-ebpf-builder or use cargo-bpf");
                info!("2. Build the dae-xdp crate targeting bpfEL");
            }
            ProgramType::Tc => {
                info!("1. Install aya-ebpf-builder or use cargo-bpf");
                info!("2. Build the dae-tc crate targeting bpfEL");
            }
        }
        info!("The user-space loader structure is in place.");
        return Ok(());
    }

    // Load and attach the eBPF program
    let mut loader = loader::EbpfLoader::new()?;

    let result = match args.program_type {
        ProgramType::Xdp => loader.load_xdp(&args.interface, &object).await,
        ProgramType::Tc => loader.load_tc(&args.interface, &object).await,
    };

    match result {
        Ok(_) => {
            info!("{} program loaded successfully", args.program_type);
            info!("eBPF maps created and initialized");

            // Keep the program running
            info!("Press Ctrl+C to stop");

            // Wait for shutdown signal
            tokio::signal::ctrl_c().await?;

            info!("Shutting down...");
            loader.unload().await?;
            Ok(())
        }
        Err(e) => {
            error!("Failed to load {} program: {}", args.program_type, e);
            Err(e)
        }
    }
}
