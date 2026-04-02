//! dae-ebpf - User-space eBPF loader for dae-rs
//!
//! This program loads the XDP eBPF program and manages the eBPF maps.
//!
//! # Architecture
//!
//! The eBPF infrastructure consists of:
//! - `dae-ebpf-common`: Shared types between kernel and user space
//! - `dae-xdp`: The XDP eBPF program (runs in kernel space)
//! - `dae-ebpf`: The user-space loader (runs in user space, loads and manages eBPF maps)

#![deny(warnings)]

mod loader;
mod maps;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// dae-rs eBPF loader arguments
#[derive(Parser, Debug)]
#[command(name = "dae-ebpf")]
#[command(about = "User-space eBPF loader for dae-rs")]
struct Args {
    /// Network interface to attach XDP to
    #[arg(short, long)]
    interface: String,

    /// Path to the XDP object file
    #[arg(short, long, default_value = "dae-xdp.o")]
    xdp_object: String,

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

    info!("dae-ebpf loader starting");
    info!("Loading XDP program on interface: {}", args.interface);

    // Check if the XDP object file exists
    let path = std::path::Path::new(&args.xdp_object);
    if !path.exists() {
        // For now, just print a message since we don't have the full build setup yet
        info!(
            "XDP object file '{}' not found. To build the XDP program, use:",
            args.xdp_object
        );
        info!("1. Install aya-ebpf-builder or use cargo-bpf");
        info!("2. Build the dae-xdp crate targeting bpfEL");
        info!("The user-space loader structure is in place.");
        return Ok(());
    }

    // Load and attach the XDP program
    let mut loader = loader::EbpfLoader::new()?;

    match loader.load(&args.interface, &args.xdp_object).await {
        Ok(_) => {
            info!("XDP program loaded successfully");
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
            error!("Failed to load XDP program: {}", e);
            Err(e)
        }
    }
}
