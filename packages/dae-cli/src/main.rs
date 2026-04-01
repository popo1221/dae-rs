//! dae-rs CLI entry point

use clap::Parser;
use dae_core::Engine;
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

    tracing::info!("dae-rs starting...");

    let engine = Engine::new();
    engine.start().await;

    tracing::info!("dae-rs running with config: {}", args.config);

    // Keep running
    tokio::signal::ctrl_c().await?;

    engine.stop().await;
    tracing::info!("dae-rs shutting down");

    Ok(())
}
