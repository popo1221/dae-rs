//! eBPF program loader
//!
//! Handles loading the XDP program and initializing maps.

use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use std::path::Path;
use tracing::{debug, info};

use crate::maps::MapManager;

/// eBPF loader for dae-rs
pub struct EbpfLoader {
    /// The loaded eBPF instance
    ebpf: Option<Ebpf>,
    /// Map manager for eBPF maps
    maps: MapManager,
}

impl EbpfLoader {
    /// Create a new eBPF loader
    pub fn new() -> Result<Self> {
        Ok(Self {
            ebpf: None,
            maps: MapManager::new(),
        })
    }

    /// Load the XDP program onto an interface
    pub async fn load(&mut self, interface: &str, xdp_object: &str) -> Result<()> {
        // Load the eBPF object file
        let path = Path::new(xdp_object);
        if !path.exists() {
            anyhow::bail!(
                "XDP object file not found: {xdp_object}. Build the dae-xdp crate first."
            );
        }

        debug!("Loading eBPF object from: {}", xdp_object);

        // Load eBPF programs using aya
        let mut ebpf = Ebpf::load_file(path).context("Failed to load eBPF object file")?;

        // Get the XDP program
        let prog: &mut Xdp = ebpf
            .program_mut("xdp_prog_main")
            .context("Failed to find 'xdp_prog_main' in eBPF object")?
            .try_into()?;

        // Load the program
        prog.load().context("Failed to load XDP program")?;

        // Attach to the interface
        info!("Attaching XDP to interface: {}", interface);
        prog.attach(interface, XdpFlags::default())
            .context("Failed to attach XDP program")?;

        // Initialize maps
        self.maps.init(&ebpf)?;

        // Initialize default routing rules
        self.maps.init_default_routes()?;

        self.ebpf = Some(ebpf);
        info!("eBPF loader initialization complete");

        Ok(())
    }

    /// Unload the eBPF program
    pub async fn unload(&mut self) -> Result<()> {
        if let Some(_ebpf) = self.ebpf.take() {
            debug!("Unloading eBPF programs");
            // The eBPF programs will be unloaded when the Ebpf object is dropped
        }
        Ok(())
    }

    /// Get the map manager for runtime map updates
    #[allow(dead_code)]
    pub fn maps(&mut self) -> &mut MapManager {
        &mut self.maps
    }
}
