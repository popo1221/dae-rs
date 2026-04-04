//! eBPF program loader
//!
//! Handles loading the XDP or TC program and initializing maps.

use anyhow::{Context, Result};
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::maps::MapManager;

/// eBPF program type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfProgramType {
    /// XDP (Express Data Path) program
    #[default]
    Xdp,
    /// TC (Traffic Control) clsact program
    Tc,
}

/// eBPF loader for dae-rs
pub struct EbpfLoader {
    /// The loaded eBPF instance
    ebpf: Option<Ebpf>,
    /// Map manager for eBPF maps
    maps: MapManager,
    /// Program type being used
    program_type: EbpfProgramType,
}

impl EbpfLoader {
    /// Create a new eBPF loader
    pub fn new() -> Result<Self> {
        Ok(Self {
            ebpf: None,
            maps: MapManager::new(),
            program_type: EbpfProgramType::default(),
        })
    }

    /// Load the XDP program onto an interface
    pub async fn load_xdp(&mut self, interface: &str, xdp_object: &str) -> Result<()> {
        // Load the eBPF object file
        let path = Path::new(xdp_object);
        if !path.exists() {
            anyhow::bail!(
                "XDP object file not found: {xdp_object}. Build the dae-xdp crate first."
            );
        }

        debug!("Loading XDP eBPF object from: {}", xdp_object);

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
        self.program_type = EbpfProgramType::Xdp;
        info!("XDP eBPF loader initialization complete");

        Ok(())
    }

    /// Load the TC program onto an interface
    ///
    /// This attaches a tc clsact qdisc and the eBPF program to the specified interface.
    /// TC programs run at a later point in the packet pipeline than XDP, allowing for
    /// more complex processing but with slightly higher overhead.
    pub async fn load_tc(&mut self, interface: &str, tc_object: &str) -> Result<()> {
        // Load the eBPF object file
        let path = Path::new(tc_object);
        if !path.exists() {
            anyhow::bail!(
                "TC object file not found: {tc_object}. Build the dae-tc crate first."
            );
        }

        debug!("Loading TC eBPF object from: {}", tc_object);

        // Load eBPF programs using aya
        let mut ebpf = Ebpf::load_file(path).context("Failed to load eBPF object file")?;

        // First, setup clsact qdisc on the interface
        self.setup_clsact(interface).await?;

        // Get the TC program (SchedClassifier)
        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_prog_main")
            .context("Failed to find 'tc_prog_main' in eBPF object")?
            .try_into()?;

        // Load the program
        prog.load().context("Failed to load TC program")?;

        // Attach to the interface as ingress filter
        info!("Attaching TC to interface: {} (clsact ingress)", interface);
        prog.attach(interface, TcAttachType::Ingress)
            .context("Failed to attach TC program")?;

        // Initialize maps
        self.maps.init(&ebpf)?;

        // Initialize default routing rules
        self.maps.init_default_routes()?;

        self.ebpf = Some(ebpf);
        self.program_type = EbpfProgramType::Tc;
        info!("TC eBPF loader initialization complete");

        Ok(())
    }

    /// Setup clsact qdisc on the interface
    async fn setup_clsact(&self, interface: &str) -> Result<()> {
        // Use the tc helper function from aya
        match tc::qdisc_add_clsact(interface) {
            Ok(_) => {
                info!("clsact qdisc setup complete on {}", interface);
            }
            Err(e) => {
                // Check if it's already attached error - ignore it
                let err_str = format!("{e}");
                if err_str.contains("File exists") || err_str.contains("AlreadyExists") {
                    debug!("clsact qdisc already exists on {}", interface);
                } else {
                    warn!("Failed to setup clsact (may already exist): {}", e);
                }
            }
        }
        Ok(())
    }

    /// Load the program (auto-detect type based on symbol name)
    #[deprecated(since = "0.1.0", note = "Use load_xdp() or load_tc() explicitly")]
    #[allow(dead_code)]
    pub async fn load(&mut self, interface: &str, object: &str) -> Result<()> {
        // Try XDP first, then TC
        let xdp_path = Path::new(object);
        if xdp_path.exists() {
            return self.load_xdp(interface, object).await;
        }

        self.load_tc(interface, object).await
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

    /// Get the current program type
    #[allow(dead_code)]
    pub fn program_type(&self) -> EbpfProgramType {
        self.program_type
    }
}

impl Default for EbpfLoader {
    fn default() -> Self {
        Self::new().expect("Failed to create EbpfLoader")
    }
}
