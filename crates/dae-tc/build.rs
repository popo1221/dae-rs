//! Build script for dae-tc
//!
//! This build script compiles the eBPF program when using cargo-bpf or
//! aya-ebpf-builder. For now, we just verify the compilation target is available.

fn main() {
    // Check if we're compiling for BPF target
    if let Ok(target) = std::env::var("CARGO_BUILD_TARGET") {
        if target.contains("bpf") {
            println!("cargo:rerun-if-changed=src/");
            return;
        }
    }

    // For regular builds, emit the rustc-cfg
    println!("cargo:rustc-cfg=kernel_mode");
}
