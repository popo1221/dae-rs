//! dae-protocol-socks4 crate
//!
//! SOCKS4/SOCKS4a protocol handler extracted from dae-proxy.

mod handler;
mod protocol;
mod request;

pub use handler::{Socks4Config, Socks4Server};
pub use protocol::{Socks4Address, Socks4Command, Socks4Reply};
pub use request::Socks4Request;
