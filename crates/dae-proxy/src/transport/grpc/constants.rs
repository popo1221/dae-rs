//! gRPC and HTTP/2 protocol constants
//!
//! Contains HPACK encoded headers and HTTP/2 frame constants
//! used by the gRPC transport implementation.

/// HTTP/2 connection preface (24 bytes)
pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame types
pub mod frame_type {
    /// DATA frame type
    pub const DATA: u8 = 0x0;
    /// HEADERS frame type
    pub const HEADERS: u8 = 0x1;
    /// SETTINGS frame type
    pub const SETTINGS: u8 = 0x4;
    /// WINDOW_UPDATE frame type
    pub const WINDOW_UPDATE: u8 = 0x9;
}

/// HTTP/2 frame flags
pub mod frame_flag {
    /// No flags
    pub const NONE: u8 = 0x0;
    /// END_STREAM flag (for DATA frames)
    pub const END_STREAM: u8 = 0x1;
    /// END_HEADERS flag (for HEADERS frames)
    pub const END_HEADERS: u8 = 0x4;
    /// ACK flag (for SETTINGS frames)
    pub const ACK: u8 = 0x1;
}

/// Default HTTP/2 settings
pub mod settings {
    /// Default connection window size
    pub const CONNECTION_WINDOW_SIZE: u32 = 65535;
}

/// gRPC headers (HPACK encoded)
///
/// These are HPACK wire format representations of HTTP/2 headers.
/// Format: index byte(s) + name + value (with appropriate indexing)
pub mod headers {
    /// :method = POST (indexed, never indexed name)
    pub const METHOD: &[u8] = &[
        0x83, 0x84, 0x07, b':', b'm', b'e', b't', b'h', b'o', b'd', 0x04, b'P', b'O', b'S', b'T',
    ];
    /// :scheme = https (indexed, never indexed name)
    pub const SCHEME_HTTPS: &[u8] = &[0x85, 0x8e, 0x07, b':', b's', b'c', b'h', b'e', b'm', b'e', 0x05, b'h', b't', b't', b'p', b's'];
    /// :scheme = http (indexed, never indexed name)
    pub const SCHEME_HTTP: &[u8] = &[0x85, 0x8e, 0x07, b':', b's', b'c', b'h', b'e', b'm', b'e', 0x04, b'h', b't', b't', b'p'];
    /// :path header (indexed, never indexed name)
    pub const PATH: &[u8] = &[0x85, 0x8e, 0x05, b':', b'p', b'a', b't', b'h'];
    /// :authority header (indexed, never indexed name)
    pub const AUTHORITY: &[u8] = &[0x85, 0x8e, 0x0a, b':', b'a', b'u', b't', b'h', b'o', b'r', b'i', b't', b'y'];
    /// content-type = application/grpc (indexed, never indexed name)
    pub const CONTENT_TYPE: &[u8] = &[
        0x87, 0x92, 0x0c, b'c', b'o', b'n', b't', b'e', b'n', b't', b'-', b't', b'y', b'p', b'e',
        0x10, b'a', b'p', b'p', b'l', b'i', b'c', b'a', b't', b'i', b'o', b'n', b'/', b'g', b'r', b'p', b'c',
    ];
    /// te = trailers (indexed, never indexed name)
    pub const TE: &[u8] = &[0x82, 0x87, 0x02, b't', b'e', 0x07, b't', b'r', b'a', b'i', b'l', b'e', b'r', b's'];
    /// user-agent = dae-rs/grpc (indexed, never indexed name)
    pub const USER_AGENT: &[u8] = &[
        0x83, 0x89, 0x0a, b'u', b's', b'e', b'r', b'-', b'a', b'g', b'e', b'n', b't',
        0x08, b'd', b'a', b'e', b'-', b'r', b's', b'/', b'g', b'r', b'p', b'c',
    ];
}
