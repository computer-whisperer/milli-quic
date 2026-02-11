//! Browser discovery for HTTP/3 via Alt-Svc (RFC 7838).
//!
//! This module provides functions to generate `Alt-Svc` HTTP response headers
//! that tell browsers HTTP/3 is available, enabling automatic protocol upgrade.

pub mod alt_svc;

pub use alt_svc::{alt_svc_clear, alt_svc_header, alt_svc_header_with_host};
