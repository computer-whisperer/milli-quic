//! TCP TLS record layer (RFC 8446).
//!
//! Standalone middleware: TCP socket ↔ TlsConnection ↔ H2Connection / Http1Connection.

pub mod record;
pub mod connection;
pub mod client;
pub mod server;

pub use connection::{TlsConnection, TlsEvent};
pub use client::TlsClient;
pub use server::TlsServer;
