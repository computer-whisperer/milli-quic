//! HTTP/1.1 protocol implementation.
//!
//! A pure-codec HTTP/1.1 stack following the same calling convention as
//! HTTP/2 and QUIC: `feed_data()` → `poll_output()` → `poll_event()`.

pub mod parse;
pub mod connection;
pub mod io;
pub mod server;
pub mod client;

pub use connection::{Http1Connection, Http1Event};
pub use io::{Http1Io, Http1IoBufs};
pub use server::Http1Server;
pub use client::Http1Client;
