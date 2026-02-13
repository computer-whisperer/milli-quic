#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod error;
pub mod frame;
pub mod varint;

#[cfg(feature = "h3")]
pub mod h3;

#[cfg(feature = "discovery")]
pub mod discovery;

pub mod transport;
pub use transport::{Address, Clock, DatagramRecv, DatagramSend, Instant, Rng, ServerTransport};

pub mod crypto;
pub mod packet;
pub mod tls;

pub mod connection;
pub use connection::{
    Connection, ConnectionConfig, ConnectionId, ConnectionState, DefaultConfig, Event,
    HandshakeContext, HandshakePool, HandshakePoolAccess, Transmit,
};
pub use tls::handshake::Role;
