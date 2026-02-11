#![no_std]
#![forbid(unsafe_code)]

pub mod error;
pub mod frame;
pub mod varint;

pub mod transport;
pub use transport::{Address, Clock, DatagramRecv, DatagramSend, Instant, Rng, ServerTransport};

pub mod crypto;
pub mod packet;
pub mod tls;

pub mod connection;
pub use connection::{
    Connection, ConnectionConfig, ConnectionId, ConnectionState, DefaultConfig, Event, Transmit,
};
pub use tls::handshake::Role;
