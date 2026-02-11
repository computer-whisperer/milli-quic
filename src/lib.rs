#![no_std]
#![forbid(unsafe_code)]

pub mod error;
pub mod varint;

mod transport;
pub use transport::{Address, Clock, DatagramRecv, DatagramSend, Instant, Rng, ServerTransport};

pub mod crypto;
