//! Shared HPACK/QPACK primitives.
//!
//! Huffman coding and integer encoding are identical between HPACK (RFC 7541)
//! and QPACK (RFC 9204). This module contains the shared implementations.
//!
//! The HPACK-specific static table (61 entries) and codec are also here,
//! gated behind the `h2` feature.

pub mod huffman;
pub mod integer;

#[cfg(feature = "h2")]
pub mod static_table;

#[cfg(feature = "h2")]
pub mod codec;
