//! HTTP/3 framing layer (RFC 9114).
//!
//! This module provides the HTTP/3 frame codec, operating on top of QUIC
//! streams. Frames use the standard TLV (Type-Length-Value) format with
//! QUIC variable-length integers for the type and length fields.

pub mod frame;

pub use frame::{decode_h3_frame, encode_h3_frame, H3Frame, PushPromiseFrame};

/// HTTP/3 settings (RFC 9114 §7.2.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct H3Settings {
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06).
    pub max_field_section_size: Option<u64>,
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01).
    pub qpack_max_table_capacity: Option<u64>,
    /// SETTINGS_QPACK_BLOCKED_STREAMS (0x07).
    pub qpack_blocked_streams: Option<u64>,
}

/// Known HTTP/3 setting identifiers.
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// HTTP/3 unidirectional stream types (RFC 9114 §6.2).
pub const H3_STREAM_TYPE_CONTROL: u64 = 0x00;
pub const H3_STREAM_TYPE_PUSH: u64 = 0x01;
pub const H3_STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
pub const H3_STREAM_TYPE_QPACK_DECODER: u64 = 0x03;
