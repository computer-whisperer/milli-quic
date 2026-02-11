/// HTTP/3 support modules.
///
/// Feature-gated behind `h3`.  Currently provides QPACK header compression
/// in static-only mode (RFC 9204 with `TABLE_SIZE = 0`).

pub mod qpack;

pub use qpack::{QpackDecoder, QpackEncoder};
