//! Shared HTTP types used across HTTP/1.1, HTTP/2, and HTTP/3.

pub mod method;
pub mod status;
pub mod header;

pub use method::Method;
pub use status::StatusCode;
pub use header::Header;
