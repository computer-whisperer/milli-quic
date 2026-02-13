//! HTTP header types and common header name constants.

/// A single HTTP header (name-value pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

impl<'a> Header<'a> {
    /// Create a new header.
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self { name, value }
    }
}

// Common header names as byte constants.
pub const CONTENT_TYPE: &[u8] = b"content-type";
pub const CONTENT_LENGTH: &[u8] = b"content-length";
pub const HOST: &[u8] = b"host";
pub const ACCEPT: &[u8] = b"accept";
pub const ACCEPT_ENCODING: &[u8] = b"accept-encoding";
pub const USER_AGENT: &[u8] = b"user-agent";
pub const SERVER: &[u8] = b"server";
pub const CACHE_CONTROL: &[u8] = b"cache-control";
pub const CONNECTION: &[u8] = b"connection";
pub const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_construction() {
        let h = Header::new(b"content-type", b"text/html");
        assert_eq!(h.name, b"content-type");
        assert_eq!(h.value, b"text/html");
    }

    #[test]
    fn header_equality() {
        let h1 = Header::new(b"host", b"example.com");
        let h2 = Header::new(b"host", b"example.com");
        let h3 = Header::new(b"host", b"other.com");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
