//! HTTP status codes (RFC 9110 §15).

/// HTTP response status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(pub u16);

impl StatusCode {
    // 1xx Informational
    pub const CONTINUE: Self = Self(100);
    pub const SWITCHING_PROTOCOLS: Self = Self(101);
    pub const EARLY_HINTS: Self = Self(103);

    // 2xx Success
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const ACCEPTED: Self = Self(202);
    pub const NO_CONTENT: Self = Self(204);
    pub const PARTIAL_CONTENT: Self = Self(206);

    // 3xx Redirection
    pub const MOVED_PERMANENTLY: Self = Self(301);
    pub const FOUND: Self = Self(302);
    pub const NOT_MODIFIED: Self = Self(304);
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    pub const PERMANENT_REDIRECT: Self = Self(308);

    // 4xx Client Error
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const REQUEST_TIMEOUT: Self = Self(408);
    pub const CONFLICT: Self = Self(409);
    pub const GONE: Self = Self(410);
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    pub const URI_TOO_LONG: Self = Self(414);
    pub const TOO_MANY_REQUESTS: Self = Self(429);

    // 5xx Server Error
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const NOT_IMPLEMENTED: Self = Self(501);
    pub const BAD_GATEWAY: Self = Self(502);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    pub const GATEWAY_TIMEOUT: Self = Self(504);

    /// Whether this is a 1xx informational status.
    pub const fn is_informational(&self) -> bool {
        self.0 >= 100 && self.0 < 200
    }

    /// Whether this is a 2xx success status.
    pub const fn is_success(&self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    /// Whether this is a 3xx redirection status.
    pub const fn is_redirection(&self) -> bool {
        self.0 >= 300 && self.0 < 400
    }

    /// Whether this is a 4xx client error status.
    pub const fn is_client_error(&self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    /// Whether this is a 5xx server error status.
    pub const fn is_server_error(&self) -> bool {
        self.0 >= 500 && self.0 < 600
    }

    /// Format this status code as 3 ASCII digits into a byte array.
    pub const fn to_bytes(&self) -> [u8; 3] {
        let d0 = (self.0 / 100) as u8;
        let d1 = ((self.0 / 10) % 10) as u8;
        let d2 = (self.0 % 10) as u8;
        [b'0' + d0, b'0' + d1, b'0' + d2]
    }

    /// Parse a status code from exactly 3 ASCII digit bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 3 {
            return None;
        }
        let d0 = b[0].wrapping_sub(b'0');
        let d1 = b[1].wrapping_sub(b'0');
        let d2 = b[2].wrapping_sub(b'0');
        if d0 > 9 || d1 > 9 || d2 > 9 {
            return None;
        }
        let code = d0 as u16 * 100 + d1 as u16 * 10 + d2 as u16;
        if code < 100 {
            return None;
        }
        Some(Self(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_categories() {
        assert!(StatusCode::CONTINUE.is_informational());
        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::FOUND.is_redirection());
        assert!(StatusCode::NOT_FOUND.is_client_error());
        assert!(StatusCode::INTERNAL_SERVER_ERROR.is_server_error());
    }

    #[test]
    fn to_bytes_roundtrip() {
        let codes = [100u16, 200, 301, 404, 500, 503];
        for code in codes {
            let sc = StatusCode(code);
            let bytes = sc.to_bytes();
            let parsed = StatusCode::from_bytes(&bytes).unwrap();
            assert_eq!(parsed, sc);
        }
    }

    #[test]
    fn from_bytes_invalid() {
        assert_eq!(StatusCode::from_bytes(b"abc"), None);
        assert_eq!(StatusCode::from_bytes(b"99"), None); // too short
        assert_eq!(StatusCode::from_bytes(b"0990"), None); // too long
        assert_eq!(StatusCode::from_bytes(b"099"), None); // < 100
    }

    #[test]
    fn category_boundaries() {
        assert!(!StatusCode(99).is_informational());
        assert!(StatusCode(100).is_informational());
        assert!(StatusCode(199).is_informational());
        assert!(!StatusCode(200).is_informational());
        assert!(StatusCode(200).is_success());
    }
}
