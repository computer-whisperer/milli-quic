//! HTTP request methods (RFC 9110 §9).

/// HTTP request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    CONNECT,
    PATCH,
    TRACE,
}

impl Method {
    /// Parse a method from its ASCII bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            b"GET" => Some(Self::GET),
            b"POST" => Some(Self::POST),
            b"PUT" => Some(Self::PUT),
            b"DELETE" => Some(Self::DELETE),
            b"HEAD" => Some(Self::HEAD),
            b"OPTIONS" => Some(Self::OPTIONS),
            b"CONNECT" => Some(Self::CONNECT),
            b"PATCH" => Some(Self::PATCH),
            b"TRACE" => Some(Self::TRACE),
            _ => None,
        }
    }

    /// Return the method as ASCII bytes.
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::GET => b"GET",
            Self::POST => b"POST",
            Self::PUT => b"PUT",
            Self::DELETE => b"DELETE",
            Self::HEAD => b"HEAD",
            Self::OPTIONS => b"OPTIONS",
            Self::CONNECT => b"CONNECT",
            Self::PATCH => b"PATCH",
            Self::TRACE => b"TRACE",
        }
    }

    /// Return the method as a string slice.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::DELETE => "DELETE",
            Self::HEAD => "HEAD",
            Self::OPTIONS => "OPTIONS",
            Self::CONNECT => "CONNECT",
            Self::PATCH => "PATCH",
            Self::TRACE => "TRACE",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_methods() {
        let methods = [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
            Method::CONNECT,
            Method::PATCH,
            Method::TRACE,
        ];
        for m in methods {
            assert_eq!(Method::from_bytes(m.as_bytes()), Some(m));
        }
    }

    #[test]
    fn unknown_method_returns_none() {
        assert_eq!(Method::from_bytes(b"UNKNOWN"), None);
        assert_eq!(Method::from_bytes(b""), None);
        assert_eq!(Method::from_bytes(b"get"), None); // case sensitive
    }

    #[test]
    fn as_str_matches_bytes() {
        for m in [Method::GET, Method::POST, Method::DELETE] {
            assert_eq!(m.as_str().as_bytes(), m.as_bytes());
        }
    }
}
