/// QPACK static table (RFC 9204 Appendix A).
///
/// 99 pre-defined header field entries, indexed 0 through 98.

/// A single entry in the static table.
#[derive(Debug, Clone, Copy)]
pub struct StaticEntry {
    pub name: &'static [u8],
    pub value: &'static [u8],
}

/// The full QPACK static table (99 entries).
pub static STATIC_TABLE: [StaticEntry; 99] = [
    StaticEntry { name: b":authority", value: b"" },                                 // 0
    StaticEntry { name: b":path", value: b"/" },                                     // 1
    StaticEntry { name: b"age", value: b"0" },                                       // 2
    StaticEntry { name: b"content-disposition", value: b"" },                         // 3
    StaticEntry { name: b"content-length", value: b"0" },                             // 4
    StaticEntry { name: b"cookie", value: b"" },                                     // 5
    StaticEntry { name: b"date", value: b"" },                                       // 6
    StaticEntry { name: b"etag", value: b"" },                                       // 7
    StaticEntry { name: b"if-modified-since", value: b"" },                           // 8
    StaticEntry { name: b"if-none-match", value: b"" },                               // 9
    StaticEntry { name: b"last-modified", value: b"" },                               // 10
    StaticEntry { name: b"link", value: b"" },                                       // 11
    StaticEntry { name: b"location", value: b"" },                                   // 12
    StaticEntry { name: b"referer", value: b"" },                                    // 13
    StaticEntry { name: b"set-cookie", value: b"" },                                 // 14
    StaticEntry { name: b":method", value: b"CONNECT" },                             // 15
    StaticEntry { name: b":method", value: b"DELETE" },                              // 16
    StaticEntry { name: b":method", value: b"GET" },                                 // 17
    StaticEntry { name: b":method", value: b"HEAD" },                                // 18
    StaticEntry { name: b":method", value: b"OPTIONS" },                             // 19
    StaticEntry { name: b":method", value: b"POST" },                                // 20
    StaticEntry { name: b":method", value: b"PUT" },                                 // 21
    StaticEntry { name: b":path", value: b"/" },                                     // 22
    StaticEntry { name: b":scheme", value: b"http" },                                // 23
    StaticEntry { name: b":scheme", value: b"https" },                               // 24
    StaticEntry { name: b":status", value: b"103" },                                 // 25
    StaticEntry { name: b":status", value: b"200" },                                 // 26
    StaticEntry { name: b":status", value: b"304" },                                 // 27
    StaticEntry { name: b":status", value: b"404" },                                 // 28
    StaticEntry { name: b":status", value: b"503" },                                 // 29
    StaticEntry { name: b"content-type", value: b"" },                               // 30
    StaticEntry { name: b"content-type", value: b"application/dns-message" },         // 31
    StaticEntry { name: b"content-type", value: b"application/javascript" },          // 32
    StaticEntry { name: b"content-type", value: b"application/json" },                // 33
    StaticEntry { name: b"content-type", value: b"application/x-www-form-urlencoded" }, // 34
    StaticEntry { name: b"content-type", value: b"image/gif" },                       // 35
    StaticEntry { name: b"content-type", value: b"image/jpeg" },                      // 36
    StaticEntry { name: b"content-type", value: b"image/png" },                       // 37
    StaticEntry { name: b"content-type", value: b"text/css" },                        // 38
    StaticEntry { name: b"content-type", value: b"text/html; charset=utf-8" },        // 39
    StaticEntry { name: b"content-type", value: b"text/plain" },                      // 40
    StaticEntry { name: b"content-type", value: b"text/plain;charset=utf-8" },        // 41
    StaticEntry { name: b"range", value: b"bytes=0-" },                              // 42
    StaticEntry { name: b"strict-transport-security", value: b"max-age=31536000" },   // 43
    StaticEntry {
        name: b"strict-transport-security",
        value: b"max-age=31536000; includesubdomains",
    }, // 44
    StaticEntry {
        name: b"strict-transport-security",
        value: b"max-age=31536000; includesubdomains; preload",
    }, // 45
    StaticEntry { name: b"vary", value: b"accept-encoding" },                        // 46
    StaticEntry { name: b"vary", value: b"origin" },                                 // 47
    StaticEntry { name: b"x-content-type-options", value: b"nosniff" },               // 48
    StaticEntry { name: b"x-xss-protection", value: b"1; mode=block" },               // 49
    StaticEntry { name: b":status", value: b"100" },                                 // 50
    StaticEntry { name: b":status", value: b"204" },                                 // 51
    StaticEntry { name: b":status", value: b"206" },                                 // 52
    StaticEntry { name: b":status", value: b"302" },                                 // 53
    StaticEntry { name: b":status", value: b"400" },                                 // 54
    StaticEntry { name: b":status", value: b"403" },                                 // 55
    StaticEntry { name: b":status", value: b"421" },                                 // 56
    StaticEntry { name: b":status", value: b"425" },                                 // 57
    StaticEntry { name: b":status", value: b"500" },                                 // 58
    StaticEntry { name: b"accept", value: b"*/*" },                                  // 59
    StaticEntry { name: b"accept", value: b"application/dns-message" },               // 60
    StaticEntry { name: b"accept-encoding", value: b"gzip, deflate, br" },            // 61
    StaticEntry { name: b"accept-ranges", value: b"bytes" },                          // 62
    StaticEntry { name: b"access-control-allow-headers", value: b"cache-control" },   // 63
    StaticEntry { name: b"access-control-allow-headers", value: b"content-type" },    // 64
    StaticEntry { name: b"access-control-allow-origin", value: b"*" },                // 65
    StaticEntry { name: b"cache-control", value: b"max-age=0" },                      // 66
    StaticEntry { name: b"cache-control", value: b"max-age=2592000" },                // 67
    StaticEntry { name: b"cache-control", value: b"max-age=604800" },                 // 68
    StaticEntry { name: b"cache-control", value: b"no-cache" },                       // 69
    StaticEntry { name: b"cache-control", value: b"no-store" },                       // 70
    StaticEntry { name: b"cache-control", value: b"public, max-age=31536000" },       // 71
    StaticEntry { name: b"content-encoding", value: b"br" },                          // 72
    StaticEntry { name: b"content-encoding", value: b"gzip" },                        // 73
    StaticEntry { name: b"content-type", value: b"application/grpc" },                // 74
    StaticEntry { name: b"content-type", value: b"application/grpc+proto" },          // 75
    StaticEntry { name: b"date", value: b"" },                                       // 76
    StaticEntry { name: b"expect-ct", value: b"" },                                  // 77
    StaticEntry { name: b"forwarded", value: b"" },                                  // 78
    StaticEntry { name: b"if-range", value: b"" },                                   // 79
    StaticEntry { name: b"origin", value: b"" },                                     // 80
    StaticEntry { name: b"purpose", value: b"prefetch" },                            // 81
    StaticEntry { name: b"server", value: b"" },                                     // 82
    StaticEntry { name: b"timing-allow-origin", value: b"*" },                        // 83
    StaticEntry { name: b"upgrade-insecure-requests", value: b"1" },                  // 84
    StaticEntry { name: b"user-agent", value: b"" },                                 // 85
    StaticEntry { name: b"x-forwarded-for", value: b"" },                            // 86
    StaticEntry { name: b"x-frame-options", value: b"deny" },                         // 87
    StaticEntry { name: b"x-frame-options", value: b"sameorigin" },                   // 88
    StaticEntry { name: b"accept-language", value: b"" },                            // 89
    StaticEntry {
        name: b"access-control-allow-credentials",
        value: b"FALSE",
    }, // 90
    StaticEntry {
        name: b"access-control-allow-credentials",
        value: b"TRUE",
    }, // 91
    StaticEntry { name: b"access-control-allow-methods", value: b"get" },             // 92
    StaticEntry {
        name: b"access-control-allow-methods",
        value: b"get, post, options",
    }, // 93
    StaticEntry { name: b"access-control-allow-methods", value: b"options" },         // 94
    StaticEntry { name: b"access-control-expose-headers", value: b"content-length" }, // 95
    StaticEntry { name: b"access-control-request-headers", value: b"content-type" },  // 96
    StaticEntry { name: b"access-control-request-method", value: b"get" },            // 97
    StaticEntry { name: b"access-control-request-method", value: b"post" },           // 98
];

/// Result of a static table lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    /// Exact match (name and value both match). Contains the table index.
    ExactMatch(usize),
    /// Name-only match. Contains the index of the first name match.
    NameMatch(usize),
    /// No match at all.
    NotFound,
}

/// Look up a header name/value pair in the static table.
///
/// Returns the best match: exact match is preferred, otherwise name-only.
pub fn lookup(name: &[u8], value: &[u8]) -> LookupResult {
    let mut name_match: Option<usize> = None;

    for (i, entry) in STATIC_TABLE.iter().enumerate() {
        if entry.name == name {
            if entry.value == value {
                return LookupResult::ExactMatch(i);
            }
            if name_match.is_none() {
                name_match = Some(i);
            }
        }
    }

    match name_match {
        Some(idx) => LookupResult::NameMatch(idx),
        None => LookupResult::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_99_entries() {
        assert_eq!(STATIC_TABLE.len(), 99);
    }

    #[test]
    fn entry_0_authority() {
        assert_eq!(STATIC_TABLE[0].name, b":authority");
        assert_eq!(STATIC_TABLE[0].value, b"");
    }

    #[test]
    fn entry_1_path() {
        assert_eq!(STATIC_TABLE[1].name, b":path");
        assert_eq!(STATIC_TABLE[1].value, b"/");
    }

    #[test]
    fn entry_17_method_get() {
        assert_eq!(STATIC_TABLE[17].name, b":method");
        assert_eq!(STATIC_TABLE[17].value, b"GET");
    }

    #[test]
    fn entry_26_status_200() {
        assert_eq!(STATIC_TABLE[26].name, b":status");
        assert_eq!(STATIC_TABLE[26].value, b"200");
    }

    #[test]
    fn entry_98_last() {
        assert_eq!(STATIC_TABLE[98].name, b"access-control-request-method");
        assert_eq!(STATIC_TABLE[98].value, b"post");
    }

    #[test]
    fn entry_33_content_type_json() {
        assert_eq!(STATIC_TABLE[33].name, b"content-type");
        assert_eq!(STATIC_TABLE[33].value, b"application/json");
    }

    #[test]
    fn entry_24_scheme_https() {
        assert_eq!(STATIC_TABLE[24].name, b":scheme");
        assert_eq!(STATIC_TABLE[24].value, b"https");
    }

    #[test]
    fn entry_61_accept_encoding() {
        assert_eq!(STATIC_TABLE[61].name, b"accept-encoding");
        assert_eq!(STATIC_TABLE[61].value, b"gzip, deflate, br");
    }

    #[test]
    fn lookup_exact_match() {
        let result = lookup(b":method", b"GET");
        assert_eq!(result, LookupResult::ExactMatch(17));
    }

    #[test]
    fn lookup_name_only_match() {
        let result = lookup(b":path", b"/index.html");
        assert_eq!(result, LookupResult::NameMatch(1));
    }

    #[test]
    fn lookup_no_match() {
        let result = lookup(b"x-custom-header", b"value");
        assert_eq!(result, LookupResult::NotFound);
    }

    #[test]
    fn lookup_exact_status_200() {
        let result = lookup(b":status", b"200");
        assert_eq!(result, LookupResult::ExactMatch(26));
    }

    #[test]
    fn lookup_name_only_status() {
        let result = lookup(b":status", b"201");
        // First :status entry is index 25
        assert_eq!(result, LookupResult::NameMatch(25));
    }

    #[test]
    fn lookup_exact_content_type_json() {
        let result = lookup(b"content-type", b"application/json");
        assert_eq!(result, LookupResult::ExactMatch(33));
    }
}
