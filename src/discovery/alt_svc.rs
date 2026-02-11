//! Alt-Svc header generation for HTTP/3 browser discovery (RFC 7838).
//!
//! The `Alt-Svc` HTTP response header advertises that an equivalent service
//! is available over HTTP/3 (QUIC). Browsers use this header to upgrade
//! connections from HTTP/2 or HTTP/1.1 to HTTP/3.
//!
//! All functions write directly into a caller-provided `&mut [u8]` buffer
//! with zero heap allocation, suitable for `no_std` environments.

use crate::error::Error;

/// Maximum number of decimal digits in a `u32` value.
const MAX_U32_DIGITS: usize = 10; // 4_294_967_295

/// Format an unsigned integer into a byte buffer as ASCII decimal.
///
/// Returns the number of bytes written.
fn fmt_u32(mut val: u32, buf: &mut [u8]) -> usize {
    if val == 0 {
        if buf.is_empty() {
            return 0;
        }
        buf[0] = b'0';
        return 1;
    }

    // Write digits in reverse into a small stack buffer, then copy forward.
    let mut tmp = [0u8; MAX_U32_DIGITS];
    let mut len = 0;
    while val > 0 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }

    // Copy reversed digits into output.
    for i in 0..len {
        if i >= buf.len() {
            return i;
        }
        buf[i] = tmp[len - 1 - i];
    }
    len
}

/// Format a `u16` value — delegates to `fmt_u32`.
fn fmt_u16(val: u16, buf: &mut [u8]) -> usize {
    fmt_u32(val as u32, buf)
}

/// Write a byte slice into `buf` at `pos`, returning the new position.
///
/// Returns `Err(Error::BufferTooSmall)` if the buffer cannot hold the data.
fn write_bytes(buf: &mut [u8], pos: usize, src: &[u8]) -> Result<usize, Error> {
    let end = pos + src.len();
    if end > buf.len() {
        return Err(Error::BufferTooSmall { needed: end });
    }
    buf[pos..end].copy_from_slice(src);
    Ok(end)
}

/// Compute the number of ASCII decimal digits needed to represent a `u32`.
fn digit_count_u32(val: u32) -> usize {
    if val == 0 {
        return 1;
    }
    let mut n = val;
    let mut count = 0;
    while n > 0 {
        count += 1;
        n /= 10;
    }
    count
}

/// Compute the total byte length of an Alt-Svc header value:
/// `h3=":PORT"; ma=MAX_AGE`
fn header_len(port: u16, max_age_secs: u32) -> usize {
    // h3=":  =  5 bytes
    // PORT  =  port_digits bytes
    // "; ma= = 6 bytes  (quote, semicolon, space, m, a, equals)
    // MAX_AGE = ma_digits bytes
    let port_digits = digit_count_u32(port as u32);
    let ma_digits = digit_count_u32(max_age_secs);
    5 + port_digits + 6 + ma_digits
}

/// Compute the total byte length of an Alt-Svc header with host:
/// `h3="HOST:PORT"; ma=MAX_AGE`
fn header_with_host_len(host: &str, port: u16, max_age_secs: u32) -> usize {
    // h3="     = 4 bytes
    // HOST     = host.len() bytes
    // :        = 1 byte
    // PORT     = port_digits bytes
    // "; ma=   = 6 bytes  (quote, semicolon, space, m, a, equals)
    // MAX_AGE  = ma_digits bytes
    let port_digits = digit_count_u32(port as u32);
    let ma_digits = digit_count_u32(max_age_secs);
    4 + host.len() + 1 + port_digits + 6 + ma_digits
}

/// Generate an Alt-Svc header value for HTTP/3.
///
/// # Arguments
/// * `port` -- The UDP port where HTTP/3 (QUIC) is served
/// * `max_age_secs` -- Cache duration in seconds (e.g., 86400 for 24 hours)
/// * `buf` -- Output buffer for the header value
///
/// # Returns
/// The number of bytes written to `buf`.
///
/// # Example output
/// `h3=":443"; ma=86400`
pub fn alt_svc_header(port: u16, max_age_secs: u32, buf: &mut [u8]) -> Result<usize, Error> {
    let needed = header_len(port, max_age_secs);
    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut pos = 0;

    // h3=":
    pos = write_bytes(buf, pos, b"h3=\":")?;

    // PORT
    let n = fmt_u16(port, &mut buf[pos..]);
    pos += n;

    // "; ma=
    pos = write_bytes(buf, pos, b"\"; ma=")?;

    // MAX_AGE
    let n = fmt_u32(max_age_secs, &mut buf[pos..]);
    pos += n;

    Ok(pos)
}

/// Generate an Alt-Svc header value that clears any cached alternative services.
///
/// # Example output
/// `clear`
pub fn alt_svc_clear(buf: &mut [u8]) -> Result<usize, Error> {
    let clear = b"clear";
    if buf.len() < clear.len() {
        return Err(Error::BufferTooSmall {
            needed: clear.len(),
        });
    }
    buf[..clear.len()].copy_from_slice(clear);
    Ok(clear.len())
}

/// Generate an Alt-Svc header with a specific host (for cross-origin).
///
/// # Arguments
/// * `host` -- The hostname where HTTP/3 is served (e.g., "quic.example.com")
/// * `port` -- The UDP port
/// * `max_age_secs` -- Cache duration in seconds
/// * `buf` -- Output buffer
///
/// # Example output
/// `h3="quic.example.com:443"; ma=86400`
pub fn alt_svc_header_with_host(
    host: &str,
    port: u16,
    max_age_secs: u32,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let needed = header_with_host_len(host, port, max_age_secs);
    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut pos = 0;

    // h3="
    pos = write_bytes(buf, pos, b"h3=\"")?;

    // HOST
    pos = write_bytes(buf, pos, host.as_bytes())?;

    // :
    pos = write_bytes(buf, pos, b":")?;

    // PORT
    let n = fmt_u16(port, &mut buf[pos..]);
    pos += n;

    // "; ma=
    pos = write_bytes(buf, pos, b"\"; ma=")?;

    // MAX_AGE
    let n = fmt_u32(max_age_secs, &mut buf[pos..]);
    pos += n;

    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: format into a buffer and return the result as a string slice.
    fn to_str(buf: &[u8], len: usize) -> &str {
        core::str::from_utf8(&buf[..len]).expect("output should be valid UTF-8")
    }

    // ---- 1. Basic Alt-Svc ----
    #[test]
    fn basic_alt_svc_443() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header(443, 86400, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\":443\"; ma=86400");
    }

    // ---- 2. Different port ----
    #[test]
    fn different_port_8443() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header(8443, 3600, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\":8443\"; ma=3600");
    }

    // ---- 3. Port 80 ----
    #[test]
    fn port_80() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header(80, 60, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\":80\"; ma=60");
    }

    // ---- 4. Max port ----
    #[test]
    fn max_port() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header(65535, 0, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\":65535\"; ma=0");
    }

    // ---- 5. Clear ----
    #[test]
    fn clear() {
        let mut buf = [0u8; 64];
        let n = alt_svc_clear(&mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "clear");
    }

    // ---- 6. With host ----
    #[test]
    fn with_host() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header_with_host("quic.example.com", 443, 86400, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\"quic.example.com:443\"; ma=86400");
    }

    // ---- 7. Buffer too small ----
    #[test]
    fn buffer_too_small_header() {
        let mut buf = [0u8; 5]; // Way too small for any header
        let result = alt_svc_header(443, 86400, &mut buf);
        assert!(result.is_err());
        match result {
            Err(Error::BufferTooSmall { needed }) => {
                assert!(needed > 5);
            }
            _ => panic!("expected BufferTooSmall"),
        }
    }

    #[test]
    fn buffer_too_small_clear() {
        let mut buf = [0u8; 3]; // "clear" needs 5
        let result = alt_svc_clear(&mut buf);
        assert_eq!(result, Err(Error::BufferTooSmall { needed: 5 }));
    }

    #[test]
    fn buffer_too_small_with_host() {
        let mut buf = [0u8; 5];
        let result = alt_svc_header_with_host("quic.example.com", 443, 86400, &mut buf);
        assert!(result.is_err());
        match result {
            Err(Error::BufferTooSmall { needed }) => {
                assert!(needed > 5);
            }
            _ => panic!("expected BufferTooSmall"),
        }
    }

    // ---- 8. Max age boundary ----
    #[test]
    fn max_age_u32_max() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header(443, u32::MAX, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\":443\"; ma=4294967295");
    }

    #[test]
    fn max_age_zero() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header(443, 0, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\":443\"; ma=0");
    }

    // ---- 9. Empty host ----
    #[test]
    fn empty_host() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header_with_host("", 443, 86400, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\":443\"; ma=86400");
    }

    // ---- 10. Output is valid UTF-8 / ASCII ----
    #[test]
    fn output_is_valid_utf8() {
        let mut buf = [0u8; 128];

        let n = alt_svc_header(443, 86400, &mut buf).unwrap();
        assert!(core::str::from_utf8(&buf[..n]).is_ok());
        // Also verify all bytes are ASCII (< 128)
        assert!(buf[..n].iter().all(|&b| b.is_ascii()));

        let n = alt_svc_clear(&mut buf).unwrap();
        assert!(core::str::from_utf8(&buf[..n]).is_ok());
        assert!(buf[..n].iter().all(|&b| b.is_ascii()));

        let n = alt_svc_header_with_host("example.com", 8443, 3600, &mut buf).unwrap();
        assert!(core::str::from_utf8(&buf[..n]).is_ok());
        assert!(buf[..n].iter().all(|&b| b.is_ascii()));
    }

    // ---- Additional edge cases ----

    #[test]
    fn exact_fit_buffer() {
        // "h3=\":443\"; ma=86400" is 19 bytes
        let expected = "h3=\":443\"; ma=86400";
        assert_eq!(expected.len(), 19);
        let mut buf = [0u8; 19];
        let n = alt_svc_header(443, 86400, &mut buf).unwrap();
        assert_eq!(n, 19);
        assert_eq!(to_str(&buf, n), expected);
    }

    #[test]
    fn buffer_one_byte_short() {
        // "h3=\":443\"; ma=86400" is 19 bytes
        let mut buf = [0u8; 18];
        let result = alt_svc_header(443, 86400, &mut buf);
        assert_eq!(result, Err(Error::BufferTooSmall { needed: 19 }));
    }

    #[test]
    fn port_1() {
        let mut buf = [0u8; 64];
        let n = alt_svc_header(1, 1, &mut buf).unwrap();
        assert_eq!(to_str(&buf, n), "h3=\":1\"; ma=1");
    }

    #[test]
    fn with_host_max_values() {
        let mut buf = [0u8; 128];
        let n = alt_svc_header_with_host("host.example.com", 65535, u32::MAX, &mut buf).unwrap();
        assert_eq!(
            to_str(&buf, n),
            "h3=\"host.example.com:65535\"; ma=4294967295"
        );
    }

    #[test]
    fn fmt_u32_helper_zero() {
        let mut buf = [0u8; 16];
        let n = fmt_u32(0, &mut buf);
        assert_eq!(&buf[..n], b"0");
    }

    #[test]
    fn fmt_u32_helper_max() {
        let mut buf = [0u8; 16];
        let n = fmt_u32(u32::MAX, &mut buf);
        assert_eq!(&buf[..n], b"4294967295");
    }

    #[test]
    fn fmt_u16_helper_max() {
        let mut buf = [0u8; 8];
        let n = fmt_u16(65535, &mut buf);
        assert_eq!(&buf[..n], b"65535");
    }
}
