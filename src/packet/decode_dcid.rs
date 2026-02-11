//! Static helper for extracting the Destination Connection ID from a raw datagram.

/// Extract the Destination Connection ID from a raw datagram.
///
/// Works for both long and short header packets.
/// For short headers, `short_header_dcid_len` is required (from server config).
///
/// Returns `None` if the datagram is too short.
pub fn decode_dcid(datagram: &[u8], short_header_dcid_len: usize) -> Option<&[u8]> {
    if datagram.is_empty() {
        return None;
    }

    let first_byte = datagram[0];

    if first_byte & 0x80 != 0 {
        // Long header: DCID length is at offset 5
        if datagram.len() < 6 {
            return None;
        }
        let dcid_len = datagram[5] as usize;
        let start = 6;
        let end = start + dcid_len;
        if datagram.len() < end {
            return None;
        }
        Some(&datagram[start..end])
    } else {
        // Short header: DCID starts at offset 1, length from config
        let start = 1;
        let end = start + short_header_dcid_len;
        if datagram.len() < end {
            return None;
        }
        Some(&datagram[start..end])
    }
}
