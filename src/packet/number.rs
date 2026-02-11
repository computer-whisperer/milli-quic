//! QUIC packet number encoding and decoding (RFC 9000 section 17.1, A.2, A.3).

use crate::error::Error;

/// Determine how many bytes are needed to encode `full_pn` given `largest_acked`.
///
/// Chooses the smallest encoding that is at least twice the distance from
/// `largest_acked` to `full_pn`, as recommended by RFC 9000 section A.2.
pub fn pn_length(full_pn: u64, largest_acked: u64) -> usize {
    let num_unacked = if full_pn > largest_acked {
        full_pn - largest_acked
    } else {
        1
    };
    // We need enough bytes so that 2 * num_unacked fits in the range.
    // 1 byte encodes 0..127 (half-range), 2 bytes 0..32767, etc.
    if num_unacked < (1 << 7) {
        1
    } else if num_unacked < (1 << 15) {
        2
    } else if num_unacked < (1 << 23) {
        3
    } else {
        4
    }
}

/// Encode a packet number using minimal bytes.
///
/// Writes the truncated packet number to `buf` in big-endian order.
/// Returns the number of bytes written (1-4).
pub fn encode_pn(full_pn: u64, largest_acked: u64, buf: &mut [u8]) -> Result<usize, Error> {
    let len = pn_length(full_pn, largest_acked);
    if buf.len() < len {
        return Err(Error::BufferTooSmall { needed: len });
    }

    // Write the lower `len` bytes of full_pn in big-endian order.
    let pn_bytes = full_pn.to_be_bytes();
    buf[..len].copy_from_slice(&pn_bytes[8 - len..]);

    Ok(len)
}

/// Decode a truncated packet number given the largest successfully processed PN.
///
/// `truncated_pn` is the raw value read from the packet.
/// `pn_len` is the number of bytes it was encoded in (1-4).
/// `largest_pn` is the largest packet number successfully processed.
///
/// Implements the algorithm from RFC 9000 section A.3.
pub fn decode_pn(truncated_pn: u32, pn_len: usize, largest_pn: u64) -> u64 {
    let pn_nbits = (pn_len as u64) * 8;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    let expected_pn = largest_pn + 1;

    // The candidate value: replace the lower bits of expected_pn with truncated_pn.
    let candidate_pn = (expected_pn & !pn_mask) | (truncated_pn as u64);

    if candidate_pn + pn_hwin <= expected_pn && candidate_pn + pn_win <= (1u64 << 62) {
        candidate_pn + pn_win
    } else if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
        candidate_pn - pn_win
    } else {
        candidate_pn
    }
}
