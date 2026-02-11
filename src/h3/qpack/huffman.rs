/// QPACK/HPACK Huffman encoding (RFC 7541 Appendix B).
///
/// TODO: Implement the full 257-symbol Huffman encoding/decoding table.
///
/// For the initial static-only QPACK implementation, Huffman encoding is not
/// used when *encoding* header values (the H bit is set to 0). The decoder
/// recognises the H bit and will reject Huffman-encoded data until this module
/// is completed.

use crate::error::Error;

/// Decode a Huffman-encoded byte string.
///
/// Not yet implemented — returns an error if called.
pub fn decode(_src: &[u8], _buf: &mut [u8]) -> Result<usize, Error> {
    // TODO: implement Huffman decoding
    Err(Error::Http3(
        crate::error::H3Error::QpackDecompressionFailed,
    ))
}

/// Encode a byte string using HPACK Huffman coding.
///
/// Not yet implemented — returns an error if called.
pub fn encode(_src: &[u8], _buf: &mut [u8]) -> Result<usize, Error> {
    // TODO: implement Huffman encoding
    Err(Error::Http3(
        crate::error::H3Error::QpackDecompressionFailed,
    ))
}

/// Return the encoded length of `src` under Huffman coding.
///
/// Not yet implemented — returns 0.
pub fn encoded_len(_src: &[u8]) -> usize {
    // TODO: implement once the Huffman table is in place.
    0
}
