/// Header protection cipher.
///
/// QUIC applies a mask to the first byte and packet number bytes of
/// each packet to prevent middleboxes from reading packet numbers.
/// The mask is derived from a 16-byte sample of the encrypted payload.
pub trait HeaderProtection {
    /// Compute a 5-byte mask from a 16-byte sample.
    ///
    /// - `mask[0]` is XORed with the first byte of the packet header
    ///   (lower 4 bits for long headers, lower 5 bits for short headers)
    /// - `mask[1..5]` are XORed with the packet number bytes
    fn mask(&self, sample: &[u8]) -> [u8; 5];
}
