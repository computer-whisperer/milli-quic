use crate::error::Error;

/// Authenticated Encryption with Associated Data.
///
/// Used for QUIC packet payload protection. QUIC mandates support for
/// AES-128-GCM; ChaCha20-Poly1305 is preferred on targets without
/// AES hardware.
pub trait Aead {
    /// Key length in bytes.
    const KEY_LEN: usize;
    /// Nonce length in bytes (always 12 for QUIC).
    const NONCE_LEN: usize;
    /// Authentication tag length in bytes (always 16 for QUIC).
    const TAG_LEN: usize;

    /// Encrypt in place.
    ///
    /// `buf[..payload_len]` contains the plaintext. The buffer must have
    /// room for the authentication tag (`buf.len() >= payload_len + TAG_LEN`).
    ///
    /// Returns the total length of ciphertext + tag.
    fn seal_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        payload_len: usize,
    ) -> Result<usize, Error>;

    /// Decrypt in place.
    ///
    /// `buf[..ciphertext_len]` contains ciphertext + authentication tag.
    ///
    /// Returns the plaintext length on success.
    fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Error>;
}
