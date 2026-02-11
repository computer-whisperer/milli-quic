use crate::error::Error;

/// HMAC-based Key Derivation Function (RFC 5869).
///
/// Used throughout QUIC for deriving encryption keys, IVs, and
/// header protection keys from TLS secrets.
pub trait Hkdf {
    /// Hash output length in bytes (e.g., 32 for SHA-256).
    const HASH_LEN: usize;

    /// HKDF-Extract: derive a pseudorandom key from salt and input keying material.
    fn extract(&self, salt: &[u8], ikm: &[u8], prk: &mut [u8]);

    /// HKDF-Expand: expand a pseudorandom key with info into output keying material.
    fn expand(&self, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error>;
}
