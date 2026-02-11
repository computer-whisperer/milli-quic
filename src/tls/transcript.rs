//! Running transcript hash for TLS 1.3 handshake.
//!
//! Maintains a SHA-256 hash state that is updated with each handshake
//! message. Intermediate hashes are obtained by cloning the state.

use sha2::{Digest, Sha256};

/// Running SHA-256 transcript hash over TLS handshake messages.
pub struct TranscriptHash {
    hasher: Sha256,
}

impl TranscriptHash {
    /// Create a new empty transcript hash.
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Feed handshake message bytes into the transcript.
    pub fn update(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    /// Get the current transcript hash without consuming the state.
    ///
    /// Clones the internal hasher, finalizes the clone, and returns
    /// the 32-byte SHA-256 digest.
    pub fn current_hash(&self) -> [u8; 32] {
        let clone = self.hasher.clone();
        let result = clone.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_transcript() {
        let t = TranscriptHash::new();
        // SHA-256 of empty input
        let hash = t.current_hash();
        let expected: [u8; 32] = {
            let h = Sha256::new();
            let r = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&r);
            out
        };
        assert_eq!(hash, expected);
    }

    #[test]
    fn incremental_hashing() {
        let mut t = TranscriptHash::new();
        t.update(b"hello");
        let hash1 = t.current_hash();

        t.update(b" world");
        let hash2 = t.current_hash();

        // hash1 != hash2 since more data was added
        assert_ne!(hash1, hash2);

        // hash2 should equal SHA-256("hello world")
        let mut h = Sha256::new();
        h.update(b"hello world");
        let expected: [u8; 32] = {
            let r = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&r);
            out
        };
        assert_eq!(hash2, expected);
    }

    #[test]
    fn current_hash_does_not_consume() {
        let mut t = TranscriptHash::new();
        t.update(b"data");
        let h1 = t.current_hash();
        let h2 = t.current_hash();
        // Calling current_hash twice should produce the same result.
        assert_eq!(h1, h2);

        // Adding more data should change the hash.
        t.update(b"more");
        let h3 = t.current_hash();
        assert_ne!(h1, h3);
    }
}
