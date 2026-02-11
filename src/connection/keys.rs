//! Connection-level key management.
//!
//! Tracks send/recv `DirectionalKeys` for each encryption level
//! (Initial, Handshake, Application) and provides helpers to derive
//! Initial keys from a DCID and install keys from TLS-derived secrets.

use crate::crypto::{CryptoProvider, DirectionalKeys, Level};
use crate::error::Error;
use crate::tls::DerivedKeys;

/// All keys for a QUIC connection, separated by level and direction.
pub struct ConnectionKeys<C: CryptoProvider> {
    pub initial_send: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub initial_recv: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub handshake_send: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub handshake_recv: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub app_send: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub app_recv: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
}

impl<C: CryptoProvider> ConnectionKeys<C> {
    /// Create an empty key set (no keys installed yet).
    pub fn new() -> Self {
        Self {
            initial_send: None,
            initial_recv: None,
            handshake_send: None,
            handshake_recv: None,
            app_send: None,
            app_recv: None,
        }
    }

    /// Derive and install Initial keys from a Destination Connection ID.
    ///
    /// For a client: send = client keys, recv = server keys.
    /// For a server: send = server keys, recv = client keys.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn derive_initial(
        &mut self,
        provider: &C,
        dcid: &[u8],
        is_client: bool,
    ) -> Result<(), Error> {
        let hkdf = provider.hkdf();
        let mut client_secret = [0u8; 32];
        let mut server_secret = [0u8; 32];
        crate::crypto::key_schedule::derive_initial_secrets(
            &hkdf,
            dcid,
            &mut client_secret,
            &mut server_secret,
        )?;

        let client_keys =
            crate::crypto::key_schedule::derive_directional_keys(provider, &hkdf, &client_secret)?;
        let server_keys =
            crate::crypto::key_schedule::derive_directional_keys(provider, &hkdf, &server_secret)?;

        if is_client {
            self.initial_send = Some(client_keys);
            self.initial_recv = Some(server_keys);
        } else {
            self.initial_send = Some(server_keys);
            self.initial_recv = Some(client_keys);
        }
        Ok(())
    }

    /// Install keys derived from TLS (handshake or application level).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn install_derived(
        &mut self,
        provider: &C,
        derived: &DerivedKeys,
    ) -> Result<(), Error> {
        let hkdf = provider.hkdf();
        let send_keys = crate::crypto::key_schedule::derive_directional_keys(
            provider,
            &hkdf,
            &derived.send_secret[..derived.secret_len],
        )?;
        let recv_keys = crate::crypto::key_schedule::derive_directional_keys(
            provider,
            &hkdf,
            &derived.recv_secret[..derived.secret_len],
        )?;

        match derived.level {
            Level::Handshake => {
                self.handshake_send = Some(send_keys);
                self.handshake_recv = Some(recv_keys);
            }
            Level::Application => {
                self.app_send = Some(send_keys);
                self.app_recv = Some(recv_keys);
            }
            Level::Initial => {
                // Initial keys are derived differently; this shouldn't happen
                // but handle gracefully.
                self.initial_send = Some(send_keys);
                self.initial_recv = Some(recv_keys);
            }
        }
        Ok(())
    }

    /// Get the send-direction keys for a given level.
    pub fn send_keys(
        &self,
        level: Level,
    ) -> Option<&DirectionalKeys<C::Aead, C::HeaderProtection>> {
        match level {
            Level::Initial => self.initial_send.as_ref(),
            Level::Handshake => self.handshake_send.as_ref(),
            Level::Application => self.app_send.as_ref(),
        }
    }

    /// Get the recv-direction keys for a given level.
    pub fn recv_keys(
        &self,
        level: Level,
    ) -> Option<&DirectionalKeys<C::Aead, C::HeaderProtection>> {
        match level {
            Level::Initial => self.initial_recv.as_ref(),
            Level::Handshake => self.handshake_recv.as_ref(),
            Level::Application => self.app_recv.as_ref(),
        }
    }

    /// Drop Initial keys (after handshake keys are installed).
    pub fn drop_initial(&mut self) {
        self.initial_send = None;
        self.initial_recv = None;
    }

    /// Drop Handshake keys (after handshake is confirmed).
    pub fn drop_handshake(&mut self) {
        self.handshake_send = None;
        self.handshake_recv = None;
    }

    /// Check if we have send keys at a given level.
    pub fn has_send_keys(&self, level: Level) -> bool {
        self.send_keys(level).is_some()
    }

    /// Check if we have recv keys at a given level.
    pub fn has_recv_keys(&self, level: Level) -> bool {
        self.recv_keys(level).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn derive_initial_client_keys() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        keys.derive_initial(&provider, &dcid, true).unwrap();

        assert!(keys.initial_send.is_some());
        assert!(keys.initial_recv.is_some());
        assert!(keys.handshake_send.is_none());
        assert!(keys.app_send.is_none());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn derive_initial_server_keys_swapped() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let dcid = [0x01, 0x02, 0x03, 0x04];

        let mut client_keys = ConnectionKeys::<Aes128GcmProvider>::new();
        client_keys.derive_initial(&provider, &dcid, true).unwrap();

        let mut server_keys = ConnectionKeys::<Aes128GcmProvider>::new();
        server_keys.derive_initial(&provider, &dcid, false).unwrap();

        // Client send IV should equal server recv IV, and vice versa
        assert_eq!(
            client_keys.initial_send.as_ref().unwrap().iv,
            server_keys.initial_recv.as_ref().unwrap().iv
        );
        assert_eq!(
            client_keys.initial_recv.as_ref().unwrap().iv,
            server_keys.initial_send.as_ref().unwrap().iv
        );
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn install_handshake_keys() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();

        // Create fake derived keys
        let mut send_secret = [0u8; 48];
        send_secret[..32].copy_from_slice(&[0xAA; 32]);
        let mut recv_secret = [0u8; 48];
        recv_secret[..32].copy_from_slice(&[0xBB; 32]);

        let derived = DerivedKeys {
            level: Level::Handshake,
            send_secret,
            recv_secret,
            secret_len: 32,
        };

        keys.install_derived(&provider, &derived).unwrap();
        assert!(keys.handshake_send.is_some());
        assert!(keys.handshake_recv.is_some());
        assert!(keys.app_send.is_none());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn drop_initial_clears_keys() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();
        keys.derive_initial(&provider, &[1, 2, 3, 4], true).unwrap();

        assert!(keys.has_send_keys(Level::Initial));
        assert!(keys.has_recv_keys(Level::Initial));

        keys.drop_initial();
        assert!(!keys.has_send_keys(Level::Initial));
        assert!(!keys.has_recv_keys(Level::Initial));
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn send_recv_keys_by_level() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();
        keys.derive_initial(&provider, &[1, 2, 3, 4], true).unwrap();

        assert!(keys.send_keys(Level::Initial).is_some());
        assert!(keys.recv_keys(Level::Initial).is_some());
        assert!(keys.send_keys(Level::Handshake).is_none());
        assert!(keys.recv_keys(Level::Handshake).is_none());
        assert!(keys.send_keys(Level::Application).is_none());
        assert!(keys.recv_keys(Level::Application).is_none());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn encrypt_decrypt_with_initial_keys() {
        use crate::crypto::Aead as _;
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let dcid = [0x01, 0x02, 0x03, 0x04];

        let mut client_keys = ConnectionKeys::<Aes128GcmProvider>::new();
        client_keys.derive_initial(&provider, &dcid, true).unwrap();

        let mut server_keys = ConnectionKeys::<Aes128GcmProvider>::new();
        server_keys.derive_initial(&provider, &dcid, false).unwrap();

        // Client encrypts, server decrypts
        let plaintext = b"hello server";
        let aad = b"packet header";
        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let send = client_keys.send_keys(Level::Initial).unwrap();
        let nonce = send.nonce(0);
        let ct_len = send
            .aead
            .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
            .unwrap();

        let recv = server_keys.recv_keys(Level::Initial).unwrap();
        let nonce = recv.nonce(0);
        let pt_len = recv.aead.open_in_place(&nonce, aad, &mut buf, ct_len).unwrap();
        assert_eq!(&buf[..pt_len], plaintext);
    }
}
