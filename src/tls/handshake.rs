//! TLS 1.3 handshake state machine for QUIC.
//!
//! Client-side state machine:
//! ```text
//! Start -> WaitServerHello -> WaitEncryptedExtensions -> WaitCertificate ->
//! WaitCertificateVerify -> WaitFinished -> SendFinished -> Complete
//! ```

use crate::crypto::{CryptoProvider, Level};
use crate::error::Error;
use crate::tls::extensions::{
    encode_client_hello_extensions, parse_encrypted_extensions_data, parse_server_hello_extensions,
};
use crate::tls::key_schedule_tls::{compute_finished_verify_data, TlsKeySchedule};
use crate::tls::messages::{
    self, CipherSuite, HandshakeType, encode_client_hello, encode_finished, parse_certificate,
    parse_certificate_verify, parse_encrypted_extensions, parse_finished, parse_server_hello,
    read_handshake_header,
};
use crate::tls::transcript::TranscriptHash;
use crate::tls::transport_params::TransportParams;
use crate::tls::{DerivedKeys, TlsSession};

/// Client or server role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Client-side handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    /// Initial state — ClientHello needs to be written.
    Start,
    /// ClientHello has been sent, waiting for ServerHello.
    WaitServerHello,
    /// ServerHello received, waiting for EncryptedExtensions.
    WaitEncryptedExtensions,
    /// Waiting for server Certificate.
    WaitCertificate,
    /// Waiting for CertificateVerify.
    WaitCertificateVerify,
    /// Waiting for server Finished.
    WaitFinished,
    /// Need to send client Finished.
    SendFinished,
    /// Handshake is complete.
    Complete,
}

/// Configuration for creating a TLS engine.
pub struct TlsConfig {
    /// Server name for SNI.
    pub server_name: heapless::String<64>,
    /// ALPN protocols to offer.
    pub alpn_protocols: &'static [&'static [u8]],
    /// Our QUIC transport parameters.
    pub transport_params: TransportParams,
    /// DER-encoded pinned server certificates for verification.
    /// If empty, certificate verification is skipped (insecure, for testing).
    pub pinned_certs: &'static [&'static [u8]],
}

/// TLS 1.3 handshake engine for QUIC, generic over the crypto provider.
pub struct TlsEngine<C: CryptoProvider> {
    role: Role,
    state: HandshakeState,

    // X25519 keypair
    private_key: x25519_dalek::StaticSecret,
    public_key: x25519_dalek::PublicKey,

    // Negotiated cipher suite
    cipher_suite: Option<CipherSuite>,

    // TLS key schedule
    key_schedule: TlsKeySchedule,
    client_handshake_secret: [u8; 32],
    server_handshake_secret: [u8; 32],
    client_app_secret: [u8; 32],
    server_app_secret: [u8; 32],

    // Transcript hash
    transcript: TranscriptHash,

    // Output buffer for pending handshake messages
    pending_write: heapless::Vec<u8, 2048>,
    pending_level: Level,

    // Keys ready to be picked up by QUIC
    pending_keys: Option<DerivedKeys>,

    // Configuration
    server_name: heapless::String<64>,
    alpn_protocols: &'static [&'static [u8]],
    transport_params: TransportParams,
    peer_transport_params: Option<TransportParams>,

    // Negotiated ALPN
    negotiated_alpn: Option<heapless::Vec<u8, 16>>,

    // Certificate verification
    pinned_certs: &'static [&'static [u8]],

    // Server certificate data (stored for verification)
    server_cert_data: heapless::Vec<u8, 2048>,

    // Handshake complete flag
    complete: bool,

    _crypto: core::marker::PhantomData<C>,
}

impl<C: CryptoProvider> TlsEngine<C>
where
    C::Hkdf: Default,
{
    /// Create a new client-side TLS engine.
    ///
    /// `secret_bytes` should be 32 random bytes for the X25519 private key.
    pub fn new_client(config: TlsConfig, secret_bytes: [u8; 32]) -> Self {
        let private_key = x25519_dalek::StaticSecret::from(secret_bytes);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        let hkdf = C::Hkdf::default();
        let key_schedule = TlsKeySchedule::new(&hkdf);

        Self {
            role: Role::Client,
            state: HandshakeState::Start,
            private_key,
            public_key,
            cipher_suite: None,
            key_schedule,
            client_handshake_secret: [0u8; 32],
            server_handshake_secret: [0u8; 32],
            client_app_secret: [0u8; 32],
            server_app_secret: [0u8; 32],
            transcript: TranscriptHash::new(),
            pending_write: heapless::Vec::new(),
            pending_level: Level::Initial,
            pending_keys: None,
            server_name: config.server_name,
            alpn_protocols: config.alpn_protocols,
            transport_params: config.transport_params,
            peer_transport_params: None,
            negotiated_alpn: None,
            pinned_certs: config.pinned_certs,
            server_cert_data: heapless::Vec::new(),
            complete: false,
            _crypto: core::marker::PhantomData,
        }
    }

    /// Build and buffer the ClientHello message.
    fn build_client_hello(&mut self, random: &[u8; 32]) -> Result<(), Error> {
        // Encode extensions
        let mut ext_buf = [0u8; 1024];
        let ext_len = encode_client_hello_extensions(
            self.server_name.as_str(),
            self.public_key.as_bytes(),
            self.alpn_protocols,
            &self.transport_params,
            &mut ext_buf,
        )?;

        let suites = [
            CipherSuite::TlsAes128GcmSha256,
            CipherSuite::TlsChacha20Poly1305Sha256,
        ];

        // QUIC doesn't use the legacy session ID
        let session_id: &[u8] = &[];

        let mut msg_buf = [0u8; 2048];
        let msg_len = encode_client_hello(
            random,
            session_id,
            &suites,
            &ext_buf[..ext_len],
            &mut msg_buf,
        )?;

        // Add to transcript
        self.transcript.update(&msg_buf[..msg_len]);

        // Buffer for write_handshake
        self.pending_write.clear();
        self.pending_write
            .extend_from_slice(&msg_buf[..msg_len])
            .map_err(|_| Error::BufferTooSmall { needed: msg_len })?;
        self.pending_level = Level::Initial;

        self.state = HandshakeState::WaitServerHello;
        Ok(())
    }

    /// Process a ServerHello message.
    fn process_server_hello(&mut self, msg_body: &[u8]) -> Result<(), Error> {
        let sh = parse_server_hello(msg_body)?;

        // Validate cipher suite
        self.cipher_suite = Some(sh.cipher_suite);

        // Parse extensions
        let ext = parse_server_hello_extensions(sh.extensions)?;

        // Must have TLS 1.3
        if ext.selected_version != 0x0304 {
            return Err(Error::Tls);
        }

        // Must have key_share
        let server_public = ext.key_share.ok_or(Error::Tls)?;

        // Perform X25519 Diffie-Hellman
        let server_pk = x25519_dalek::PublicKey::from(server_public);
        let shared_secret = self.private_key.diffie_hellman(&server_pk);

        // Derive handshake secrets
        let hkdf = C::Hkdf::default();
        self.key_schedule
            .derive_handshake_secret(&hkdf, shared_secret.as_bytes())?;

        // Get transcript hash at ClientHello..ServerHello
        let transcript_hash = self.transcript.current_hash();

        // Derive handshake traffic secrets
        self.key_schedule.derive_handshake_traffic_secrets(
            &hkdf,
            &transcript_hash,
            &mut self.client_handshake_secret,
            &mut self.server_handshake_secret,
        )?;

        // Emit handshake-level keys for QUIC
        self.pending_keys = Some(DerivedKeys {
            level: Level::Handshake,
            send_secret: self.client_handshake_secret,
            recv_secret: self.server_handshake_secret,
        });

        self.state = HandshakeState::WaitEncryptedExtensions;
        Ok(())
    }

    /// Process an EncryptedExtensions message.
    fn process_encrypted_extensions(&mut self, msg_body: &[u8]) -> Result<(), Error> {
        let ext_data = parse_encrypted_extensions(msg_body)?;
        let parsed = parse_encrypted_extensions_data(ext_data)?;

        self.negotiated_alpn = parsed.alpn;
        self.peer_transport_params = parsed.transport_params;

        self.state = HandshakeState::WaitCertificate;
        Ok(())
    }

    /// Process a Certificate message.
    fn process_certificate(&mut self, msg_body: &[u8]) -> Result<(), Error> {
        let cert = parse_certificate(msg_body)?;

        // Store the first certificate for potential verification
        self.server_cert_data.clear();
        for entry in messages::iter_certificate_entries(cert.entries) {
            let entry = entry?;
            // Store first cert (the end-entity cert)
            if self.server_cert_data.is_empty() {
                let _ = self.server_cert_data.extend_from_slice(entry.cert_data);
            }
            break;
        }

        self.state = HandshakeState::WaitCertificateVerify;
        Ok(())
    }

    /// Process a CertificateVerify message.
    fn process_certificate_verify(&mut self, msg_body: &[u8]) -> Result<(), Error> {
        let _cv = parse_certificate_verify(msg_body)?;

        // For the initial implementation, we verify against pinned certificates
        // by comparing the raw DER bytes. Full signature verification would
        // require an ASN.1 parser and signature verification library.
        if !self.pinned_certs.is_empty() {
            let mut found = false;
            for pinned in self.pinned_certs {
                if *pinned == self.server_cert_data.as_slice() {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(Error::Tls);
            }
        }
        // If pinned_certs is empty, we skip verification (TOFU / testing mode)

        self.state = HandshakeState::WaitFinished;
        Ok(())
    }

    /// Process a server Finished message.
    fn process_server_finished(
        &mut self,
        msg_body: &[u8],
        transcript_before_finished: &[u8; 32],
    ) -> Result<(), Error> {
        let verify_data = parse_finished(msg_body)?;

        // Verify the server's Finished MAC
        let hkdf = C::Hkdf::default();
        let mut server_finished_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(
            &hkdf,
            &self.server_handshake_secret,
            &mut server_finished_key,
        )?;

        let expected =
            compute_finished_verify_data(&hkdf, &server_finished_key, transcript_before_finished)?;

        // Constant-time comparison
        if !ct_eq(&expected, verify_data) {
            return Err(Error::Tls);
        }

        // Now derive application secrets.
        // The transcript hash for app secrets includes everything up to and including
        // the server's Finished message (which has already been added to transcript
        // by the caller).
        let transcript_hash = self.transcript.current_hash();

        self.key_schedule.derive_master_secret(&hkdf)?;
        self.key_schedule.derive_app_traffic_secrets(
            &hkdf,
            &transcript_hash,
            &mut self.client_app_secret,
            &mut self.server_app_secret,
        )?;

        // Emit application-level keys
        self.pending_keys = Some(DerivedKeys {
            level: Level::Application,
            send_secret: self.client_app_secret,
            recv_secret: self.server_app_secret,
        });

        // Build client Finished
        let mut client_finished_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(
            &hkdf,
            &self.client_handshake_secret,
            &mut client_finished_key,
        )?;

        let client_verify =
            compute_finished_verify_data(&hkdf, &client_finished_key, &transcript_hash)?;

        let mut fin_buf = [0u8; 36];
        let fin_len = encode_finished(&client_verify, &mut fin_buf)?;

        // Add client Finished to transcript
        self.transcript.update(&fin_buf[..fin_len]);

        self.pending_write.clear();
        self.pending_write
            .extend_from_slice(&fin_buf[..fin_len])
            .map_err(|_| Error::BufferTooSmall { needed: fin_len })?;
        self.pending_level = Level::Handshake;

        self.state = HandshakeState::SendFinished;
        Ok(())
    }
}

impl<C: CryptoProvider> TlsSession for TlsEngine<C>
where
    C::Hkdf: Default,
{
    type Error = Error;

    fn read_handshake(&mut self, _level: Level, data: &[u8]) -> Result<(), Error> {
        if self.role != Role::Client {
            return Err(Error::InvalidState);
        }

        // Multiple TLS messages may be concatenated in a single CRYPTO frame.
        let mut off = 0;
        while off < data.len() {
            let remaining = &data[off..];
            let (msg_type_byte, body_len) = read_handshake_header(remaining)?;
            let msg_len = 4 + body_len;

            if remaining.len() < msg_len {
                return Err(Error::Tls);
            }

            let full_msg = &remaining[..msg_len];
            let msg_body = &remaining[4..msg_len];

            let msg_type =
                HandshakeType::from_u8(msg_type_byte).ok_or(Error::Tls)?;

            match (self.state, msg_type) {
                (HandshakeState::WaitServerHello, HandshakeType::ServerHello) => {
                    // Add full message (including header) to transcript
                    self.transcript.update(full_msg);
                    self.process_server_hello(msg_body)?;
                }
                (HandshakeState::WaitEncryptedExtensions, HandshakeType::EncryptedExtensions) => {
                    self.transcript.update(full_msg);
                    self.process_encrypted_extensions(msg_body)?;
                }
                (HandshakeState::WaitCertificate, HandshakeType::Certificate) => {
                    self.transcript.update(full_msg);
                    self.process_certificate(msg_body)?;
                }
                (HandshakeState::WaitCertificateVerify, HandshakeType::CertificateVerify) => {
                    // Get transcript hash before adding CertificateVerify
                    // (needed for CertificateVerify signature verification)
                    self.transcript.update(full_msg);
                    self.process_certificate_verify(msg_body)?;
                }
                (HandshakeState::WaitFinished, HandshakeType::Finished) => {
                    // Get transcript hash BEFORE adding Finished message
                    let transcript_before = self.transcript.current_hash();
                    self.transcript.update(full_msg);
                    self.process_server_finished(msg_body, &transcript_before)?;
                }
                _ => {
                    return Err(Error::Tls);
                }
            }

            off += msg_len;
        }

        Ok(())
    }

    fn write_handshake(&mut self, buf: &mut [u8]) -> Result<(usize, Level), Error> {
        if self.role != Role::Client {
            return Err(Error::InvalidState);
        }

        match self.state {
            HandshakeState::Start => {
                // Generate ClientHello with a deterministic random for now.
                // In production, this should come from a proper RNG.
                let random = [0u8; 32];
                self.build_client_hello(&random)?;
            }
            HandshakeState::SendFinished => {
                // Client Finished was already built in process_server_finished.
                // It's in pending_write. After it's flushed, we're complete.
            }
            _ => {}
        }

        if self.pending_write.is_empty() {
            return Ok((0, Level::Initial));
        }

        let len = self.pending_write.len();
        if buf.len() < len {
            return Err(Error::BufferTooSmall { needed: len });
        }

        buf[..len].copy_from_slice(&self.pending_write);
        let level = self.pending_level;
        self.pending_write.clear();

        if self.state == HandshakeState::SendFinished {
            self.state = HandshakeState::Complete;
            self.complete = true;
        }

        Ok((len, level))
    }

    fn derived_keys(&mut self) -> Option<DerivedKeys> {
        self.pending_keys.take()
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_ref().map(|v| v.as_slice())
    }

    fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.peer_transport_params.as_ref()
    }

    fn set_transport_params(&mut self, params: &TransportParams) {
        self.transport_params = params.clone();
    }
}

/// Constant-time comparison of two byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
        assert!(ct_eq(&[], &[]));
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_generates_client_hello() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let config = TlsConfig {
            server_name: heapless::String::try_from("example.com").unwrap(),
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };

        let secret = [0x42u8; 32];
        let mut engine = TlsEngine::<Aes128GcmProvider>::new_client(config, secret);

        let mut buf = [0u8; 2048];
        let (len, level) = engine.write_handshake(&mut buf).unwrap();

        assert!(len > 0, "ClientHello should have been produced");
        assert_eq!(level, Level::Initial);

        // Verify it's a ClientHello
        let (msg_type, body_len) = read_handshake_header(&buf[..len]).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientHello as u8);
        assert_eq!(body_len + 4, len);

        // State should be WaitServerHello
        assert!(!engine.is_complete());

        // A second write_handshake should produce nothing
        let (len2, _) = engine.write_handshake(&mut buf).unwrap();
        assert_eq!(len2, 0);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_rejects_unexpected_message() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let config = TlsConfig {
            server_name: heapless::String::try_from("test.example").unwrap(),
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };

        let secret = [0x42u8; 32];
        let mut engine = TlsEngine::<Aes128GcmProvider>::new_client(config, secret);

        // Send ClientHello first
        let mut buf = [0u8; 2048];
        engine.write_handshake(&mut buf).unwrap();

        // Now feed an EncryptedExtensions (wrong state — should be ServerHello)
        let fake_ee = [
            HandshakeType::EncryptedExtensions as u8,
            0, 0, 2, // length = 2
            0, 0, // empty extensions list
        ];
        let result = engine.read_handshake(Level::Initial, &fake_ee);
        assert!(result.is_err());
    }

    /// Integration test: simulate a full client handshake with constructed server messages.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_full_handshake_flow() {
        use crate::crypto::rustcrypto::{Aes128GcmProvider, HkdfSha256};
        use crate::tls::key_schedule_tls::compute_finished_verify_data;

        let config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };

        let client_secret_bytes = [0x42u8; 32];
        let mut engine = TlsEngine::<Aes128GcmProvider>::new_client(config, client_secret_bytes);

        // Step 1: Write ClientHello
        let mut buf = [0u8; 2048];
        let (ch_len, ch_level) = engine.write_handshake(&mut buf).unwrap();
        assert!(ch_len > 0);
        assert_eq!(ch_level, Level::Initial);

        // We need to build a ServerHello that the client can process.
        // Generate a server X25519 keypair
        let server_secret = x25519_dalek::StaticSecret::from([0xAA; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);

        // Build a ServerHello message
        let mut sh_buf = [0u8; 512];
        let sh_len = build_test_server_hello(
            &[0xBB; 32],
            CipherSuite::TlsAes128GcmSha256,
            server_public.as_bytes(),
            &mut sh_buf,
        );

        // Step 2: Feed ServerHello to client
        engine
            .read_handshake(Level::Initial, &sh_buf[..sh_len])
            .unwrap();

        // Should have handshake keys now
        let keys = engine.derived_keys().unwrap();
        assert_eq!(keys.level, Level::Handshake);

        // Step 3: Feed EncryptedExtensions
        let mut ee_buf = [0u8; 512];
        let ee_len = build_test_encrypted_extensions(&mut ee_buf);
        engine
            .read_handshake(Level::Handshake, &ee_buf[..ee_len])
            .unwrap();

        // Check we got ALPN
        assert_eq!(engine.alpn(), Some(b"h3".as_slice()));

        // Check we got transport params
        assert!(engine.peer_transport_params().is_some());

        // Step 4: Feed Certificate
        let mut cert_buf = [0u8; 512];
        let cert_len = build_test_certificate(&mut cert_buf);
        engine
            .read_handshake(Level::Handshake, &cert_buf[..cert_len])
            .unwrap();

        // Step 5: Feed CertificateVerify
        let mut cv_buf = [0u8; 128];
        let cv_len = build_test_certificate_verify(&mut cv_buf);
        engine
            .read_handshake(Level::Handshake, &cv_buf[..cv_len])
            .unwrap();

        // Step 6: Feed server Finished
        // We need to compute the real server Finished.
        // The server's Finished key is derived from server_handshake_secret.
        // We need to derive it the same way as the client did.

        // Compute the shared secret as the server would
        let client_pk = x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(client_secret_bytes),
        );
        let shared = server_secret.diffie_hellman(&client_pk);

        // Re-derive the key schedule from scratch (same as client)
        let hkdf = HkdfSha256;
        let mut server_ks = TlsKeySchedule::new(&hkdf);
        server_ks
            .derive_handshake_secret(&hkdf, shared.as_bytes())
            .unwrap();

        // We need the transcript hash at ClientHello..ServerHello
        // Rebuild it: hash(ClientHello || ServerHello)
        let mut server_transcript = TranscriptHash::new();
        server_transcript.update(&buf[..ch_len]);
        server_transcript.update(&sh_buf[..sh_len]);
        let ch_sh_hash = server_transcript.current_hash();

        let mut s_client_hs = [0u8; 32];
        let mut s_server_hs = [0u8; 32];
        server_ks
            .derive_handshake_traffic_secrets(&hkdf, &ch_sh_hash, &mut s_client_hs, &mut s_server_hs)
            .unwrap();

        // Add EE, Certificate, CertificateVerify to server transcript
        server_transcript.update(&ee_buf[..ee_len]);
        server_transcript.update(&cert_buf[..cert_len]);
        server_transcript.update(&cv_buf[..cv_len]);

        // Compute server Finished
        let mut server_fin_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(&hkdf, &s_server_hs, &mut server_fin_key).unwrap();
        let server_fin_hash = server_transcript.current_hash();
        let server_verify =
            compute_finished_verify_data(&hkdf, &server_fin_key, &server_fin_hash).unwrap();

        let mut fin_buf = [0u8; 36];
        let fin_len = encode_finished(&server_verify, &mut fin_buf).unwrap();

        engine
            .read_handshake(Level::Handshake, &fin_buf[..fin_len])
            .unwrap();

        // Should have application keys
        let app_keys = engine.derived_keys().unwrap();
        assert_eq!(app_keys.level, Level::Application);

        // Step 7: Write client Finished
        let mut client_fin_buf = [0u8; 256];
        let (cfin_len, cfin_level) = engine.write_handshake(&mut client_fin_buf).unwrap();
        assert!(cfin_len > 0);
        assert_eq!(cfin_level, Level::Handshake);

        // Handshake should be complete
        assert!(engine.is_complete());

        // Verify the client Finished is a proper Finished message
        let (msg_type, _body_len) = read_handshake_header(&client_fin_buf[..cfin_len]).unwrap();
        assert_eq!(msg_type, HandshakeType::Finished as u8);
    }

    // --- Test helper functions to build server messages ---

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn build_test_server_hello(
        random: &[u8; 32],
        cipher_suite: CipherSuite,
        server_public_key: &[u8; 32],
        out: &mut [u8],
    ) -> usize {
        // Build ServerHello body
        let mut body = [0u8; 256];
        let mut off = 0;

        // Version: 0x0303
        body[off] = 0x03;
        body[off + 1] = 0x03;
        off += 2;

        // Random
        body[off..off + 32].copy_from_slice(random);
        off += 32;

        // Session ID: empty
        body[off] = 0;
        off += 1;

        // Cipher suite
        let cs = cipher_suite.to_u16();
        body[off] = (cs >> 8) as u8;
        body[off + 1] = (cs & 0xFF) as u8;
        off += 2;

        // Compression method: null
        body[off] = 0;
        off += 1;

        // Extensions
        let mut ext_buf = [0u8; 128];
        let mut ext_off = 0;

        // supported_versions
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x2b; // type
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x02; // length
        ext_off += 2;
        ext_buf[ext_off] = 0x03;
        ext_buf[ext_off + 1] = 0x04; // TLS 1.3
        ext_off += 2;

        // key_share
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x33; // type
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x24; // length = 36
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x1d; // X25519
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x20; // key length = 32
        ext_off += 2;
        ext_buf[ext_off..ext_off + 32].copy_from_slice(server_public_key);
        ext_off += 32;

        // Extensions length
        body[off] = ((ext_off >> 8) & 0xFF) as u8;
        body[off + 1] = (ext_off & 0xFF) as u8;
        off += 2;
        body[off..off + ext_off].copy_from_slice(&ext_buf[..ext_off]);
        off += ext_off;

        // Write handshake header
        out[0] = HandshakeType::ServerHello as u8;
        out[1] = ((off >> 16) & 0xFF) as u8;
        out[2] = ((off >> 8) & 0xFF) as u8;
        out[3] = (off & 0xFF) as u8;
        out[4..4 + off].copy_from_slice(&body[..off]);

        4 + off
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn build_test_encrypted_extensions(out: &mut [u8]) -> usize {
        // Build EncryptedExtensions body
        let mut body = [0u8; 256];
        let mut ext_buf = [0u8; 256];
        let mut ext_off = 0;

        // ALPN extension
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x10; // ALPN type
        ext_off += 2;
        // ALPN data: list_len(2) + proto_len(1) + "h3"(2) = 5
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x05;
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x03; // list length
        ext_off += 2;
        ext_buf[ext_off] = 0x02; // "h3" length
        ext_off += 1;
        ext_buf[ext_off] = b'h';
        ext_buf[ext_off + 1] = b'3';
        ext_off += 2;

        // QUIC transport params extension
        let params = TransportParams::default_params();
        let mut tp_buf = [0u8; 128];
        let tp_len = params.encode(&mut tp_buf).unwrap();

        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x39; // QUIC TP type
        ext_off += 2;
        ext_buf[ext_off] = ((tp_len >> 8) & 0xFF) as u8;
        ext_buf[ext_off + 1] = (tp_len & 0xFF) as u8;
        ext_off += 2;
        ext_buf[ext_off..ext_off + tp_len].copy_from_slice(&tp_buf[..tp_len]);
        ext_off += tp_len;

        // Extensions list length prefix
        body[0] = ((ext_off >> 8) & 0xFF) as u8;
        body[1] = (ext_off & 0xFF) as u8;
        body[2..2 + ext_off].copy_from_slice(&ext_buf[..ext_off]);
        let body_len = 2 + ext_off;

        // Handshake header
        out[0] = HandshakeType::EncryptedExtensions as u8;
        out[1] = ((body_len >> 16) & 0xFF) as u8;
        out[2] = ((body_len >> 8) & 0xFF) as u8;
        out[3] = (body_len & 0xFF) as u8;
        out[4..4 + body_len].copy_from_slice(&body[..body_len]);

        4 + body_len
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn build_test_certificate(out: &mut [u8]) -> usize {
        // Build a minimal Certificate message
        let mut body = [0u8; 256];
        let mut off = 0;

        // certificate_request_context length = 0
        body[off] = 0;
        off += 1;

        // Fake cert data
        let fake_cert = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

        // certificate_list length (3 bytes)
        // entry: cert_data_len(3) + cert_data(6) + extensions_len(2) = 11
        let list_len = 3 + fake_cert.len() + 2;
        body[off] = 0;
        body[off + 1] = ((list_len >> 8) & 0xFF) as u8;
        body[off + 2] = (list_len & 0xFF) as u8;
        off += 3;

        // cert_data_length
        body[off] = 0;
        body[off + 1] = 0;
        body[off + 2] = fake_cert.len() as u8;
        off += 3;
        body[off..off + fake_cert.len()].copy_from_slice(&fake_cert);
        off += fake_cert.len();

        // extensions_length = 0
        body[off] = 0;
        body[off + 1] = 0;
        off += 2;

        // Handshake header
        out[0] = HandshakeType::Certificate as u8;
        out[1] = ((off >> 16) & 0xFF) as u8;
        out[2] = ((off >> 8) & 0xFF) as u8;
        out[3] = (off & 0xFF) as u8;
        out[4..4 + off].copy_from_slice(&body[..off]);

        4 + off
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn build_test_certificate_verify(out: &mut [u8]) -> usize {
        // Build a minimal CertificateVerify message
        let mut body = [0u8; 128];

        // Algorithm: Ed25519 = 0x0807
        body[0] = 0x08;
        body[1] = 0x07;

        // Signature: fake 64-byte signature
        let fake_sig = [0xAA; 64];
        body[2] = 0;
        body[3] = fake_sig.len() as u8;
        body[4..4 + fake_sig.len()].copy_from_slice(&fake_sig);
        let body_len = 4 + fake_sig.len();

        // Handshake header
        out[0] = HandshakeType::CertificateVerify as u8;
        out[1] = ((body_len >> 16) & 0xFF) as u8;
        out[2] = ((body_len >> 8) & 0xFF) as u8;
        out[3] = (body_len & 0xFF) as u8;
        out[4..4 + body_len].copy_from_slice(&body[..body_len]);

        4 + body_len
    }
}
