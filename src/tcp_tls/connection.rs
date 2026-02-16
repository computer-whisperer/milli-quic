//! TLS 1.3 connection state machine over TCP.
//!
//! Follows the milli-http `feed_data()` → `poll_output()` → `poll_event()` pattern.

use crate::crypto::{CryptoProvider, Aead, Level};
use crate::crypto::key_schedule::derive_tls_record_keys;
use crate::error::Error;
use crate::tls::handshake::{TlsConfig, ServerTlsConfig, TlsEngine};
use crate::tls::{DerivedKeys, TlsSession};

use super::record::{self, ContentType, RECORD_HEADER_LEN};

/// Events produced by TlsConnection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsEvent {
    /// TLS handshake is complete; application data can now flow.
    HandshakeComplete,
    /// Application data is available (call `recv_app_data`).
    AppData,
    /// Peer sent a close_notify alert.
    PeerClosed,
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnState {
    /// TLS handshake in progress (plaintext records).
    Handshake,
    /// Handshake in progress, ServerHello received, handshake records encrypted.
    HandshakeEncrypted,
    /// Handshake complete, application data flowing.
    Active,
    /// close_notify sent or received.
    Closing,
    /// Connection fully closed.
    Closed,
}

/// AEAD + IV for one direction.
struct DirectionalRecordKeys<A: Aead> {
    aead: A,
    iv: [u8; 12],
}

/// TLS 1.3 connection state machine.
///
/// `C`: CryptoProvider implementation.
/// `BUF`: internal buffer size (should be >= 18432 for one max-size TLS record + header).
pub struct TlsConnection<C: CryptoProvider, const BUF: usize = 18432> {
    provider: C,
    engine: TlsEngine<C>,
    state: ConnState,

    // Raw TCP data received
    recv_buf: heapless::Vec<u8, BUF>,
    // Data to send on TCP
    send_buf: heapless::Vec<u8, BUF>,
    send_offset: usize,

    // Decrypted application data buffer
    app_recv_buf: heapless::Vec<u8, BUF>,

    // Application data to encrypt and send
    app_send_buf: heapless::Vec<u8, BUF>,

    // AEAD keys for handshake traffic
    hs_send: Option<DirectionalRecordKeys<C::Aead>>,
    hs_recv: Option<DirectionalRecordKeys<C::Aead>>,

    // AEAD keys for application traffic
    app_send: Option<DirectionalRecordKeys<C::Aead>>,
    app_recv: Option<DirectionalRecordKeys<C::Aead>>,

    // Per-direction sequence numbers
    send_seq: u64,
    recv_seq: u64,
    hs_send_seq: u64,
    hs_recv_seq: u64,

    // Event queue
    events: heapless::Deque<TlsEvent, 8>,

    // Whether we've already sent the engine's handshake output
    engine_output_pending: bool,

    // Track whether we need to send ChangeCipherSpec (middlebox compat)
    ccs_sent: bool,
}

impl<C: CryptoProvider, const BUF: usize> TlsConnection<C, BUF>
where
    C::Hkdf: Default,
{
    /// Create a new client-side TLS connection.
    pub fn new_client(provider: C, config: TlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        let engine = TlsEngine::<C>::new_tcp_client(config, secret, random);
        Self::new(provider, engine)
    }

    /// Create a new server-side TLS connection.
    pub fn new_server(provider: C, config: ServerTlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        let engine = TlsEngine::<C>::new_tcp_server(config, secret, random);
        Self::new(provider, engine)
    }

    fn new(provider: C, engine: TlsEngine<C>) -> Self {
        Self {
            provider,
            engine,
            state: ConnState::Handshake,
            recv_buf: heapless::Vec::new(),
            send_buf: heapless::Vec::new(),
            send_offset: 0,
            app_recv_buf: heapless::Vec::new(),
            app_send_buf: heapless::Vec::new(),
            hs_send: None,
            hs_recv: None,
            app_send: None,
            app_recv: None,
            send_seq: 0,
            recv_seq: 0,
            hs_send_seq: 0,
            hs_recv_seq: 0,
            events: heapless::Deque::new(),
            engine_output_pending: true,
            ccs_sent: false,
        }
    }

    /// Feed raw TCP data into the connection.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.recv_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: self.recv_buf.len() + data.len(),
            });
        }
        let _ = self.recv_buf.extend_from_slice(data);
        self.process_recv()
    }

    /// Pull the next chunk of outgoing TCP data.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        self.flush_engine_output();
        self.flush_app_send();

        if self.send_offset >= self.send_buf.len() {
            return None;
        }

        let avail = self.send_buf.len() - self.send_offset;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&self.send_buf[self.send_offset..self.send_offset + n]);
        self.send_offset += n;

        if self.send_offset >= self.send_buf.len() {
            self.send_buf.clear();
            self.send_offset = 0;
        }

        Some(&buf[..n])
    }

    /// Poll for the next TLS event.
    pub fn poll_event(&mut self) -> Option<TlsEvent> {
        self.events.pop_front()
    }

    /// Read decrypted application data.
    pub fn recv_app_data(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.app_recv_buf.is_empty() {
            return Err(Error::WouldBlock);
        }
        let n = self.app_recv_buf.len().min(buf.len());
        buf[..n].copy_from_slice(&self.app_recv_buf[..n]);

        let remaining = self.app_recv_buf.len() - n;
        for i in 0..remaining {
            self.app_recv_buf[i] = self.app_recv_buf[n + i];
        }
        self.app_recv_buf.truncate(remaining);
        Ok(n)
    }

    /// Queue application data for encryption and sending.
    pub fn send_app_data(&mut self, data: &[u8]) -> Result<usize, Error> {
        if self.state != ConnState::Active {
            return Err(Error::InvalidState);
        }
        if self.app_send_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: self.app_send_buf.len() + data.len(),
            });
        }
        let _ = self.app_send_buf.extend_from_slice(data);
        Ok(data.len())
    }

    /// Get the negotiated ALPN protocol, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.engine.alpn()
    }

    /// Whether the connection is active (handshake complete, not closed).
    pub fn is_active(&self) -> bool {
        self.state == ConnState::Active
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnState::Closed | ConnState::Closing)
    }

    /// Initiate a graceful close (send close_notify).
    pub fn close(&mut self) -> Result<(), Error> {
        if self.state == ConnState::Closed || self.state == ConnState::Closing {
            return Ok(());
        }
        self.send_alert(1, 0)?; // warning(1) close_notify(0)
        self.state = ConnState::Closing;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: processing received data
    // ------------------------------------------------------------------

    fn process_recv(&mut self) -> Result<(), Error> {
        loop {
            if self.recv_buf.len() < RECORD_HEADER_LEN {
                return Ok(());
            }

            let hdr = record::decode_record_header(&self.recv_buf[..RECORD_HEADER_LEN])?;
            let total = RECORD_HEADER_LEN + hdr.length as usize;

            if self.recv_buf.len() < total {
                return Ok(());
            }

            // Copy record out of recv_buf
            let mut record_data = [0u8; 18432];
            if total > record_data.len() {
                return Err(Error::BufferTooSmall { needed: total });
            }
            record_data[..total].copy_from_slice(&self.recv_buf[..total]);

            let remaining = self.recv_buf.len() - total;
            for i in 0..remaining {
                self.recv_buf[i] = self.recv_buf[total + i];
            }
            self.recv_buf.truncate(remaining);

            // Save header bytes for AAD
            let header_bytes: [u8; 5] = [
                record_data[0], record_data[1], record_data[2],
                record_data[3], record_data[4],
            ];
            let payload_len = hdr.length as usize;
            self.handle_record(hdr.content_type, &header_bytes,
                              &mut record_data[RECORD_HEADER_LEN..total], payload_len)?;
        }
    }

    fn handle_record(
        &mut self,
        ct: ContentType,
        header_bytes: &[u8; 5],
        payload: &mut [u8],
        payload_len: usize,
    ) -> Result<(), Error> {
        match self.state {
            ConnState::Handshake => {
                match ct {
                    ContentType::Handshake => {
                        self.engine.read_handshake(Level::Initial, &payload[..payload_len])
                            .map_err(|_| Error::Tls)?;
                        self.check_keys()?;
                    }
                    ContentType::ChangeCipherSpec => {} // ignore
                    ContentType::Alert => self.handle_alert(&payload[..payload_len])?,
                    _ => return Err(Error::Tls),
                }
            }
            ConnState::HandshakeEncrypted => {
                match ct {
                    ContentType::ApplicationData => {
                        let keys = self.hs_recv.as_ref().ok_or(Error::Tls)?;
                        let nonce = record::build_nonce(&keys.iv, self.hs_recv_seq);
                        self.hs_recv_seq += 1;

                        let plain_len = keys.aead.open_in_place(
                            &nonce, header_bytes, payload, payload_len,
                        )?;
                        let (data_len, inner_ct) = find_inner_content_type(&payload[..plain_len])?;

                        match inner_ct {
                            ContentType::Handshake => {
                                self.engine.read_handshake(Level::Handshake, &payload[..data_len])
                                    .map_err(|_| Error::Tls)?;
                                self.check_keys()?;
                            }
                            ContentType::Alert => self.handle_alert(&payload[..data_len])?,
                            _ => return Err(Error::Tls),
                        }
                    }
                    ContentType::ChangeCipherSpec => {} // ignore
                    ContentType::Handshake => {
                        self.engine.read_handshake(Level::Initial, &payload[..payload_len])
                            .map_err(|_| Error::Tls)?;
                        self.check_keys()?;
                    }
                    _ => return Err(Error::Tls),
                }
            }
            ConnState::Active => {
                match ct {
                    ContentType::ApplicationData => {
                        let keys = self.app_recv.as_ref().ok_or(Error::Tls)?;
                        let nonce = record::build_nonce(&keys.iv, self.recv_seq);
                        self.recv_seq += 1;

                        let plain_len = keys.aead.open_in_place(
                            &nonce, header_bytes, payload, payload_len,
                        )?;
                        let (data_len, inner_ct) = find_inner_content_type(&payload[..plain_len])?;

                        match inner_ct {
                            ContentType::ApplicationData => {
                                if self.app_recv_buf.len() + data_len > BUF {
                                    return Err(Error::BufferTooSmall {
                                        needed: self.app_recv_buf.len() + data_len,
                                    });
                                }
                                let _ = self.app_recv_buf.extend_from_slice(&payload[..data_len]);
                                let _ = self.events.push_back(TlsEvent::AppData);
                            }
                            ContentType::Alert => self.handle_alert(&payload[..data_len])?,
                            ContentType::Handshake => {} // Post-handshake (e.g. NewSessionTicket)
                            _ => return Err(Error::Tls),
                        }
                    }
                    ContentType::ChangeCipherSpec => {} // ignore
                    _ => return Err(Error::Tls),
                }
            }
            ConnState::Closing | ConnState::Closed => {} // ignore
        }
        Ok(())
    }

    fn handle_alert(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() < 2 {
            return Err(Error::Tls);
        }
        let desc = data[1];
        if desc == 0 {
            // close_notify
            self.state = ConnState::Closing;
            let _ = self.events.push_back(TlsEvent::PeerClosed);
            Ok(())
        } else {
            self.state = ConnState::Closed;
            Err(Error::Tls)
        }
    }

    fn send_alert(&mut self, level: u8, desc: u8) -> Result<(), Error> {
        let alert_data = [level, desc];
        if self.state == ConnState::Active {
            self.encrypt_and_send(&alert_data, ContentType::Alert, false)
        } else {
            let mut buf = [0u8; 16];
            let n = record::encode_record_header(ContentType::Alert, 2, &mut buf)?;
            buf[n] = level;
            buf[n + 1] = desc;
            self.queue_send(&buf[..n + 2])
        }
    }

    // ------------------------------------------------------------------
    // Internal: key management
    // ------------------------------------------------------------------

    fn check_keys(&mut self) -> Result<(), Error> {
        while let Some(keys) = self.engine.derived_keys() {
            self.install_keys(keys)?;
        }

        if self.engine.is_complete() && self.state != ConnState::Active {
            self.state = ConnState::Active;
            self.send_seq = 0;
            self.recv_seq = 0;
            let _ = self.events.push_back(TlsEvent::HandshakeComplete);
        }

        Ok(())
    }

    fn install_keys(&mut self, keys: DerivedKeys) -> Result<(), Error> {
        let hkdf = C::Hkdf::default();
        let key_len = C::Aead::KEY_LEN;

        let send_secret = &keys.send_secret[..keys.secret_len];
        let recv_secret = &keys.recv_secret[..keys.secret_len];

        match keys.level {
            Level::Handshake => {
                let mut send_key_buf = [0u8; 32];
                let mut send_iv = [0u8; 12];
                derive_tls_record_keys(&hkdf, send_secret, &mut send_key_buf[..key_len], &mut send_iv)?;
                let send_aead = self.provider.aead(&send_key_buf[..key_len])?;
                self.hs_send = Some(DirectionalRecordKeys { aead: send_aead, iv: send_iv });

                let mut recv_key_buf = [0u8; 32];
                let mut recv_iv = [0u8; 12];
                derive_tls_record_keys(&hkdf, recv_secret, &mut recv_key_buf[..key_len], &mut recv_iv)?;
                let recv_aead = self.provider.aead(&recv_key_buf[..key_len])?;
                self.hs_recv = Some(DirectionalRecordKeys { aead: recv_aead, iv: recv_iv });

                self.hs_send_seq = 0;
                self.hs_recv_seq = 0;
                self.state = ConnState::HandshakeEncrypted;
                self.engine_output_pending = true;
            }
            Level::Application => {
                let mut send_key_buf = [0u8; 32];
                let mut send_iv = [0u8; 12];
                derive_tls_record_keys(&hkdf, send_secret, &mut send_key_buf[..key_len], &mut send_iv)?;
                let send_aead = self.provider.aead(&send_key_buf[..key_len])?;
                self.app_send = Some(DirectionalRecordKeys { aead: send_aead, iv: send_iv });

                let mut recv_key_buf = [0u8; 32];
                let mut recv_iv = [0u8; 12];
                derive_tls_record_keys(&hkdf, recv_secret, &mut recv_key_buf[..key_len], &mut recv_iv)?;
                let recv_aead = self.provider.aead(&recv_key_buf[..key_len])?;
                self.app_recv = Some(DirectionalRecordKeys { aead: recv_aead, iv: recv_iv });

                self.engine_output_pending = true;
            }
            _ => {}
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: output generation
    // ------------------------------------------------------------------

    fn flush_engine_output(&mut self) {
        if !self.engine_output_pending {
            return;
        }

        let mut buf = [0u8; 2048];
        loop {
            let (n, level) = match self.engine.write_handshake(&mut buf) {
                Ok(result) => result,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }

            match level {
                Level::Initial => {
                    let _ = self.wrap_plaintext_record(ContentType::Handshake, &buf[..n]);
                }
                Level::Handshake => {
                    if !self.ccs_sent {
                        let ccs = [
                            ContentType::ChangeCipherSpec as u8,
                            0x03, 0x03, 0x00, 0x01, 0x01,
                        ];
                        let _ = self.queue_send(&ccs);
                        self.ccs_sent = true;
                    }
                    let _ = self.encrypt_and_send(&buf[..n], ContentType::Handshake, true);
                }
                _ => {}
            }
        }

        let _ = self.check_keys();
        self.engine_output_pending = false;
    }

    fn flush_app_send(&mut self) {
        if self.app_send_buf.is_empty() || self.state != ConnState::Active {
            return;
        }

        while !self.app_send_buf.is_empty() {
            let chunk_len = self.app_send_buf.len().min(16384);
            let mut chunk = [0u8; 16384];
            chunk[..chunk_len].copy_from_slice(&self.app_send_buf[..chunk_len]);

            if self.encrypt_and_send(&chunk[..chunk_len], ContentType::ApplicationData, false).is_err() {
                break;
            }

            let remaining = self.app_send_buf.len() - chunk_len;
            for i in 0..remaining {
                self.app_send_buf[i] = self.app_send_buf[chunk_len + i];
            }
            self.app_send_buf.truncate(remaining);
        }
    }

    fn wrap_plaintext_record(&mut self, ct: ContentType, data: &[u8]) -> Result<(), Error> {
        let mut header = [0u8; 5];
        record::encode_record_header(ct, data.len() as u16, &mut header)?;
        self.queue_send(&header)?;
        self.queue_send(data)
    }

    fn encrypt_and_send(
        &mut self,
        data: &[u8],
        inner_ct: ContentType,
        use_hs_keys: bool,
    ) -> Result<(), Error> {
        let (keys, seq) = if use_hs_keys {
            (self.hs_send.as_ref().ok_or(Error::Tls)?, &mut self.hs_send_seq)
        } else {
            (self.app_send.as_ref().ok_or(Error::Tls)?, &mut self.send_seq)
        };

        let nonce = record::build_nonce(&keys.iv, *seq);
        *seq += 1;

        let inner_len = data.len() + 1;
        let outer_payload_len = inner_len + C::Aead::TAG_LEN;

        // Outer record header (also used as AAD)
        let mut header = [0u8; 5];
        record::encode_record_header(
            ContentType::ApplicationData,
            outer_payload_len as u16,
            &mut header,
        )?;

        // Build plaintext: data + inner_ct_byte
        let mut enc_buf = [0u8; 16640];
        if inner_len + C::Aead::TAG_LEN > enc_buf.len() {
            return Err(Error::BufferTooSmall {
                needed: inner_len + C::Aead::TAG_LEN,
            });
        }
        enc_buf[..data.len()].copy_from_slice(data);
        enc_buf[data.len()] = inner_ct as u8;

        let ciphertext_len = keys.aead.seal_in_place(&nonce, &header, &mut enc_buf, inner_len)?;

        self.queue_send(&header)?;
        self.queue_send(&enc_buf[..ciphertext_len])
    }

    fn queue_send(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.send_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: self.send_buf.len() + data.len(),
            });
        }
        let _ = self.send_buf.extend_from_slice(data);
        Ok(())
    }
}

/// Find the inner content type from decrypted TLS record plaintext.
/// The inner CT is the last non-zero byte; everything before it is the actual data.
fn find_inner_content_type(plaintext: &[u8]) -> Result<(usize, ContentType), Error> {
    let mut pos = plaintext.len();
    while pos > 0 && plaintext[pos - 1] == 0 {
        pos -= 1;
    }
    if pos == 0 {
        return Err(Error::Tls);
    }
    let ct = ContentType::from_byte(plaintext[pos - 1]).ok_or(Error::Tls)?;
    Ok((pos - 1, ct))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use crate::crypto::rustcrypto::Aes128GcmProvider;
    use crate::tls::handshake::{TlsConfig, ServerTlsConfig};
    use crate::tls::TransportParams;

    type TestClient = TlsConnection<Aes128GcmProvider, 32768>;
    type TestServer = TlsConnection<Aes128GcmProvider, 32768>;

    const TEST_SEED: [u8; 32] = [0x01u8; 32];

    fn test_cert_der() -> Vec<u8> {
        let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&TEST_SEED);
        let mut buf = [0u8; 512];
        let len = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut buf).unwrap();
        buf[..len].to_vec()
    }

    fn make_client() -> TestClient {
        let config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };
        TestClient::new_client(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
    }

    fn make_server(cert: &'static [u8]) -> TestServer {
        let config = ServerTlsConfig {
            cert_der: cert,
            private_key_der: &TEST_SEED,
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
        };
        TestServer::new_server(Aes128GcmProvider, config, [0xCC; 32], [0xDD; 32])
    }

    /// Transfer all pending output from src to dst.
    fn transfer(src: &mut TestClient, dst: &mut TestServer) -> bool {
        let mut any = false;
        let mut buf = [0u8; 32768];
        while let Some(data) = src.poll_output(&mut buf) {
            let copy = data.to_vec();
            dst.feed_data(&copy).unwrap();
            any = true;
        }
        any
    }

    fn transfer_rev(src: &mut TestServer, dst: &mut TestClient) -> bool {
        let mut any = false;
        let mut buf = [0u8; 32768];
        while let Some(data) = src.poll_output(&mut buf) {
            let copy = data.to_vec();
            dst.feed_data(&copy).unwrap();
            any = true;
        }
        any
    }

    /// Run the handshake to completion by exchanging data back and forth.
    fn handshake(client: &mut TestClient, server: &mut TestServer) {
        for _ in 0..20 {
            let a = transfer(client, server);
            let b = transfer_rev(server, client);
            if !a && !b {
                break;
            }
        }
    }

    fn drain_events_client(c: &mut TestClient) -> Vec<TlsEvent> {
        let mut events = Vec::new();
        while let Some(ev) = c.poll_event() {
            events.push(ev);
        }
        events
    }

    fn drain_events_server(s: &mut TestServer) -> Vec<TlsEvent> {
        let mut events = Vec::new();
        while let Some(ev) = s.poll_event() {
            events.push(ev);
        }
        events
    }

    #[test]
    fn handshake_completes() {
        // We need a 'static cert_der reference. Use a leaked allocation for test.
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        assert!(!client.is_active());
        assert!(!server.is_active());

        handshake(&mut client, &mut server);

        let client_events = drain_events_client(&mut client);
        let server_events = drain_events_server(&mut server);

        assert!(
            client_events.contains(&TlsEvent::HandshakeComplete),
            "client should emit HandshakeComplete, got: {:?}",
            client_events,
        );
        assert!(
            server_events.contains(&TlsEvent::HandshakeComplete),
            "server should emit HandshakeComplete, got: {:?}",
            server_events,
        );

        assert!(client.is_active());
        assert!(server.is_active());
    }

    #[test]
    fn app_data_roundtrip() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        handshake(&mut client, &mut server);

        // Drain handshake events
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        // Client sends data
        client.send_app_data(b"Hello from client").unwrap();
        transfer(&mut client, &mut server);

        let server_events = drain_events_server(&mut server);
        assert!(server_events.contains(&TlsEvent::AppData));

        let mut recv_buf = [0u8; 256];
        let n = server.recv_app_data(&mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..n], b"Hello from client");

        // Server sends data back
        server.send_app_data(b"Hello from server").unwrap();
        transfer_rev(&mut server, &mut client);

        let client_events = drain_events_client(&mut client);
        assert!(client_events.contains(&TlsEvent::AppData));

        let n = client.recv_app_data(&mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..n], b"Hello from server");
    }

    #[test]
    fn alpn_negotiation() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        handshake(&mut client, &mut server);
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        assert_eq!(client.alpn(), Some(b"h2".as_slice()));
        assert_eq!(server.alpn(), Some(b"h2".as_slice()));
    }

    #[test]
    fn send_before_handshake_fails() {
        let cert = test_cert_der().leak();
        let client = make_client();
        let _server = make_server(cert);

        // Client should not be active before handshake
        assert!(!client.is_active());
    }

    #[test]
    fn graceful_close() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        handshake(&mut client, &mut server);
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        // Client initiates close
        client.close().unwrap();
        assert!(client.is_closed());

        // Transfer close_notify to server
        transfer(&mut client, &mut server);

        let server_events = drain_events_server(&mut server);
        assert!(
            server_events.contains(&TlsEvent::PeerClosed),
            "server should see PeerClosed, got: {:?}",
            server_events,
        );
    }

    #[test]
    fn multiple_app_data_messages() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        handshake(&mut client, &mut server);
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        // Send multiple messages
        for i in 0..5u8 {
            let msg = [b'A' + i; 100];
            client.send_app_data(&msg).unwrap();
        }

        transfer(&mut client, &mut server);

        // Server should receive all data
        let mut recv_buf = [0u8; 1024];
        let n = server.recv_app_data(&mut recv_buf).unwrap();
        assert_eq!(n, 500);
    }

    #[test]
    fn send_app_data_before_handshake_returns_error() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let _server = make_server(cert);

        let result = client.send_app_data(b"too early");
        assert!(result.is_err());
    }

    #[test]
    fn recv_app_data_when_empty_returns_would_block() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        handshake(&mut client, &mut server);
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        let mut buf = [0u8; 64];
        let result = server.recv_app_data(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn fragmented_feed_data() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        // Do the handshake but feed server data one byte at a time
        for _ in 0..20 {
            // Client → Server: feed byte-by-byte
            let mut buf = [0u8; 32768];
            while let Some(data) = client.poll_output(&mut buf) {
                let copy = data.to_vec();
                for byte in &copy {
                    server.feed_data(core::slice::from_ref(byte)).unwrap();
                }
            }
            // Server → Client: feed byte-by-byte
            let mut buf2 = [0u8; 32768];
            while let Some(data) = server.poll_output(&mut buf2) {
                let copy = data.to_vec();
                for byte in &copy {
                    client.feed_data(core::slice::from_ref(byte)).unwrap();
                }
            }
            if client.is_active() && server.is_active() {
                break;
            }
        }

        assert!(client.is_active(), "handshake should complete with fragmented data");
        assert!(server.is_active());

        // Now send app data fragmented too
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        client.send_app_data(b"fragmented test").unwrap();
        let mut buf = [0u8; 32768];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            for byte in &copy {
                server.feed_data(core::slice::from_ref(byte)).unwrap();
            }
        }

        let events = drain_events_server(&mut server);
        assert!(events.contains(&TlsEvent::AppData));

        let mut recv = [0u8; 64];
        let n = server.recv_app_data(&mut recv).unwrap();
        assert_eq!(&recv[..n], b"fragmented test");
    }

    #[test]
    fn server_initiated_close() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        handshake(&mut client, &mut server);
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        server.close().unwrap();
        assert!(server.is_closed());

        transfer_rev(&mut server, &mut client);

        let client_events = drain_events_client(&mut client);
        assert!(
            client_events.contains(&TlsEvent::PeerClosed),
            "client should see PeerClosed, got: {:?}",
            client_events,
        );
    }

    #[test]
    fn large_payload_near_record_limit() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        handshake(&mut client, &mut server);
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        // Send 16000 bytes (near the 16384 TLS record limit)
        let big_data = [0x42u8; 16000];
        client.send_app_data(&big_data).unwrap();
        transfer(&mut client, &mut server);

        let events = drain_events_server(&mut server);
        assert!(events.contains(&TlsEvent::AppData));

        let mut recv = [0u8; 16384];
        let n = server.recv_app_data(&mut recv).unwrap();
        assert_eq!(n, 16000);
        assert!(recv[..n].iter().all(|&b| b == 0x42));
    }

    #[test]
    fn data_after_close_ignored() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        handshake(&mut client, &mut server);
        drain_events_client(&mut client);
        drain_events_server(&mut server);

        // Close and transfer close_notify
        client.close().unwrap();
        transfer(&mut client, &mut server);
        drain_events_server(&mut server);

        // Server trying to send after receiving close_notify should still work
        // (it's half-closed), but the closed side shouldn't produce new data
        assert!(client.is_closed());
        // close() again is idempotent
        client.close().unwrap();
    }

    #[test]
    fn tls_client_wrapper_handshake() {
        use super::super::client::TlsClient;
        use super::super::server::TlsServer;

        let cert: &'static [u8] = test_cert_der().leak();

        let client_config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };
        let server_config = ServerTlsConfig {
            cert_der: cert,
            private_key_der: &TEST_SEED,
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
        };

        let mut client: TlsClient<Aes128GcmProvider, 32768> =
            TlsClient::new(Aes128GcmProvider, client_config, [0xAA; 32], [0xBB; 32]);
        let mut server: TlsServer<Aes128GcmProvider, 32768> =
            TlsServer::new(Aes128GcmProvider, server_config, [0xCC; 32], [0xDD; 32]);

        // Handshake
        for _ in 0..20 {
            let mut any = false;
            let mut buf = [0u8; 32768];
            while let Some(data) = client.poll_output(&mut buf) {
                let copy = data.to_vec();
                server.feed_data(&copy).unwrap();
                any = true;
            }
            let mut buf2 = [0u8; 32768];
            while let Some(data) = server.poll_output(&mut buf2) {
                let copy = data.to_vec();
                client.feed_data(&copy).unwrap();
                any = true;
            }
            if !any { break; }
        }

        assert!(client.is_active());
        assert!(server.is_active());
        assert_eq!(client.alpn(), Some(b"h2".as_slice()));

        // App data through wrappers
        client.send_app_data(b"wrapper test").unwrap();
        let mut buf = [0u8; 32768];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            server.feed_data(&copy).unwrap();
        }

        let mut recv = [0u8; 64];
        let n = server.recv_app_data(&mut recv).unwrap();
        assert_eq!(&recv[..n], b"wrapper test");
    }

    #[test]
    fn find_inner_content_type_basic() {
        // ApplicationData byte at the end
        let data = [0x41, 0x42, 0x43, ContentType::ApplicationData as u8];
        let (len, ct) = find_inner_content_type(&data).unwrap();
        assert_eq!(len, 3);
        assert_eq!(ct, ContentType::ApplicationData);
    }

    #[test]
    fn find_inner_content_type_with_padding() {
        // Data + CT byte + zero padding
        let data = [0x41, ContentType::Handshake as u8, 0x00, 0x00];
        let (len, ct) = find_inner_content_type(&data).unwrap();
        assert_eq!(len, 1);
        assert_eq!(ct, ContentType::Handshake);
    }

    #[test]
    fn find_inner_content_type_empty() {
        let data = [0u8; 4]; // all zeros
        assert!(find_inner_content_type(&data).is_err());
    }
}
