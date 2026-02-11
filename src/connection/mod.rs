//! QUIC connection state machine.
//!
//! The `Connection` struct integrates all existing modules (crypto, TLS, packet,
//! frame, transport) into a working QUIC connection. It manages the handshake,
//! packet encryption/decryption, stream multiplexing, loss detection, congestion
//! control, and flow control.

pub mod keys;
pub mod recv;
pub mod transmit;

use crate::crypto::{CryptoProvider, Level};
use crate::error::Error;
use crate::tls::handshake::{Role, ServerTlsConfig, TlsConfig, TlsEngine};
use crate::tls::transport_params::TransportParams;

use crate::transport::congestion::CongestionController;
use crate::transport::flow_control::FlowController;
use crate::transport::loss::LossDetector;
use crate::transport::recovery::SentPacketTracker;
use crate::transport::stream::StreamMap;
use crate::transport::{Instant, Rng};

use self::keys::ConnectionKeys;
use self::recv::level_index;

// ---------------------------------------------------------------------------
// Configuration trait
// ---------------------------------------------------------------------------

/// Compile-time configuration for a QUIC connection.
pub trait ConnectionConfig {
    const MAX_STREAMS: usize;
    const SENT_PACKETS_PER_SPACE: usize;
    const MAX_CIDS: usize;
    const CRYPTO_BUF_SIZE: usize;
}

/// Default configuration suitable for most use cases.
pub struct DefaultConfig;

impl ConnectionConfig for DefaultConfig {
    const MAX_STREAMS: usize = 32;
    const SENT_PACKETS_PER_SPACE: usize = 64;
    const MAX_CIDS: usize = 4;
    const CRYPTO_BUF_SIZE: usize = 4096;
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// High-level state of the QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// TLS handshake in progress.
    Handshaking,
    /// Handshake complete, data can be exchanged.
    Active,
    /// We received a CONNECTION_CLOSE and are draining.
    Draining,
    /// We are sending CONNECTION_CLOSE.
    Closing,
    /// Connection fully closed.
    Closed,
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

/// Events produced by the connection for the application layer.
#[derive(Debug, Clone)]
pub enum Event {
    /// Handshake is complete; connection is now usable.
    Connected,
    /// A new stream was opened (by the peer).
    StreamOpened(u64),
    /// Stream has data available to read.
    StreamReadable(u64),
    /// Stream can accept more data.
    StreamWritable(u64),
    /// Peer reset the stream.
    StreamReset { stream_id: u64, error_code: u64 },
    /// Peer asked us to stop sending.
    StopSending { stream_id: u64, error_code: u64 },
    /// Stream send side finished (all data acked).
    StreamFinished(u64),
    /// Connection was closed.
    ConnectionClose {
        error_code: u64,
        reason: heapless::Vec<u8, 64>,
    },
}

// ---------------------------------------------------------------------------
// ConnectionId
// ---------------------------------------------------------------------------

/// A QUIC Connection ID (up to 20 bytes).
#[derive(Debug, Clone)]
pub struct ConnectionId {
    pub bytes: [u8; 20],
    pub len: u8,
}

impl ConnectionId {
    pub fn empty() -> Self {
        Self {
            bytes: [0u8; 20],
            len: 0,
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut cid = Self::empty();
        let copy_len = data.len().min(20);
        cid.bytes[..copy_len].copy_from_slice(&data[..copy_len]);
        cid.len = copy_len as u8;
        cid
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn generate(rng: &mut impl Rng, len: u8) -> Self {
        let mut cid = Self::empty();
        let actual_len = (len as usize).min(20);
        rng.fill(&mut cid.bytes[..actual_len]);
        cid.len = actual_len as u8;
        cid
    }
}

// ---------------------------------------------------------------------------
// Transmit
// ---------------------------------------------------------------------------

/// An outgoing datagram to send on the wire.
pub struct Transmit<'a> {
    pub data: &'a [u8],
}

// ---------------------------------------------------------------------------
// Stream send queue entry
// ---------------------------------------------------------------------------

/// A pending stream data send.
#[derive(Clone)]
pub struct StreamSendEntry {
    pub stream_id: u64,
    pub offset: u64,
    pub data: [u8; 1024],
    pub len: usize,
    pub fin: bool,
}

/// A simple received-data buffer for a single stream.
pub struct StreamRecvBuf {
    pub stream_id: u64,
    pub data: [u8; 1024],
    pub len: usize,
    pub read_offset: usize,
    pub fin_received: bool,
}

// ---------------------------------------------------------------------------
// Received PN tracker for ACK generation
// ---------------------------------------------------------------------------

/// Simple tracker of received packet numbers per space.
pub struct RecvPnTracker {
    /// Largest received PN.
    pub largest: Option<u64>,
    /// Count of packets received (for simple ACK generation).
    pub count: u64,
}

impl RecvPnTracker {
    pub fn new() -> Self {
        Self {
            largest: None,
            count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Connection struct
// ---------------------------------------------------------------------------

/// A QUIC connection.
pub struct Connection<C: CryptoProvider, Cfg: ConnectionConfig = DefaultConfig> {
    pub(crate) state: ConnectionState,
    pub(crate) role: Role,
    pub(crate) crypto: C,
    pub(crate) keys: ConnectionKeys<C>,
    pub(crate) tls: TlsEngine<C>,
    pub(crate) streams: StreamMap<32>,
    pub(crate) sent_tracker: SentPacketTracker<128>,
    pub(crate) loss_detector: LossDetector,
    pub(crate) congestion: CongestionController,
    pub(crate) flow_control: FlowController,

    // Crypto frame reassembly buffers (one per level: Initial, Handshake, Application)
    pub(crate) crypto_recv_buf: [heapless::Vec<u8, 4096>; 3],
    pub(crate) crypto_recv_offset: [u64; 3],

    // Crypto send offsets (tracks how many bytes we've sent per level)
    pub(crate) crypto_send_offset: [u64; 3],

    // Pending TLS crypto data that was retrieved but not yet sent
    pub(crate) pending_crypto: [heapless::Vec<u8, 2048>; 3],
    pub(crate) pending_crypto_level: [Level; 3],

    // Our connection IDs
    pub(crate) local_cids: heapless::Vec<ConnectionId, 4>,
    pub(crate) remote_cid: ConnectionId,

    // Packet numbers
    pub(crate) next_pn: [u64; 3],
    pub(crate) largest_recv_pn: [Option<u64>; 3],

    // Received PN tracking per space for ACK generation
    pub(crate) recv_pn_tracker: [RecvPnTracker; 3],

    // ACK state
    pub(crate) ack_eliciting_received: [bool; 3],

    // Transport parameters
    pub(crate) local_params: TransportParams,
    pub(crate) peer_params: Option<TransportParams>,

    // Events queue
    pub(crate) events: heapless::Deque<Event, 16>,

    // Pending close
    pub(crate) close_frame: Option<(u64, heapless::Vec<u8, 64>)>,

    // Idle timeout
    pub(crate) idle_timeout: Option<u64>,
    pub(crate) last_activity: Instant,

    // Server needs to send HANDSHAKE_DONE
    pub(crate) need_handshake_done: bool,

    // Stream send queue
    pub(crate) stream_send_queue: heapless::Vec<StreamSendEntry, 16>,

    // Stream receive buffers (simple, indexed by position)
    pub(crate) stream_recv_bufs: [Option<StreamRecvBuf>; 32],

    // Marker for config type
    _cfg: core::marker::PhantomData<Cfg>,
}

impl<C: CryptoProvider, Cfg: ConnectionConfig> Connection<C, Cfg>
where
    C::Hkdf: Default,
{
    /// Create a new client-side QUIC connection.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn client(
        crypto: C,
        server_name: &str,
        alpn: &'static [&'static [u8]],
        transport_params: TransportParams,
        rng: &mut impl Rng,
    ) -> Result<Self, Error> {
        // Generate X25519 secret and random bytes
        let mut secret_bytes = [0u8; 32];
        let mut random = [0u8; 32];
        rng.fill(&mut secret_bytes);
        rng.fill(&mut random);

        let tls_config = TlsConfig {
            server_name: heapless::String::try_from(server_name).map_err(|_| Error::Tls)?,
            alpn_protocols: alpn,
            transport_params: transport_params.clone(),
            pinned_certs: &[],
        };

        let tls = TlsEngine::<C>::new_client(tls_config, secret_bytes, random);

        // Generate a local connection ID
        let local_cid = ConnectionId::generate(rng, 8);

        // Generate a random destination CID for the server
        let initial_dcid = ConnectionId::generate(rng, 8);

        let mut keys = ConnectionKeys::new();
        // Derive initial keys from the destination CID
        keys.derive_initial(&crypto, initial_dcid.as_slice(), true)?;

        let mut local_cids = heapless::Vec::new();
        let _ = local_cids.push(local_cid);

        let fc = FlowController::new(
            transport_params.initial_max_data,
            transport_params.initial_max_streams_bidi,
            transport_params.initial_max_streams_uni,
        );

        Ok(Self {
            state: ConnectionState::Handshaking,
            role: Role::Client,
            crypto,
            keys,
            tls,
            streams: StreamMap::new(),
            sent_tracker: SentPacketTracker::new(),
            loss_detector: LossDetector::new(transport_params.max_ack_delay * 1000),
            congestion: CongestionController::new(1200),
            flow_control: fc,
            crypto_recv_buf: core::array::from_fn(|_| heapless::Vec::new()),
            crypto_recv_offset: [0; 3],
            crypto_send_offset: [0; 3],
            pending_crypto: core::array::from_fn(|_| heapless::Vec::new()),
            pending_crypto_level: [Level::Initial; 3],
            local_cids,
            remote_cid: initial_dcid,
            next_pn: [0; 3],
            largest_recv_pn: [None; 3],
            recv_pn_tracker: core::array::from_fn(|_| RecvPnTracker::new()),
            ack_eliciting_received: [false; 3],
            local_params: transport_params,
            peer_params: None,
            events: heapless::Deque::new(),
            close_frame: None,
            idle_timeout: None,
            last_activity: 0,
            need_handshake_done: false,
            stream_send_queue: heapless::Vec::new(),
            stream_recv_bufs: core::array::from_fn(|_| None),
            _cfg: core::marker::PhantomData,
        })
    }

    /// Create a new server-side QUIC connection.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn server(
        crypto: C,
        config: ServerTlsConfig,
        transport_params: TransportParams,
        rng: &mut impl Rng,
    ) -> Result<Self, Error> {
        let mut secret_bytes = [0u8; 32];
        let mut random = [0u8; 32];
        rng.fill(&mut secret_bytes);
        rng.fill(&mut random);

        let tls = TlsEngine::<C>::new_server(config, secret_bytes, random);

        let local_cid = ConnectionId::generate(rng, 8);
        let mut local_cids = heapless::Vec::new();
        let _ = local_cids.push(local_cid);

        let fc = FlowController::new(
            transport_params.initial_max_data,
            transport_params.initial_max_streams_bidi,
            transport_params.initial_max_streams_uni,
        );

        Ok(Self {
            state: ConnectionState::Handshaking,
            role: Role::Server,
            crypto,
            keys: ConnectionKeys::new(),
            tls,
            streams: StreamMap::new(),
            sent_tracker: SentPacketTracker::new(),
            loss_detector: LossDetector::new(transport_params.max_ack_delay * 1000),
            congestion: CongestionController::new(1200),
            flow_control: fc,
            crypto_recv_buf: core::array::from_fn(|_| heapless::Vec::new()),
            crypto_recv_offset: [0; 3],
            crypto_send_offset: [0; 3],
            pending_crypto: core::array::from_fn(|_| heapless::Vec::new()),
            pending_crypto_level: [Level::Initial; 3],
            local_cids,
            remote_cid: ConnectionId::empty(),
            next_pn: [0; 3],
            largest_recv_pn: [None; 3],
            recv_pn_tracker: core::array::from_fn(|_| RecvPnTracker::new()),
            ack_eliciting_received: [false; 3],
            local_params: transport_params,
            peer_params: None,
            events: heapless::Deque::new(),
            close_frame: None,
            idle_timeout: None,
            last_activity: 0,
            need_handshake_done: true,
            stream_send_queue: heapless::Vec::new(),
            stream_recv_bufs: core::array::from_fn(|_| None),
            _cfg: core::marker::PhantomData,
        })
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get the next event for the application.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Get the next timer deadline.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.loss_detector.next_timeout(&self.sent_tracker)
    }

    /// Handle a timer expiration.
    pub fn handle_timeout(&mut self, now: Instant) {
        // Check idle timeout
        if let Some(idle) = self.idle_timeout {
            if now.saturating_sub(self.last_activity) >= idle {
                self.state = ConnectionState::Closed;
                let _ = self.events.push_back(Event::ConnectionClose {
                    error_code: 0,
                    reason: heapless::Vec::new(),
                });
                return;
            }
        }

        // PTO expired
        self.loss_detector.on_pto();
    }

    /// Open a new bidirectional stream.
    pub fn open_stream(&mut self) -> Result<u64, Error> {
        if !matches!(self.state, ConnectionState::Active) {
            return Err(Error::InvalidState);
        }
        let is_client = self.role == Role::Client;
        self.streams.open_bidi(is_client)
    }

    /// Open a new unidirectional stream.
    pub fn open_uni_stream(&mut self) -> Result<u64, Error> {
        if !matches!(self.state, ConnectionState::Active) {
            return Err(Error::InvalidState);
        }
        let is_client = self.role == Role::Client;
        self.streams.open_uni(is_client)
    }

    /// Send data on a stream.
    pub fn stream_send(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        if matches!(self.state, ConnectionState::Closed | ConnectionState::Draining) {
            return Err(Error::Closed);
        }

        // Validate stream exists
        let stream = self.streams.get(stream_id).ok_or(Error::InvalidState)?;
        let send = stream.send.as_ref().ok_or(Error::InvalidState)?;
        let offset = send.offset;

        // Limit data to available capacity
        let max_send = (send.max_data - send.offset) as usize;
        let send_len = data.len().min(max_send).min(1024);

        if send_len == 0 && !fin {
            return Ok(0);
        }

        // Record in stream map
        self.streams.mark_send(stream_id, send_len as u64, fin)?;

        // Queue for transmission
        let mut entry = StreamSendEntry {
            stream_id,
            offset,
            data: [0u8; 1024],
            len: send_len,
            fin,
        };
        entry.data[..send_len].copy_from_slice(&data[..send_len]);
        let _ = self.stream_send_queue.push(entry);

        Ok(send_len)
    }

    /// Receive data from a stream.
    pub fn stream_recv(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        if matches!(self.state, ConnectionState::Closed) {
            return Err(Error::Closed);
        }

        // Look for data in our receive buffers
        for slot in self.stream_recv_bufs.iter_mut() {
            if let Some(recv) = slot {
                if recv.stream_id == stream_id {
                    let available = recv.len - recv.read_offset;
                    if available == 0 {
                        if recv.fin_received {
                            let fin = true;
                            *slot = None;
                            return Ok((0, fin));
                        }
                        return Err(Error::WouldBlock);
                    }
                    let copy_len = available.min(buf.len());
                    buf[..copy_len].copy_from_slice(
                        &recv.data[recv.read_offset..recv.read_offset + copy_len],
                    );
                    recv.read_offset += copy_len;
                    let fin = recv.fin_received && recv.read_offset >= recv.len;
                    if fin || recv.read_offset >= recv.len {
                        if fin {
                            *slot = None;
                        }
                    }
                    return Ok((copy_len, fin));
                }
            }
        }

        Err(Error::WouldBlock)
    }

    /// Reset a stream (send RESET_STREAM to peer).
    pub fn stream_reset(&mut self, stream_id: u64, _error_code: u64) -> Result<(), Error> {
        self.streams.mark_reset_sent(stream_id)
    }

    /// Tell peer to stop sending on a stream.
    pub fn stream_stop_sending(
        &mut self,
        stream_id: u64,
        _error_code: u64,
    ) -> Result<(), Error> {
        // Mark in stream map; the actual frame is sent in poll_transmit
        self.streams.handle_stop_sending(stream_id)
    }

    /// Initiate connection close.
    pub fn close(&mut self, error_code: u64, reason: &[u8]) {
        if matches!(
            self.state,
            ConnectionState::Closed | ConnectionState::Draining | ConnectionState::Closing
        ) {
            return;
        }
        let mut reason_vec = heapless::Vec::new();
        let copy_len = reason.len().min(64);
        let _ = reason_vec.extend_from_slice(&reason[..copy_len]);
        self.close_frame = Some((error_code, reason_vec));
        self.state = ConnectionState::Closing;
    }

    /// Is the connection fully closed?
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnectionState::Closed)
    }

    /// Is the handshake complete and the connection established?
    pub fn is_established(&self) -> bool {
        matches!(self.state, ConnectionState::Active)
    }

    /// Get the connection state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Store received stream data in a receive buffer.
    pub(crate) fn store_stream_data(
        &mut self,
        stream_id: u64,
        _offset: u64,
        data: &[u8],
        fin: bool,
    ) {
        // Find existing buffer or allocate new one
        let mut target_idx = None;
        for (i, slot) in self.stream_recv_bufs.iter().enumerate() {
            if let Some(buf) = slot {
                if buf.stream_id == stream_id {
                    target_idx = Some(i);
                    break;
                }
            }
        }

        if target_idx.is_none() {
            // Find empty slot
            for (i, slot) in self.stream_recv_bufs.iter().enumerate() {
                if slot.is_none() {
                    target_idx = Some(i);
                    break;
                }
            }
        }

        if let Some(idx) = target_idx {
            if self.stream_recv_bufs[idx].is_none() {
                self.stream_recv_bufs[idx] = Some(StreamRecvBuf {
                    stream_id,
                    data: [0u8; 1024],
                    len: 0,
                    read_offset: 0,
                    fin_received: false,
                });
            }
            if let Some(ref mut buf) = self.stream_recv_bufs[idx] {
                let copy_len = data.len().min(1024 - buf.len);
                buf.data[buf.len..buf.len + copy_len].copy_from_slice(&data[..copy_len]);
                buf.len += copy_len;
                if fin {
                    buf.fin_received = true;
                }
            }
        }
    }

    /// Track a received packet number for ACK generation.
    pub(crate) fn track_received_pn(&mut self, level: Level, pn: u64) {
        let idx = level_index(level);
        let tracker = &mut self.recv_pn_tracker[idx];
        match tracker.largest {
            None => tracker.largest = Some(pn),
            Some(prev) if pn > prev => tracker.largest = Some(pn),
            _ => {}
        }
        tracker.count += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::MIN_INITIAL_PACKET_SIZE;

    #[test]
    fn connection_id_from_slice() {
        let cid = ConnectionId::from_slice(&[1, 2, 3, 4]);
        assert_eq!(cid.len, 4);
        assert_eq!(cid.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn connection_id_empty() {
        let cid = ConnectionId::empty();
        assert_eq!(cid.len, 0);
        assert_eq!(cid.as_slice().len(), 0);
    }

    #[test]
    fn connection_id_max_len() {
        let data = [0xAA; 25]; // longer than 20
        let cid = ConnectionId::from_slice(&data);
        assert_eq!(cid.len, 20);
        assert_eq!(cid.as_slice().len(), 20);
    }

    #[test]
    fn connection_state_initial() {
        assert_eq!(ConnectionState::Handshaking, ConnectionState::Handshaking);
    }

    #[test]
    fn default_config_values() {
        assert_eq!(DefaultConfig::MAX_STREAMS, 32);
        assert_eq!(DefaultConfig::SENT_PACKETS_PER_SPACE, 64);
        assert_eq!(DefaultConfig::MAX_CIDS, 4);
        assert_eq!(DefaultConfig::CRYPTO_BUF_SIZE, 4096);
    }

    struct TestRng(u8);

    impl Rng for TestRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[test]
    fn connection_id_generate() {
        let mut rng = TestRng(0x42);
        let cid = ConnectionId::generate(&mut rng, 8);
        assert_eq!(cid.len, 8);
        assert_eq!(cid.as_slice()[0], 0x42);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_connection_creates() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut rng = TestRng(0x10);
        let tp = TransportParams::default_params();
        let conn = Connection::<Aes128GcmProvider>::client(
            Aes128GcmProvider,
            "example.com",
            &[b"h3"],
            tp,
            &mut rng,
        );
        assert!(conn.is_ok());
        let conn = conn.unwrap();
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert_eq!(conn.role, Role::Client);
        assert!(!conn.is_established());
        assert!(!conn.is_closed());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_connection_creates() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        use crate::tls::handshake::ServerTlsConfig;

        let mut rng = TestRng(0x20);
        let tp = TransportParams::default_params();
        let config = ServerTlsConfig {
            cert_der: &[0xDE, 0xAD],
            private_key_der: &[0x01, 0x02],
            alpn_protocols: &[b"h3"],
            transport_params: tp.clone(),
        };
        let conn =
            Connection::<Aes128GcmProvider>::server(Aes128GcmProvider, config, tp, &mut rng);
        assert!(conn.is_ok());
        let conn = conn.unwrap();
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert_eq!(conn.role, Role::Server);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_poll_transmit_produces_initial() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut rng = TestRng(0x10);
        let tp = TransportParams::default_params();
        let mut conn = Connection::<Aes128GcmProvider>::client(
            Aes128GcmProvider,
            "example.com",
            &[b"h3"],
            tp,
            &mut rng,
        )
        .unwrap();

        let mut buf = [0u8; 2048];
        let tx = conn.poll_transmit(&mut buf, 0);
        assert!(tx.is_some());
        let tx = tx.unwrap();

        // Should be at least MIN_INITIAL_PACKET_SIZE
        assert!(
            tx.data.len() >= MIN_INITIAL_PACKET_SIZE,
            "Initial packet should be padded to at least 1200 bytes, got {}",
            tx.data.len()
        );

        // First byte should be a long header (form bit set)
        assert!(tx.data[0] & 0x80 != 0, "should be long header");
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn close_transitions_state() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut rng = TestRng(0x10);
        let tp = TransportParams::default_params();
        let mut conn = Connection::<Aes128GcmProvider>::client(
            Aes128GcmProvider,
            "example.com",
            &[b"h3"],
            tp,
            &mut rng,
        )
        .unwrap();

        conn.close(0, b"goodbye");
        assert_eq!(conn.state, ConnectionState::Closing);

        // poll_transmit should send the close frame
        let mut buf = [0u8; 2048];
        let tx = conn.poll_transmit(&mut buf, 0);
        assert!(tx.is_some());
        assert_eq!(conn.state, ConnectionState::Closed);
        assert!(conn.is_closed());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn recv_pn_tracker() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut rng = TestRng(0x10);
        let tp = TransportParams::default_params();
        let mut conn = Connection::<Aes128GcmProvider>::client(
            Aes128GcmProvider,
            "example.com",
            &[b"h3"],
            tp,
            &mut rng,
        )
        .unwrap();

        conn.track_received_pn(Level::Initial, 0);
        conn.track_received_pn(Level::Initial, 1);
        conn.track_received_pn(Level::Initial, 5);

        assert_eq!(conn.recv_pn_tracker[0].largest, Some(5));
        assert_eq!(conn.recv_pn_tracker[0].count, 3);
    }

    // =========================================================================
    // Integration test: full client-server handshake over Connection API
    // =========================================================================

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    mod integration {
        use super::*;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        use crate::packet::MIN_INITIAL_PACKET_SIZE;
        use crate::tls::handshake::ServerTlsConfig;

        const FAKE_CERT: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        const FAKE_KEY: &[u8] = &[0x01, 0x02, 0x03, 0x04];

        struct TestRng(u8);
        impl Rng for TestRng {
            fn fill(&mut self, buf: &mut [u8]) {
                for b in buf.iter_mut() {
                    *b = self.0;
                    self.0 = self.0.wrapping_add(1);
                }
            }
        }

        fn make_client() -> Connection<Aes128GcmProvider> {
            let mut rng = TestRng(0x10);
            Connection::client(
                Aes128GcmProvider,
                "test.local",
                &[b"h3"],
                TransportParams::default_params(),
                &mut rng,
            )
            .unwrap()
        }

        fn make_server() -> Connection<Aes128GcmProvider> {
            let mut rng = TestRng(0x50);
            let config = ServerTlsConfig {
                cert_der: FAKE_CERT,
                private_key_der: FAKE_KEY,
                alpn_protocols: &[b"h3"],
                transport_params: TransportParams::default_params(),
            };
            Connection::server(Aes128GcmProvider, config, TransportParams::default_params(), &mut rng)
                .unwrap()
        }

        #[test]
        fn client_generates_padded_initial() {
            let mut client = make_client();
            let mut buf = [0u8; 2048];
            let tx = client.poll_transmit(&mut buf, 0).unwrap();
            assert!(tx.data.len() >= MIN_INITIAL_PACKET_SIZE);
        }

        #[test]
        fn full_handshake() {
            let mut client = make_client();
            let mut server = make_server();
            let now = 1_000_000u64;

            // Use the handshake helper with enough rounds
            run_handshake_to_completion(&mut client, &mut server, now);

            assert!(
                server.is_established(),
                "server should be active, state = {:?}",
                server.state()
            );
            assert!(
                client.is_established(),
                "client should be active, state = {:?}",
                client.state()
            );

            // Check that the client received a Connected event
            let mut found_connected = false;
            while let Some(ev) = client.poll_event() {
                if matches!(ev, Event::Connected) {
                    found_connected = true;
                }
            }
            assert!(found_connected, "client should have received Connected event");
        }

        #[test]
        fn stream_data_after_handshake() {
            let mut client = make_client();
            let mut server = make_server();
            let now = 1_000_000u64;

            // Run handshake to completion
            run_handshake_to_completion(&mut client, &mut server, now);

            assert!(client.is_established());
            assert!(server.is_established());

            // Client opens a stream and sends data
            let stream_id = client.open_stream().unwrap();
            let data = b"hello from client";
            let sent = client.stream_send(stream_id, data, false).unwrap();
            assert_eq!(sent, data.len());

            // Client generates a 1-RTT packet with STREAM frame
            let mut buf = [0u8; 2048];
            let tx = client.poll_transmit(&mut buf, now);
            assert!(tx.is_some(), "should have stream data to send");

            let tx = tx.unwrap();
            let pkt_data: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };

            // Server receives stream data
            server.recv(&pkt_data, now).unwrap();

            // Server should have a StreamReadable event
            let mut found_readable = false;
            while let Some(ev) = server.poll_event() {
                if matches!(ev, Event::StreamReadable(id) if id == stream_id) {
                    found_readable = true;
                }
            }
            assert!(found_readable, "server should see StreamReadable event");

            // Server reads the data
            let mut recv_buf = [0u8; 256];
            let (read_len, fin) = server.stream_recv(stream_id, &mut recv_buf).unwrap();
            assert_eq!(read_len, data.len());
            assert_eq!(&recv_buf[..read_len], data);
            assert!(!fin);
        }

        #[test]
        fn connection_close_after_handshake() {
            let mut client = make_client();
            let mut server = make_server();
            let now = 1_000_000u64;

            run_handshake_to_completion(&mut client, &mut server, now);

            // Client closes connection
            client.close(0, b"done");
            assert_eq!(client.state(), ConnectionState::Closing);

            let mut buf = [0u8; 2048];
            let tx = client.poll_transmit(&mut buf, now).unwrap();
            let close_pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };

            assert!(client.is_closed());

            // Server receives the close
            server.recv(&close_pkt, now).unwrap();
            assert_eq!(server.state(), ConnectionState::Draining);

            let mut found_close = false;
            while let Some(ev) = server.poll_event() {
                if matches!(ev, Event::ConnectionClose { error_code: 0, .. }) {
                    found_close = true;
                }
            }
            assert!(found_close, "server should see ConnectionClose event");
        }

        /// Helper: run the handshake to completion.
        /// Exchanges packets between client and server in a loop until both
        /// sides report is_established() or the maximum number of rounds is reached.
        fn run_handshake_to_completion(
            client: &mut Connection<Aes128GcmProvider>,
            server: &mut Connection<Aes128GcmProvider>,
            now: Instant,
        ) {
            for _round in 0..20 {
                // Client -> Server: keep draining transmits
                loop {
                    let mut buf = [0u8; 4096];
                    match client.poll_transmit(&mut buf, now) {
                        Some(tx) => {
                            let data: heapless::Vec<u8, 4096> = {
                                let mut v = heapless::Vec::new();
                                let _ = v.extend_from_slice(tx.data);
                                v
                            };
                            let _ = server.recv(&data, now);
                        }
                        None => break,
                    }
                }

                // Server -> Client: keep draining transmits
                loop {
                    let mut buf = [0u8; 4096];
                    match server.poll_transmit(&mut buf, now) {
                        Some(tx) => {
                            let data: heapless::Vec<u8, 4096> = {
                                let mut v = heapless::Vec::new();
                                let _ = v.extend_from_slice(tx.data);
                                v
                            };
                            let _ = client.recv(&data, now);
                        }
                        None => break,
                    }
                }

                if client.is_established() && server.is_established() {
                    return;
                }
            }

            // If we get here, handshake did not complete.
            // Provide diagnostic information for debugging.
            assert!(
                client.is_established() && server.is_established(),
                "handshake did not complete after 20 rounds: client={:?}, server={:?}",
                client.state(),
                server.state()
            );
        }

        #[test]
        fn open_stream_before_handshake_fails() {
            let mut client = make_client();
            assert_eq!(
                client.open_stream().unwrap_err(),
                Error::InvalidState
            );
        }

        #[test]
        fn poll_event_empty_initially() {
            let mut client = make_client();
            assert!(client.poll_event().is_none());
        }

        #[test]
        fn multiple_poll_transmit_drains() {
            let mut client = make_client();
            let mut buf = [0u8; 2048];

            // First call should produce Initial
            let tx1 = client.poll_transmit(&mut buf, 0);
            assert!(tx1.is_some());

            // Second call should produce nothing (no more data)
            let tx2 = client.poll_transmit(&mut buf, 0);
            assert!(tx2.is_none());
        }

        #[test]
        fn stream_send_with_fin() {
            let mut client = make_client();
            let mut server = make_server();
            let now = 1_000_000u64;

            run_handshake_to_completion(&mut client, &mut server, now);

            let stream_id = client.open_stream().unwrap();
            let sent = client.stream_send(stream_id, b"final", true).unwrap();
            assert_eq!(sent, 5);

            let mut buf = [0u8; 2048];
            let tx = client.poll_transmit(&mut buf, now);
            assert!(tx.is_some());

            let pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.unwrap().data);
                v
            };

            server.recv(&pkt, now).unwrap();

            let mut recv_buf = [0u8; 256];
            let (len, fin) = server.stream_recv(stream_id, &mut recv_buf).unwrap();
            assert_eq!(len, 5);
            assert_eq!(&recv_buf[..len], b"final");
            assert!(fin);
        }
    }
}
