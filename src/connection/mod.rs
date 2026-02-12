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
    /// The next expected stream offset (byte position in the stream).
    pub next_offset: u64,
}

// ---------------------------------------------------------------------------
// Received PN tracker for ACK generation
// ---------------------------------------------------------------------------

/// Tracker of received packet number ranges per space for correct ACK generation.
///
/// Stores up to 32 non-overlapping, non-adjacent `(start, end)` inclusive
/// ranges, sorted in ascending order. When a new PN is recorded the tracker
/// extends or merges existing ranges. If the vec is full the lowest (oldest)
/// range is dropped.
pub struct RecvPnTracker {
    /// Non-overlapping, non-adjacent, ascending-sorted inclusive ranges.
    pub ranges: heapless::Vec<(u64, u64), 32>,
}

impl RecvPnTracker {
    pub fn new() -> Self {
        Self {
            ranges: heapless::Vec::new(),
        }
    }

    /// The largest received PN, or `None` if nothing has been received.
    pub fn largest(&self) -> Option<u64> {
        self.ranges.last().map(|&(_, end)| end)
    }

    /// Record reception of packet number `pn`.
    pub fn record(&mut self, pn: u64) {
        // Find which range to extend / insert at.
        // Ranges are sorted ascending by start.

        // Check if pn is already contained in an existing range.
        // Also find potential ranges to extend.
        let mut merge_left: Option<usize> = None;
        let mut merge_right: Option<usize> = None;

        for (i, &(start, end)) in self.ranges.iter().enumerate() {
            if pn >= start && pn <= end {
                // Already tracked.
                return;
            }
            // Can extend this range's upper end by 1?
            if pn == end + 1 {
                merge_left = Some(i);
            }
            // Can extend this range's lower end by 1?
            if pn + 1 == start {
                merge_right = Some(i);
            }
        }

        match (merge_left, merge_right) {
            (Some(li), Some(ri)) => {
                // pn bridges two adjacent ranges -- merge them.
                let new_start = self.ranges[li].0;
                let new_end = self.ranges[ri].1;
                // Remove the higher-index first to keep the lower index valid.
                let (first_rm, second_rm) = if li < ri { (ri, li) } else { (li, ri) };
                self.ranges.remove(first_rm);
                self.ranges.remove(second_rm);
                // Insert merged range at the correct position.
                self.insert_range(new_start, new_end);
            }
            (Some(li), None) => {
                // Extend upper bound of range at li.
                self.ranges[li].1 = pn;
            }
            (None, Some(ri)) => {
                // Extend lower bound of range at ri.
                self.ranges[ri].0 = pn;
            }
            (None, None) => {
                // New standalone range.
                if self.ranges.is_full() {
                    // Drop the lowest (oldest) range.
                    self.ranges.remove(0);
                }
                self.insert_range(pn, pn);
            }
        }
    }

    /// Insert a `(start, end)` range maintaining ascending order by `start`.
    fn insert_range(&mut self, start: u64, end: u64) {
        let pos = self
            .ranges
            .iter()
            .position(|&(s, _)| s > start)
            .unwrap_or(self.ranges.len());
        // heapless::Vec doesn't have `insert`, so we push and rotate.
        let _ = self.ranges.push((start, end));
        // Shift elements right from pos to len-2 to make room.
        let len = self.ranges.len();
        if pos < len - 1 {
            // Rotate the tail so the newly pushed element ends up at `pos`.
            self.ranges[pos..].rotate_right(1);
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
    pub(crate) crypto_reasm: [recv::CryptoReassemblyBuf; 3],

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

    // Anti-amplification: total bytes received before address validation
    pub(crate) anti_amplification_bytes_received: usize,
    // Anti-amplification: total bytes sent before address validation
    pub(crate) anti_amplification_bytes_sent: usize,
    // Whether address has been validated (handshake complete or Retry)
    pub(crate) address_validated: bool,

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

        // Generate a local connection ID
        let local_cid = ConnectionId::generate(rng, 8);

        // Set the client's initial_source_connection_id in transport params
        // (RFC 9000 §18.2 — both endpoints MUST include this).
        let mut tp = transport_params.clone();
        let scid_slice = local_cid.as_slice();
        let scid_len = scid_slice.len().min(20);
        tp.initial_scid[..scid_len].copy_from_slice(&scid_slice[..scid_len]);
        tp.initial_scid_len = scid_len as u8;

        let tls_config = TlsConfig {
            server_name: heapless::String::try_from(server_name).map_err(|_| Error::Tls)?,
            alpn_protocols: alpn,
            transport_params: tp,
            pinned_certs: &[],
        };

        let tls = TlsEngine::<C>::new_client(tls_config, secret_bytes, random);

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
            crypto_reasm: core::array::from_fn(|_| recv::CryptoReassemblyBuf::new()),
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
            anti_amplification_bytes_received: 0,
            anti_amplification_bytes_sent: 0,
            address_validated: true, // Client doesn't need amplification protection
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
            crypto_reasm: core::array::from_fn(|_| recv::CryptoReassemblyBuf::new()),
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
            anti_amplification_bytes_received: 0,
            anti_amplification_bytes_sent: 0,
            address_validated: false, // Server must validate address before sending freely
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

    /// Store received stream data in a receive buffer, respecting the offset.
    ///
    /// - If `offset` equals the expected next offset, data is appended.
    /// - If `offset` is less than expected (duplicate/overlap), already-received
    ///   bytes are skipped and only the new tail (if any) is appended.
    /// - If `offset` is greater than expected (gap), the frame is dropped
    ///   because we do not buffer out-of-order data; QUIC will retransmit.
    pub(crate) fn store_stream_data(
        &mut self,
        stream_id: u64,
        offset: u64,
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
                    next_offset: 0,
                });
            }
            if let Some(ref mut buf) = self.stream_recv_bufs[idx] {
                let frame_end = offset + data.len() as u64;

                if offset > buf.next_offset {
                    // Gap: we cannot place this data yet. Drop the frame;
                    // QUIC will retransmit the missing data first.
                    // Still record FIN if the frame carried it (edge case:
                    // FIN on an empty retransmit at the expected offset later).
                    return;
                }

                // offset <= buf.next_offset: possibly overlapping.
                if frame_end <= buf.next_offset {
                    // Entirely duplicate data we already have. Nothing to copy.
                    // But if FIN was set, record it.
                    if fin {
                        buf.fin_received = true;
                    }
                    return;
                }

                // We need to skip the bytes we already have.
                let skip = (buf.next_offset - offset) as usize;
                let new_data = &data[skip..];
                let copy_len = new_data.len().min(1024 - buf.len);
                buf.data[buf.len..buf.len + copy_len].copy_from_slice(&new_data[..copy_len]);
                buf.len += copy_len;
                buf.next_offset += copy_len as u64;
                if fin {
                    buf.fin_received = true;
                }
            }
        }
    }

    /// Check whether the anti-amplification limit allows sending `bytes` more bytes.
    /// Returns `true` if sending is allowed, `false` if it would exceed the 3x limit.
    pub(crate) fn amplification_allows(&self, bytes: usize) -> bool {
        if self.address_validated {
            return true;
        }
        self.anti_amplification_bytes_sent + bytes
            <= 3 * self.anti_amplification_bytes_received
    }

    /// Track a received packet number for ACK generation.
    pub(crate) fn track_received_pn(&mut self, level: Level, pn: u64) {
        let idx = level_index(level);
        self.recv_pn_tracker[idx].record(pn);
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

        assert_eq!(conn.recv_pn_tracker[0].largest(), Some(5));
        // Should have two ranges: [0,1] and [5,5]
        assert_eq!(conn.recv_pn_tracker[0].ranges.len(), 2);
        assert_eq!(conn.recv_pn_tracker[0].ranges[0], (0, 1));
        assert_eq!(conn.recv_pn_tracker[0].ranges[1], (5, 5));
    }

    // =========================================================================
    // Integration test: full client-server handshake over Connection API
    // =========================================================================

    // -----------------------------------------------------------------------
    // Phase 13: Anti-amplification tests
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    mod amplification_tests {
        use super::*;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        use crate::tls::handshake::ServerTlsConfig;

        const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

        fn get_test_ed25519_cert_der() -> &'static [u8] {
            use std::sync::LazyLock;
            static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
                let s: [u8; 32] = [0x01u8; 32];
                let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&s);
                let mut b = [0u8; 512];
                let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
                b[..n].to_vec()
            });
            &V
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
        fn client_address_always_validated() {
            let mut rng = TestRng(0x10);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let conn = Connection::<Aes128GcmProvider>::client(
                Aes128GcmProvider,
                "example.com",
                &[b"h3"],
                tp,
                &mut rng,
            )
            .unwrap();
            assert!(conn.address_validated);
        }

        #[test]
        fn server_address_not_validated_initially() {
            let mut rng = TestRng(0x20);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let conn = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
            )
            .unwrap();
            assert!(!conn.address_validated);
        }

        #[test]
        fn amplification_allows_within_3x() {
            let mut rng = TestRng(0x20);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let mut conn = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
            )
            .unwrap();

            // Simulate receiving 1200 bytes
            conn.anti_amplification_bytes_received = 1200;

            // Can send up to 3600 bytes
            assert!(conn.amplification_allows(3600));
            assert!(!conn.amplification_allows(3601));

            // After sending some, check remaining
            conn.anti_amplification_bytes_sent = 3000;
            assert!(conn.amplification_allows(600));
            assert!(!conn.amplification_allows(601));
        }

        #[test]
        fn amplification_allows_after_validation() {
            let mut rng = TestRng(0x20);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let mut conn = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
            )
            .unwrap();

            // Before validation, 0 received means 0 can be sent
            assert!(!conn.amplification_allows(1));

            // After validation, anything can be sent
            conn.address_validated = true;
            assert!(conn.amplification_allows(1_000_000));
        }

        #[test]
        fn amplification_zero_received_blocks_all() {
            let mut rng = TestRng(0x20);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let conn = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
            )
            .unwrap();

            // No bytes received, no bytes can be sent
            assert!(!conn.amplification_allows(1));
            // But 0 bytes is OK
            assert!(conn.amplification_allows(0));
        }

        #[test]
        fn server_validated_after_handshake() {
            // Full handshake should set address_validated = true on the server
            let mut rng_c = TestRng(0x10);
            let mut rng_s = TestRng(0x50);
            let tp = crate::tls::transport_params::TransportParams::default_params();

            let mut client = Connection::<Aes128GcmProvider>::client(
                Aes128GcmProvider,
                "test.local",
                &[b"h3"],
                tp.clone(),
                &mut rng_c,
            )
            .unwrap();

            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let mut server = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng_s,
            )
            .unwrap();

            assert!(!server.address_validated);

            // Run handshake
            let now = 1_000_000u64;
            for _round in 0..20 {
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
                    break;
                }
            }

            assert!(server.is_established());
            assert!(server.address_validated, "server should be address-validated after handshake");
        }
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    mod integration {
        use super::*;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        use crate::packet::MIN_INITIAL_PACKET_SIZE;
        use crate::tls::handshake::ServerTlsConfig;

        const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

        fn get_test_ed25519_cert_der() -> &'static [u8] {
            use std::sync::LazyLock;
            static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
                let s: [u8; 32] = [0x01u8; 32];
                let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&s);
                let mut b = [0u8; 512];
                let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
                b[..n].to_vec()
            });
            &V
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
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
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

    // =========================================================================
    // M9 — RecvPnTracker range-based ACK generation tests
    // =========================================================================

    mod recv_pn_tracker_tests {
        use super::*;

        #[test]
        fn single_pn_produces_single_range() {
            let mut t = RecvPnTracker::new();
            t.record(5);
            assert_eq!(t.ranges.as_slice(), &[(5, 5)]);
            assert_eq!(t.largest(), Some(5));
        }

        #[test]
        fn contiguous_pns_merge_into_one_range() {
            let mut t = RecvPnTracker::new();
            t.record(0);
            t.record(1);
            t.record(2);
            t.record(3);
            assert_eq!(t.ranges.as_slice(), &[(0, 3)]);
        }

        #[test]
        fn non_contiguous_pns_produce_multiple_ranges() {
            let mut t = RecvPnTracker::new();
            // Receive 0, 1, 5, 6, 10
            t.record(0);
            t.record(1);
            t.record(5);
            t.record(6);
            t.record(10);
            assert_eq!(t.ranges.as_slice(), &[(0, 1), (5, 6), (10, 10)]);
        }

        #[test]
        fn filling_gap_merges_ranges() {
            let mut t = RecvPnTracker::new();
            t.record(0);
            t.record(2);
            assert_eq!(t.ranges.as_slice(), &[(0, 0), (2, 2)]);
            // Now fill the gap
            t.record(1);
            assert_eq!(t.ranges.as_slice(), &[(0, 2)]);
        }

        #[test]
        fn out_of_order_pns_correctly_tracked() {
            let mut t = RecvPnTracker::new();
            t.record(5);
            t.record(3);
            t.record(1);
            t.record(4);
            t.record(2);
            // Should all merge into one range
            assert_eq!(t.ranges.as_slice(), &[(1, 5)]);
        }

        #[test]
        fn duplicate_pn_is_idempotent() {
            let mut t = RecvPnTracker::new();
            t.record(3);
            t.record(3);
            t.record(3);
            assert_eq!(t.ranges.as_slice(), &[(3, 3)]);
        }

        #[test]
        fn full_tracker_drops_lowest_range() {
            let mut t = RecvPnTracker::new();
            // Fill all 32 slots with non-contiguous ranges: 0, 100, 200, ...
            for i in 0..32 {
                t.record(i * 100);
            }
            assert_eq!(t.ranges.len(), 32);
            assert_eq!(t.ranges[0], (0, 0));

            // Adding one more should drop the lowest (0, 0)
            t.record(5000);
            assert_eq!(t.ranges.len(), 32);
            assert_eq!(t.ranges[0], (100, 100));
            assert_eq!(t.ranges[31], (5000, 5000));
        }

        #[test]
        fn largest_returns_none_when_empty() {
            let t = RecvPnTracker::new();
            assert_eq!(t.largest(), None);
        }

        #[test]
        fn extend_lower_bound() {
            let mut t = RecvPnTracker::new();
            t.record(5);
            t.record(4);
            assert_eq!(t.ranges.as_slice(), &[(4, 5)]);
        }
    }

    // =========================================================================
    // M4 — Stream data offset handling tests
    // =========================================================================

    mod stream_offset_tests {
        use super::*;

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        fn make_test_client() -> Connection<crate::crypto::rustcrypto::Aes128GcmProvider> {
            use crate::crypto::rustcrypto::Aes128GcmProvider;

            struct TestRng(u8);
            impl Rng for TestRng {
                fn fill(&mut self, buf: &mut [u8]) {
                    for b in buf.iter_mut() {
                        *b = self.0;
                        self.0 = self.0.wrapping_add(1);
                    }
                }
            }

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

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn in_order_data_appended() {
            let mut conn = make_test_client();
            let sid = 4u64; // arbitrary stream id
            conn.store_stream_data(sid, 0, b"hello", false);
            let buf = conn.stream_recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"hello");
            assert_eq!(buf.next_offset, 5);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn gap_drops_frame() {
            let mut conn = make_test_client();
            let sid = 4u64;
            // First send offset 0 with 5 bytes
            conn.store_stream_data(sid, 0, b"hello", false);
            // Then send offset 10 (gap) -- should be dropped
            conn.store_stream_data(sid, 10, b"world", false);
            let buf = conn.stream_recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"hello");
            assert_eq!(buf.next_offset, 5);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn duplicate_data_skipped() {
            let mut conn = make_test_client();
            let sid = 4u64;
            conn.store_stream_data(sid, 0, b"hello", false);
            // Retransmit same data
            conn.store_stream_data(sid, 0, b"hello", false);
            let buf = conn.stream_recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            // Should not double-append
            assert_eq!(&buf.data[..buf.len], b"hello");
            assert_eq!(buf.next_offset, 5);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn partial_overlap_appends_new_tail() {
            let mut conn = make_test_client();
            let sid = 4u64;
            conn.store_stream_data(sid, 0, b"hel", false);
            assert_eq!(conn.stream_recv_bufs.iter().find_map(|s| s.as_ref()).unwrap().next_offset, 3);
            // Overlap: offset 1 with "ello" -- first 2 bytes overlap, last 2 are new
            conn.store_stream_data(sid, 1, b"ello", false);
            let buf = conn.stream_recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"hello");
            assert_eq!(buf.next_offset, 5);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn sequential_in_order_frames() {
            let mut conn = make_test_client();
            let sid = 4u64;
            conn.store_stream_data(sid, 0, b"hel", false);
            conn.store_stream_data(sid, 3, b"lo ", false);
            conn.store_stream_data(sid, 6, b"world", true);
            let buf = conn.stream_recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"hello world");
            assert_eq!(buf.next_offset, 11);
            assert!(buf.fin_received);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn fin_on_duplicate_is_recorded() {
            let mut conn = make_test_client();
            let sid = 4u64;
            conn.store_stream_data(sid, 0, b"done", false);
            // Retransmit with FIN
            conn.store_stream_data(sid, 0, b"done", true);
            let buf = conn.stream_recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"done");
            assert!(buf.fin_received);
        }
    }

    /// Test that processes a real curl --http3 Initial packet.
    #[cfg(feature = "rustcrypto-chacha")]
    mod curl_interop {
        use super::*;
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        /// Hex-encoded Initial packet captured from `curl --http3`.
        const CURL_INITIAL_HEX: &str = "ca00000001145853147be8dc7ffd04d27473064d582c2c9f8d471486e5be8c8451a8acebec17f0649776ebdd90221c008000047c69639d2b78e5215ce9d38a549bb4e688821d3188bc79338e5e0431d6551a14ea5b36462fb746f1a17913ae38d0ae789132b5b31d5c8ed9c418ba0ac877f4a68fa436f7477f5ee9f5bd90d4137dafdfec0b04ffcaef83f5e0184b9742faac00fe7246d94117a9d11ab92944b1cc9e8dbb799545ae87db196f9e5f7f0ab0779685b369ae3bb9c281ac872de74c1bdba52d7c0b61b52b1c56e5a42ef9c01751348961ecb3bb4b8b052b1ef0919fe4fb66beafc588e0761ad77b6b8f036e0baa8e7f8dbe369dd82bf79fc40664a4f5b9679c8c435fc6eac36f10cfb00f864a8fed955eda0bffd0f822ff30202f8e4d73511560078339b3961a90bfbb93bab6d0c832bc1912adc6dbc2cab5adb9acf3764bcff373394c1b08e29ebeecffecf1e3de0d205e07676198c11a9a803cf03c9b706885cbb89e43aa1eb8779eeb3ea94ff590ae853b6bc394f0091c93b2e5da54bb674c55d820bdc57bef9b401022198a573b74ce7430dfaf84efe24de129a93f2b05d902234490b4398a6e7a13f766c131d3dae63a71c434de7ba68002162bea6c0105d378cca320817f6192ae6701fc040c06f52dac2cf8fe00813810202478c2b81a98778d9a264c33a57ddae92e0d4375aa5fd19825582e5f5293a6a4a9c1ad24e6c4476b77c3c5228637708c0ec6b3469e3874a3509df2d36806caf72f1a60fcbfe2fcb0c0dcba4b54f80838dfc10f610e5377d95041ac78a03e9f2c74acc27bbc61b4e6c911f0c591a1da67ccb3ce982603238b34a0ccb486f79226f0046289e6317edc55569d41a01ad04ee4d359acb8fa494cc3229251d56eab7da70e46c543c4afd49a7f5efb8f12b890f982a4002c1513cb0c87e25f9b59035b4f9987b96feb1b5c6e86c1314d3064f418bfd6d1a3a7242e761a50ebc6c4e190919fa4a0a2a9406b741b53534a1baebe185ef8698998ff47cf0a9165b8b7cd5e4966c8e6a5faaa4a8309f973f5ae0ff7d96c6eadf12a89124b6f1297c90363727aa64c8d1be9ff4fdb886dbe8add8ccd7410d705617c4830ab90949544b1e47544d25c25e7f3d8e36054e95205ecb68464e0561cc5e8f0f458a4c82c3fdb1fdb2c1e7bd9b2da14807b4d3eda466f4fc57554fac825803557c28d4537175c672bd1496c361c211613838b465b4dcec2a5d64d31760c713f55b480205f228c0a9999c94684e88f2b645d5961818afb145ac12511896784bdf7688d7f4381cbc98a2584b05c31a81071e96d67ace70663601d2e88963590c82dd37983df27688618a584a54f2c33e6d9013ea434577a813d9e9d433a2c59ed070c7db47d286fd2b687428c0a22b9933149ca9988682803dc554cb0603edb5f62b0f16217abca14be43b1ba03931158b40695f3e3ec03b51ebd1dbd30e36daa3f527955f25e3524db0480c65d4c2c8d4b87c5d58c0a2bf5e6bcbc5354b97b9dc50f22b3c961c2ded546556beb3dbd6d48e3c69b182abd6034df6a806d7e235ea8f9bd7c648197d5e56c65591d26da0e0e62e3e536570eefd1dd66a5b9e376d116dfad88d7bb337a856a5a95b98b2840b58d83c769d2d8b01dc12b09a0f8db6c667c2fe4752ebd21cdc4c97349de0fcf805db46253b4503f18";

        const TEST_SEED: [u8; 32] = [0x42u8; 32];

        fn get_test_cert_der() -> &'static [u8] {
            use std::sync::LazyLock;
            static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
                let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&TEST_SEED);
                let mut b = [0u8; 512];
                let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
                b[..n].to_vec()
            });
            &V
        }

        fn hex_to_bytes(hex: &str) -> std::vec::Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        }

        #[test]
        fn server_processes_curl_initial_packet() {
            let data = hex_to_bytes(CURL_INITIAL_HEX);
            assert_eq!(data.len(), 1200);

            let tp = TransportParams::default_params();
            let config = crate::tls::handshake::ServerTlsConfig {
                cert_der: get_test_cert_der(),
                private_key_der: &TEST_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };

            struct TestRng(u8);
            impl Rng for TestRng {
                fn fill(&mut self, buf: &mut [u8]) {
                    for b in buf.iter_mut() {
                        *b = self.0;
                        self.0 = self.0.wrapping_add(1);
                    }
                }
            }
            let mut rng = TestRng(0x10);
            let mut server =
                Connection::<Aes128GcmProvider>::server(Aes128GcmProvider, config, tp, &mut rng)
                    .expect("create server");

            // Process the curl Initial packet
            let now = 1_000_000u64;
            let result = server.recv(&data, now);
            std::eprintln!("recv result: {:?}", result);
            assert!(result.is_ok(), "recv should succeed: {:?}", result);

            // Check that the server:
            // 1. Derived initial keys (from DCID)
            assert!(
                server.keys.has_recv_keys(Level::Initial),
                "should have initial recv keys"
            );

            // 2. Marked the packet as ack-eliciting
            assert!(
                server.ack_eliciting_received[0],
                "Initial packet should be ack-eliciting"
            );

            // 3. Tracked PN 0 in the recv_pn_tracker
            assert!(
                !server.recv_pn_tracker[0].ranges.is_empty(),
                "should have tracked PN 0"
            );

            // 4. Buffered CRYPTO data in the reassembly buffer
            // The ClientHello is 1499 bytes but only ~1077 fit in this datagram.
            let reasm = &server.crypto_reasm[0];
            let avail = reasm.contiguous_len();
            std::eprintln!(
                "CRYPTO reassembly: {} contiguous bytes, delivered={}",
                avail, reasm.delivered
            );
            assert!(avail > 0, "should have some contiguous CRYPTO data");
            assert!(
                avail < 1499,
                "shouldn't have the full ClientHello yet (only one datagram)"
            );

            // 5. poll_transmit should produce an ACK (even though TLS hasn't
            //    processed the ClientHello yet).
            let mut tx_buf = [0u8; 2048];
            let tx = server.poll_transmit(&mut tx_buf, now);
            std::eprintln!("poll_transmit: {:?}", tx.as_ref().map(|t| t.data.len()));
            assert!(
                tx.is_some(),
                "server should send an ACK for the client's Initial"
            );
        }
    }
}
