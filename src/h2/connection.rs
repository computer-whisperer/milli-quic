//! HTTP/2 connection state machine (RFC 9113).
//!
//! Pure codec following the milli-http pattern:
//! `feed_data()` → `poll_output()` → `poll_event()`

use crate::error::Error;
use crate::hpack::codec::{HpackDecoder, HpackEncoder};
use super::frame::{self, *};
use super::stream::{H2Stream, H2StreamState};
use super::flow_control::{FlowController, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_CONNECTION_WINDOW_SIZE};

/// HTTP/2 connection preface (RFC 9113 §3.4).
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Events produced by the HTTP/2 connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2Event {
    /// Connection settings exchanged, ready for requests.
    Connected,
    /// Headers received on a stream.
    Headers(u64),
    /// Body data available on a stream.
    Data(u64),
    /// Stream reset by peer.
    StreamReset(u64, u32),
    /// Peer sent GOAWAY.
    GoAway(u64, u32),
    /// Stream finished (END_STREAM received).
    Finished(u64),
    /// A timeout fired (idle or header timeout).
    Timeout,
}

/// Connection role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// HTTP/2 connection settings.
#[derive(Debug, Clone)]
pub struct H2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl Default for H2Settings {
    fn default() -> Self {
        Self {
            header_table_size: 0, // We don't use dynamic table
            enable_push: false,
            max_concurrent_streams: 128,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE as u32,
            max_frame_size: 16384,
            max_header_list_size: 8192,
        }
    }
}

impl H2Settings {
    /// Encode settings as SETTINGS frame payload (6 bytes per param).
    pub fn encode_params(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut off = 0;
        off += frame::encode_setting(SETTINGS_HEADER_TABLE_SIZE, self.header_table_size, &mut buf[off..])?;
        if !self.enable_push {
            off += frame::encode_setting(SETTINGS_ENABLE_PUSH, 0, &mut buf[off..])?;
        }
        off += frame::encode_setting(SETTINGS_MAX_CONCURRENT_STREAMS, self.max_concurrent_streams, &mut buf[off..])?;
        off += frame::encode_setting(SETTINGS_INITIAL_WINDOW_SIZE, self.initial_window_size, &mut buf[off..])?;
        off += frame::encode_setting(SETTINGS_MAX_FRAME_SIZE, self.max_frame_size, &mut buf[off..])?;
        off += frame::encode_setting(SETTINGS_MAX_HEADER_LIST_SIZE, self.max_header_list_size, &mut buf[off..])?;
        Ok(off)
    }

    /// Apply a settings parameter with RFC 9113 §6.5.2 validation.
    pub fn apply(&mut self, id: u16, value: u32) -> Result<(), Error> {
        match id {
            SETTINGS_HEADER_TABLE_SIZE => self.header_table_size = value,
            SETTINGS_ENABLE_PUSH => {
                if value > 1 {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                self.enable_push = value != 0;
            }
            SETTINGS_MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = value,
            SETTINGS_INITIAL_WINDOW_SIZE => {
                if value > 0x7fff_ffff {
                    return Err(Error::Http2(crate::error::H2Error::FlowControlError));
                }
                self.initial_window_size = value;
            }
            SETTINGS_MAX_FRAME_SIZE => {
                if !(16384..=16_777_215).contains(&value) {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                self.max_frame_size = value;
            }
            SETTINGS_MAX_HEADER_LIST_SIZE => self.max_header_list_size = value,
            _ => {} // Unknown settings are ignored (RFC 9113 §6.5.2)
        }
        Ok(())
    }
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum H2ConnState {
    /// Waiting for connection preface (client: send preface, server: expect preface).
    WaitingPreface,
    /// Waiting for initial SETTINGS from peer.
    WaitingSettings,
    /// Connection is active.
    Active,
    /// GOAWAY sent or received.
    Closing,
    /// Connection closed.
    Closed,
}

/// HTTP/2 connection state machine.
///
/// Generic parameters:
/// - `MAX_STREAMS`: maximum number of concurrent streams tracked
/// - `BUF`: size of internal send/recv buffers
/// - `HDRBUF`: per-stream header buffer size
/// - `DATABUF`: per-stream data buffer size
pub struct H2Connection<
    const MAX_STREAMS: usize = 8,
    const BUF: usize = 16384,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    role: Role,
    state: H2ConnState,
    local_settings: H2Settings,
    peer_settings: H2Settings,
    streams: heapless::Vec<H2Stream<HDRBUF, DATABUF>, MAX_STREAMS>,
    encoder: HpackEncoder,
    decoder: HpackDecoder,
    // I/O accumulation
    recv_buf: heapless::Vec<u8, BUF>,
    send_buf: heapless::Vec<u8, BUF>,
    send_offset: usize,
    // Flow control
    conn_send_fc: FlowController,
    conn_recv_fc: FlowController,
    // Event queue
    events: heapless::Deque<H2Event, 32>,
    // Connection state
    next_stream_id: u64,
    last_peer_stream_id: u64,
    /// Stream expecting CONTINUATION frames (RFC 9113 §4.3).
    continuation_stream_id: Option<u64>,
    settings_sent: bool,
    settings_ack_received: bool,
    peer_settings_received: bool,
    preface_sent: bool,
    preface_validated: bool,
    preface_bytes_seen: usize,
    goaway_sent: bool,
    // Timeout support
    timeout_config: crate::http::TimeoutConfig,
    last_activity: u64,
    connection_start: u64,
    headers_phase_complete: bool,
}

impl<const MAX_STREAMS: usize, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    H2Connection<MAX_STREAMS, BUF, HDRBUF, DATABUF>
{
    /// Create a new client-side connection.
    pub fn new_client() -> Self {
        Self::new(Role::Client)
    }

    /// Create a new server-side connection.
    pub fn new_server() -> Self {
        Self::new(Role::Server)
    }

    fn new(role: Role) -> Self {
        let next_stream_id = match role {
            Role::Client => 1,
            Role::Server => 2,
        };
        Self {
            role,
            state: H2ConnState::WaitingPreface,
            local_settings: H2Settings::default(),
            peer_settings: H2Settings::default(),
            streams: heapless::Vec::new(),
            encoder: HpackEncoder::new(),
            decoder: HpackDecoder::new(),
            recv_buf: heapless::Vec::new(),
            send_buf: heapless::Vec::new(),
            send_offset: 0,
            conn_send_fc: FlowController::new(DEFAULT_CONNECTION_WINDOW_SIZE),
            conn_recv_fc: FlowController::new(DEFAULT_CONNECTION_WINDOW_SIZE),
            events: heapless::Deque::new(),
            next_stream_id,
            last_peer_stream_id: 0,
            continuation_stream_id: None,
            settings_sent: false,
            settings_ack_received: false,
            peer_settings_received: false,
            preface_sent: false,
            preface_validated: false,
            preface_bytes_seen: 0,
            goaway_sent: false,
            timeout_config: crate::http::TimeoutConfig::default(),
            last_activity: 0,
            connection_start: 0,
            headers_phase_complete: false,
        }
    }

    /// Feed received TCP data into the connection.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        // Ensure our own SETTINGS is queued before processing any peer data
        // (RFC 9113 §3.4: server SETTINGS must be the first frame sent)
        self.generate_output();

        // Append to recv buffer
        if self.recv_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall { needed: self.recv_buf.len() + data.len() });
        }
        let _ = self.recv_buf.extend_from_slice(data);

        // Process received data
        self.process_recv()
    }

    /// Pull the next chunk of outgoing data.
    ///
    /// Returns `Some(slice)` with data to send, or `None` if nothing pending.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        // First, generate any pending output
        self.generate_output();

        if self.send_offset >= self.send_buf.len() {
            return None;
        }

        let avail = self.send_buf.len() - self.send_offset;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&self.send_buf[self.send_offset..self.send_offset + n]);
        self.send_offset += n;

        // If we've consumed everything, clear the buffer
        if self.send_offset >= self.send_buf.len() {
            self.send_buf.clear();
            self.send_offset = 0;
        }

        Some(&buf[..n])
    }

    /// Poll for the next event.
    pub fn poll_event(&mut self) -> Option<H2Event> {
        self.events.pop_front()
    }

    // ------------------------------------------------------------------
    // Application API
    // ------------------------------------------------------------------

    /// Send headers on a new or existing stream.
    ///
    /// For clients: opens a new request stream.
    /// For servers: sends response headers.
    pub fn send_headers(
        &mut self,
        stream_id: u64,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        // Encode headers with HPACK
        let mut hpack_buf = [0u8; 4096];
        let hpack_len = self.encoder.encode(headers, &mut hpack_buf)?;

        // Build HEADERS frame
        let frame = H2Frame::Headers {
            stream_id,
            fragment: &hpack_buf[..hpack_len],
            end_stream,
            end_headers: true,
            priority: None,
        };

        let mut frame_buf = [0u8; 4096];
        let frame_len = frame::encode_frame(&frame, &mut frame_buf)?;

        self.queue_send(&frame_buf[..frame_len])?;

        // Update stream state
        self.ensure_stream(stream_id);
        if let Some(stream) = self.get_stream_mut(stream_id) {
            if stream.state == H2StreamState::Idle {
                stream.open();
            }
            if end_stream {
                stream.send_end_stream();
            }
        }

        Ok(())
    }

    /// Open a new stream and send headers. Returns the stream ID.
    pub fn open_stream(
        &mut self,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        // RFC 9113 §5.1.1: stream IDs must not exceed 2^31-1
        if self.next_stream_id > 0x7fff_ffff {
            return Err(Error::StreamLimitExhausted);
        }
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        self.send_headers(stream_id, headers, end_stream)?;
        Ok(stream_id)
    }

    /// Send data on a stream.
    pub fn send_data(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        // Check stream state
        if let Some(stream) = self.get_stream(stream_id) && !stream.can_send() {
            return Err(Error::InvalidState);
        }
        // Check flow control
        let max_by_conn = self.conn_send_fc.window().max(0) as usize;
        let max_by_stream = self.get_stream(stream_id)
            .map(|s| s.send_window.max(0) as usize)
            .unwrap_or(0);
        let max_frame = self.peer_settings.max_frame_size as usize;
        let can_send = data.len().min(max_by_conn).min(max_by_stream).min(max_frame);

        if can_send == 0 && !data.is_empty() {
            return Err(Error::WouldBlock);
        }

        let to_send = if data.is_empty() { data } else { &data[..can_send] };
        let actual_end = end_stream && (to_send.len() == data.len());

        let frame = H2Frame::Data {
            stream_id,
            payload: to_send,
            end_stream: actual_end,
        };
        let mut frame_buf = [0u8; 16384];
        // Need at most 9 + max_frame_size
        let max_needed = 9 + to_send.len();
        if max_needed > frame_buf.len() {
            return Err(Error::BufferTooSmall { needed: max_needed });
        }
        let frame_len = frame::encode_frame(&frame, &mut frame_buf)?;
        self.queue_send(&frame_buf[..frame_len])?;

        // Update flow control
        if !to_send.is_empty() {
            self.conn_send_fc.consume(to_send.len() as u32)?;
            if let Some(stream) = self.get_stream_mut(stream_id) {
                stream.send_window -= to_send.len() as i32;
            }
        }

        // Update stream state
        if actual_end && let Some(stream) = self.get_stream_mut(stream_id) {
            stream.send_end_stream();
        }

        Ok(to_send.len())
    }

    /// Read received headers for a stream.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        let stream = self.get_stream(stream_id).ok_or(Error::InvalidState)?;
        if !stream.headers_received {
            return Err(Error::WouldBlock);
        }
        self.decoder.decode(&stream.headers_data, emit)?;
        // Clear after decode to prevent double-reading
        if let Some(stream) = self.get_stream_mut(stream_id) {
            stream.headers_data.clear();
            stream.headers_received = false;
        }
        Ok(())
    }

    /// Read received body data for a stream.
    pub fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        let stream = self.get_stream_mut(stream_id).ok_or(Error::InvalidState)?;

        if stream.data_buf.is_empty() {
            if stream.fin_received {
                return Ok((0, true));
            }
            return Err(Error::WouldBlock);
        }

        let copy_len = stream.data_buf.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&stream.data_buf[..copy_len]);

        // Shift remaining data
        let remaining = stream.data_buf.len() - copy_len;
        for i in 0..remaining {
            stream.data_buf[i] = stream.data_buf[copy_len + i];
        }
        stream.data_buf.truncate(remaining);

        let fin = stream.data_buf.is_empty() && stream.fin_received;
        stream.data_available = !stream.data_buf.is_empty();

        // Send WINDOW_UPDATE for connection and stream
        if copy_len > 0 {
            self.send_window_update(0, copy_len as u32);
            self.send_window_update(stream_id, copy_len as u32);
        }

        Ok((copy_len, fin))
    }

    /// Send a GOAWAY frame.
    pub fn send_goaway(&mut self, error_code: u32) -> Result<(), Error> {
        let frame = H2Frame::GoAway {
            last_stream_id: self.last_peer_stream_id,
            error_code,
            debug: &[],
        };
        let mut buf = [0u8; 32];
        let n = frame::encode_frame(&frame, &mut buf)?;
        self.queue_send(&buf[..n])?;
        self.goaway_sent = true;
        self.state = H2ConnState::Closing;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: output generation
    // ------------------------------------------------------------------

    fn generate_output(&mut self) {
        // Send connection preface + SETTINGS if not done
        if !self.preface_sent {
            if self.role == Role::Client {
                // Client sends the preface magic string
                let _ = self.queue_send(CONNECTION_PREFACE);
            }
            // Both roles send SETTINGS
            let _ = self.send_initial_settings();
            self.preface_sent = true;
        }
    }

    fn send_initial_settings(&mut self) -> Result<(), Error> {
        let mut params = [0u8; 64];
        let params_len = self.local_settings.encode_params(&mut params)?;
        let frame = H2Frame::Settings { ack: false, params: &params[..params_len] };
        let mut buf = [0u8; 128];
        let n = frame::encode_frame(&frame, &mut buf)?;
        self.queue_send(&buf[..n])?;
        self.settings_sent = true;
        Ok(())
    }

    fn send_settings_ack(&mut self) -> Result<(), Error> {
        let frame = H2Frame::Settings { ack: true, params: &[] };
        let mut buf = [0u8; 16];
        let n = frame::encode_frame(&frame, &mut buf)?;
        self.queue_send(&buf[..n])
    }

    fn send_ping_ack(&mut self, data: [u8; 8]) -> Result<(), Error> {
        let frame = H2Frame::Ping { data, ack: true };
        let mut buf = [0u8; 32];
        let n = frame::encode_frame(&frame, &mut buf)?;
        self.queue_send(&buf[..n])
    }

    fn send_window_update(&mut self, stream_id: u64, increment: u32) {
        if increment == 0 {
            return;
        }
        let frame = H2Frame::WindowUpdate { stream_id, increment };
        let mut buf = [0u8; 16];
        if let Ok(n) = frame::encode_frame(&frame, &mut buf) {
            let _ = self.queue_send(&buf[..n]);
        }
        // Update our recv window tracker
        if stream_id == 0 {
            let _ = self.conn_recv_fc.replenish(increment);
        } else if let Some(stream) = self.get_stream_mut(stream_id) {
            let new_window = stream.recv_window as i64 + increment as i64;
            stream.recv_window = new_window.min(0x7fff_ffff) as i32;
        }
    }

    fn queue_send(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.send_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall { needed: self.send_buf.len() + data.len() });
        }
        let _ = self.send_buf.extend_from_slice(data);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: receive processing
    // ------------------------------------------------------------------

    fn process_recv(&mut self) -> Result<(), Error> {
        // Phase 1: Validate connection preface (server only)
        if self.role == Role::Server && !self.preface_validated {
            self.validate_client_preface()?;
            if !self.preface_validated {
                return Ok(()); // Need more data
            }
        }

        // Phase 2: Parse frames
        loop {
            if self.recv_buf.len() < 9 {
                break; // Need at least a frame header
            }

            // Peek at frame length
            let payload_len = ((self.recv_buf[0] as usize) << 16)
                | ((self.recv_buf[1] as usize) << 8)
                | (self.recv_buf[2] as usize);
            let total = 9 + payload_len;

            if self.recv_buf.len() < total {
                break; // Incomplete frame
            }

            // We need to extract the frame data before processing to avoid borrow issues.
            // Copy the frame bytes out of recv_buf.
            let mut frame_data = [0u8; 16384];
            if total > frame_data.len() {
                return Err(Error::BufferTooSmall { needed: total });
            }
            frame_data[..total].copy_from_slice(&self.recv_buf[..total]);

            // Remove consumed bytes from recv_buf
            let remaining = self.recv_buf.len() - total;
            for i in 0..remaining {
                self.recv_buf[i] = self.recv_buf[total + i];
            }
            self.recv_buf.truncate(remaining);

            // Parse and handle
            let (frame, _consumed) = frame::decode_frame(&frame_data[..total])?;
            self.handle_frame(frame)?;
        }

        // Clean up closed streams to free slots
        self.streams.retain(|s| s.state != H2StreamState::Closed || s.data_available);

        Ok(())
    }

    fn validate_client_preface(&mut self) -> Result<(), Error> {
        let expected = CONNECTION_PREFACE;
        while self.preface_bytes_seen < expected.len() && !self.recv_buf.is_empty() {
            if self.recv_buf[0] != expected[self.preface_bytes_seen] {
                return Err(Error::InvalidState); // Invalid preface
            }
            self.preface_bytes_seen += 1;
            // Remove consumed byte
            let remaining = self.recv_buf.len() - 1;
            for i in 0..remaining {
                self.recv_buf[i] = self.recv_buf[1 + i];
            }
            self.recv_buf.truncate(remaining);
        }
        if self.preface_bytes_seen >= expected.len() {
            self.preface_validated = true;
        }
        Ok(())
    }

    fn handle_frame(&mut self, frame: H2Frame<'_>) -> Result<(), Error> {
        // RFC 9113 §4.3: If we're expecting CONTINUATION, only CONTINUATION
        // for the same stream is allowed.
        if let Some(expected_sid) = self.continuation_stream_id {
            match &frame {
                H2Frame::Continuation { stream_id, .. } if *stream_id == expected_sid => {
                    // OK — this is the expected continuation
                }
                _ => {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
            }
        }

        match frame {
            H2Frame::Settings { ack, params, .. } => {
                // SETTINGS must be on stream 0 (checked via frame stream_id in caller)
                if ack {
                    // ACK must have empty payload (RFC 9113 §6.5)
                    if !params.is_empty() {
                        return Err(Error::Http2(crate::error::H2Error::FrameSizeError));
                    }
                    self.settings_ack_received = true;
                    if self.peer_settings_received && self.state == H2ConnState::WaitingSettings {
                        self.state = H2ConnState::Active;
                        self.headers_phase_complete = true;
                        let _ = self.events.push_back(H2Event::Connected);
                    }
                } else {
                    // Save old initial window size for delta computation
                    let old_initial = self.peer_settings.initial_window_size as i32;
                    // Apply peer settings (with validation)
                    frame::decode_settings_params(params, |id, value| {
                        self.peer_settings.apply(id, value)
                    })?;
                    self.peer_settings_received = true;
                    // Send ACK
                    self.send_settings_ack()?;
                    // Transition to active once we have peer settings
                    match self.state {
                        H2ConnState::WaitingPreface | H2ConnState::WaitingSettings => {
                            self.state = H2ConnState::Active;
                            self.headers_phase_complete = true;
                            let _ = self.events.push_back(H2Event::Connected);
                        }
                        _ => {}
                    }
                    // Update stream send windows by the delta (RFC 9113 §6.9.2)
                    let new_initial = self.peer_settings.initial_window_size as i32;
                    let delta = new_initial - old_initial;
                    if delta != 0 {
                        for stream in self.streams.iter_mut() {
                            stream.send_window += delta;
                        }
                    }
                }
            }
            H2Frame::Headers { stream_id, fragment, end_stream, end_headers, .. } => {
                // RFC 9113 §6.2: HEADERS must not be on stream 0
                if stream_id == 0 {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                self.last_peer_stream_id = self.last_peer_stream_id.max(stream_id);
                self.ensure_stream(stream_id);
                if let Some(stream) = self.streams.iter_mut().find(|s| s.id == stream_id) {
                    if stream.state == H2StreamState::Idle {
                        stream.open();
                    }
                    // Always store the fragment (may be followed by CONTINUATION)
                    stream.headers_data.clear();
                    let _ = stream.headers_data.extend_from_slice(fragment);
                    if end_headers {
                        stream.headers_received = true;
                    }
                    if end_stream {
                        stream.recv_end_stream();
                    }
                }
                if !end_headers {
                    self.continuation_stream_id = Some(stream_id);
                } else {
                    let _ = self.events.push_back(H2Event::Headers(stream_id));
                }
                if end_stream {
                    let _ = self.events.push_back(H2Event::Finished(stream_id));
                }
            }
            H2Frame::Data { stream_id, payload, end_stream } => {
                // RFC 9113 §6.1: DATA must not be on stream 0
                if stream_id == 0 {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                // Update connection recv flow control
                self.conn_recv_fc.consume(payload.len() as u32)?;

                if let Some(stream) = self.streams.iter_mut().find(|s| s.id == stream_id) {
                    let _ = stream.data_buf.extend_from_slice(payload);
                    stream.data_available = true;
                    stream.recv_window -= payload.len() as i32;
                    if end_stream {
                        stream.recv_end_stream();
                    }
                }
                let _ = self.events.push_back(H2Event::Data(stream_id));
                if end_stream {
                    let _ = self.events.push_back(H2Event::Finished(stream_id));
                }
            }
            H2Frame::WindowUpdate { stream_id, increment } => {
                // RFC 9113 §6.9: increment of 0 MUST be treated as error
                if increment == 0 {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                if stream_id == 0 {
                    self.conn_send_fc.replenish(increment)?;
                } else if let Some(stream) = self.get_stream_mut(stream_id) {
                    // Check overflow: window must not exceed 2^31-1
                    let new_window = stream.send_window as i64 + increment as i64;
                    if new_window > 0x7fff_ffff {
                        return Err(Error::Http2(crate::error::H2Error::FlowControlError));
                    }
                    stream.send_window = new_window as i32;
                }
            }
            H2Frame::Ping { data, ack } => {
                if !ack {
                    self.send_ping_ack(data)?;
                }
            }
            H2Frame::GoAway { last_stream_id, error_code, .. } => {
                self.state = H2ConnState::Closing;
                let _ = self.events.push_back(H2Event::GoAway(last_stream_id, error_code));
            }
            H2Frame::RstStream { stream_id, error_code } => {
                if let Some(stream) = self.get_stream_mut(stream_id) {
                    stream.reset();
                }
                let _ = self.events.push_back(H2Event::StreamReset(stream_id, error_code));
            }
            H2Frame::Priority { .. } => {
                // Priority frames are advisory; we ignore them.
            }
            H2Frame::Continuation { stream_id, fragment, end_headers } => {
                // RFC 9113 §6.10: CONTINUATION must not be on stream 0
                if stream_id == 0 {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                if let Some(stream) = self.get_stream_mut(stream_id) {
                    let _ = stream.headers_data.extend_from_slice(fragment);
                    if end_headers {
                        stream.headers_received = true;
                        self.continuation_stream_id = None;
                        let _ = self.events.push_back(H2Event::Headers(stream_id));
                    }
                }
            }
            H2Frame::PushPromise { .. } => {
                // We don't support server push; ignore.
            }
            H2Frame::Unknown { .. } => {
                // Unknown frames are silently ignored (RFC 9113 §4.1).
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Stream management
    // ------------------------------------------------------------------

    fn ensure_stream(&mut self, stream_id: u64) {
        if !self.streams.iter().any(|s| s.id == stream_id) {
            let initial_send = self.peer_settings.initial_window_size as i32;
            let initial_recv = self.local_settings.initial_window_size as i32;
            let _ = self.streams.push(H2Stream::new(stream_id, initial_send, initial_recv));
        }
    }

    fn get_stream(&self, stream_id: u64) -> Option<&H2Stream<HDRBUF, DATABUF>> {
        self.streams.iter().find(|s| s.id == stream_id)
    }

    fn get_stream_mut(&mut self, stream_id: u64) -> Option<&mut H2Stream<HDRBUF, DATABUF>> {
        self.streams.iter_mut().find(|s| s.id == stream_id)
    }

    /// Whether the connection is in Active state.
    pub fn is_active(&self) -> bool {
        self.state == H2ConnState::Active
    }

    // ------------------------------------------------------------------
    // Timeout + connection state API
    // ------------------------------------------------------------------

    /// Configure timeouts. `now` is the current timestamp in microseconds.
    pub fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        self.timeout_config = config;
        self.last_activity = now;
        self.connection_start = now;
    }

    /// Return the earliest deadline (in µs) at which `handle_timeout` should be called,
    /// or `None` if no timeouts are configured.
    pub fn next_timeout(&self) -> Option<u64> {
        if self.state == H2ConnState::Closed {
            return None;
        }
        let mut earliest: Option<u64> = None;

        if !self.headers_phase_complete {
            if let Some(hdr_us) = self.timeout_config.header_timeout_us {
                let deadline = self.connection_start.saturating_add(hdr_us);
                earliest = Some(earliest.map_or(deadline, |e: u64| e.min(deadline)));
            }
        }

        if let Some(idle_us) = self.timeout_config.idle_timeout_us {
            let deadline = self.last_activity.saturating_add(idle_us);
            earliest = Some(earliest.map_or(deadline, |e: u64| e.min(deadline)));
        }

        earliest
    }

    /// Check timeouts. If a timeout fires, queues a GOAWAY frame, transitions
    /// to Closed, and emits `H2Event::Timeout`.
    pub fn handle_timeout(&mut self, now: u64) {
        if self.state == H2ConnState::Closed {
            return;
        }

        // Header timeout: fires if headers phase not complete
        if !self.headers_phase_complete {
            if let Some(hdr_us) = self.timeout_config.header_timeout_us {
                if now >= self.connection_start.saturating_add(hdr_us) {
                    let _ = self.send_goaway(0);
                    self.state = H2ConnState::Closed;
                    let _ = self.events.push_back(H2Event::Timeout);
                    return;
                }
            }
        }

        // Idle timeout
        if let Some(idle_us) = self.timeout_config.idle_timeout_us {
            if now >= self.last_activity.saturating_add(idle_us) {
                let _ = self.send_goaway(0);
                self.state = H2ConnState::Closed;
                let _ = self.events.push_back(H2Event::Timeout);
            }
        }
    }

    /// Feed data with timestamp tracking. Updates `last_activity` then calls `feed_data`.
    pub fn feed_data_timed(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        self.last_activity = now;
        self.feed_data(data)
    }

    /// Whether the connection has been closed (GOAWAY sent/received, or timeout).
    pub fn is_closed(&self) -> bool {
        matches!(self.state, H2ConnState::Closed | H2ConnState::Closing)
    }

    /// Whether the SETTINGS exchange is complete and the connection is usable.
    pub fn is_established(&self) -> bool {
        self.state == H2ConnState::Active
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_generates_preface() {
        let mut conn = H2Connection::<16, 4096>::new_client();
        let mut buf = [0u8; 4096];
        let output = conn.poll_output(&mut buf);
        assert!(output.is_some());
        let data = output.unwrap();
        // Should start with the connection preface
        assert!(data.starts_with(CONNECTION_PREFACE));
        // Followed by SETTINGS frame
        let after_preface = &data[CONNECTION_PREFACE.len()..];
        assert!(after_preface.len() >= 9);
        // SETTINGS frame type is 0x04
        assert_eq!(after_preface[3], FRAME_SETTINGS);
    }

    #[test]
    fn server_generates_settings_only() {
        let mut conn = H2Connection::<16, 4096>::new_server();
        let mut buf = [0u8; 4096];
        let output = conn.poll_output(&mut buf);
        assert!(output.is_some());
        let data = output.unwrap();
        // Server should NOT send the preface magic, just SETTINGS
        assert_eq!(data[3], FRAME_SETTINGS);
    }

    #[test]
    fn client_server_handshake() {
        let mut client = H2Connection::<16, 8192>::new_client();
        let mut server = H2Connection::<16, 8192>::new_server();

        // Client → Server
        let mut buf = [0u8; 4096];
        let data = client.poll_output(&mut buf).unwrap();
        let client_data: heapless::Vec<u8, 4096> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(data);
            v
        };
        server.feed_data(&client_data).unwrap();

        // Server → Client
        let mut buf2 = [0u8; 4096];
        let data = server.poll_output(&mut buf2).unwrap();
        let server_data: heapless::Vec<u8, 4096> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(data);
            v
        };
        client.feed_data(&server_data).unwrap();

        // Client should get Connected event (received server SETTINGS)
        let mut client_connected = false;
        while let Some(ev) = client.poll_event() {
            if ev == H2Event::Connected {
                client_connected = true;
            }
        }
        assert!(client_connected);

        // Client sends SETTINGS ACK back
        let mut buf3 = [0u8; 4096];
        if let Some(data) = client.poll_output(&mut buf3) {
            let ack_data: heapless::Vec<u8, 4096> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            server.feed_data(&ack_data).unwrap();
        }

        // Server should get Connected event
        let mut server_connected = false;
        while let Some(ev) = server.poll_event() {
            if ev == H2Event::Connected {
                server_connected = true;
            }
        }
        assert!(server_connected);
    }

    #[test]
    fn full_request_response() {
        let mut client = H2Connection::<16, 16384>::new_client();
        let mut server = H2Connection::<16, 16384>::new_server();

        // Run handshake
        run_handshake(&mut client, &mut server);

        // Client sends request
        let stream_id = client.open_stream(
            &[
                (b":method", b"GET"),
                (b":path", b"/"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
            ],
            true, // end_stream — GET has no body
        ).unwrap();
        assert_eq!(stream_id, 1);

        // Exchange
        exchange(&mut client, &mut server);

        // Server should see Headers
        let mut got_headers = false;
        let mut header_stream = 0u64;
        while let Some(ev) = server.poll_event() {
            if let H2Event::Headers(sid) = ev {
                got_headers = true;
                header_stream = sid;
            }
        }
        assert!(got_headers);

        // Server reads headers
        let mut method = heapless::Vec::<u8, 64>::new();
        server.recv_headers(header_stream, |name, value| {
            if name == b":method" {
                let _ = method.extend_from_slice(value);
            }
        }).unwrap();
        assert_eq!(method.as_slice(), b"GET");

        // Server sends response
        server.send_headers(
            header_stream,
            &[(b":status", b"200"), (b"content-type", b"text/plain")],
            false,
        ).unwrap();
        server.send_data(header_stream, b"Hello!", true).unwrap();

        // Exchange
        exchange(&mut server, &mut client);

        // Client should see response
        let mut got_resp = false;
        let mut got_data = false;
        while let Some(ev) = client.poll_event() {
            match ev {
                H2Event::Headers(sid) if sid == stream_id => got_resp = true,
                H2Event::Data(sid) if sid == stream_id => got_data = true,
                _ => {}
            }
        }
        assert!(got_resp);
        assert!(got_data);

        // Client reads response body
        let mut body = [0u8; 256];
        let (n, fin) = client.recv_body(stream_id, &mut body).unwrap();
        assert_eq!(&body[..n], b"Hello!");
        assert!(fin);
    }

    #[test]
    fn ping_pong() {
        let mut client = H2Connection::<16, 8192>::new_client();
        let mut server = H2Connection::<16, 8192>::new_server();
        run_handshake(&mut client, &mut server);

        // Client sends PING
        let ping_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let frame = H2Frame::Ping { data: ping_data, ack: false };
        let mut buf = [0u8; 32];
        let n = frame::encode_frame(&frame, &mut buf).unwrap();
        client.queue_send(&buf[..n]).unwrap();

        // Exchange
        exchange(&mut client, &mut server);

        // Server should have sent PING ACK
        let mut buf2 = [0u8; 4096];
        if let Some(data) = server.poll_output(&mut buf2) {
            client.feed_data(data).unwrap();
        }
        // We just verify no error occurred — the pong was sent automatically
    }

    #[test]
    fn goaway() {
        let mut client = H2Connection::<16, 8192>::new_client();
        let mut server = H2Connection::<16, 8192>::new_server();
        run_handshake(&mut client, &mut server);

        // Server sends GOAWAY
        server.send_goaway(0).unwrap();
        exchange(&mut server, &mut client);

        let mut got_goaway = false;
        while let Some(ev) = client.poll_event() {
            if let H2Event::GoAway(_, _) = ev {
                got_goaway = true;
            }
        }
        assert!(got_goaway);
    }

    // Test helpers

    fn run_handshake<const M: usize, const B: usize, const H: usize, const D: usize>(
        client: &mut H2Connection<M, B, H, D>,
        server: &mut H2Connection<M, B, H, D>,
    ) {
        for _ in 0..5 {
            exchange(client, server);
            exchange(server, client);
        }
    }

    fn exchange<const M: usize, const B: usize, const H: usize, const D: usize>(
        sender: &mut H2Connection<M, B, H, D>,
        receiver: &mut H2Connection<M, B, H, D>,
    ) {
        let mut buf = [0u8; 8192];
        while let Some(data) = sender.poll_output(&mut buf) {
            let copy: heapless::Vec<u8, 8192> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            let _ = receiver.feed_data(&copy);
        }
    }

    // ====== Timeout + Connection State Tests ======

    #[test]
    fn idle_timeout_fires() {
        let mut client = H2Connection::<16, 8192>::new_client();
        let mut server = H2Connection::<16, 8192>::new_server();

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000), // 1 second
            header_timeout_us: None,
        };
        server.set_timeouts(config, 0);
        run_handshake(&mut client, &mut server);

        // No activity for 2 seconds
        server.handle_timeout(2_000_000);

        let mut got_timeout = false;
        while let Some(ev) = server.poll_event() {
            if ev == H2Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout);
        assert!(server.is_closed());
    }

    #[test]
    fn header_timeout_fires_during_preface() {
        let mut server = H2Connection::<16, 8192>::new_server();

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: None,
            header_timeout_us: Some(500_000), // 0.5 seconds
        };
        server.set_timeouts(config, 0);

        // No data sent, header timeout fires
        server.handle_timeout(600_000);

        let mut got_timeout = false;
        while let Some(ev) = server.poll_event() {
            if ev == H2Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout);
        assert!(server.is_closed());
    }

    #[test]
    fn activity_resets_idle_timer() {
        let mut client = H2Connection::<16, 8192>::new_client();
        let mut server = H2Connection::<16, 8192>::new_server();

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: None,
        };
        server.set_timeouts(config, 0);
        run_handshake(&mut client, &mut server);

        // Activity at t=800ms
        server.feed_data_timed(b"", 800_000).unwrap();

        // Check at t=1.5s — should NOT timeout (last activity was 800ms, idle is 1s)
        server.handle_timeout(1_500_000);
        assert!(!server.is_closed());

        // Check at t=2s — SHOULD timeout (1.2s since last activity)
        server.handle_timeout(2_000_000);
        assert!(server.is_closed());
    }

    #[test]
    fn is_closed_and_is_established() {
        let mut client = H2Connection::<16, 8192>::new_client();
        let mut server = H2Connection::<16, 8192>::new_server();

        // Before handshake
        assert!(!server.is_established());
        assert!(!server.is_closed());

        run_handshake(&mut client, &mut server);

        // After handshake
        assert!(server.is_established());
        assert!(!server.is_closed());

        // After GOAWAY
        server.send_goaway(0).unwrap();
        assert!(!server.is_established());
        assert!(server.is_closed());
    }

    #[test]
    fn next_timeout_returns_correct_deadline() {
        let mut server = H2Connection::<16, 8192>::new_server();

        // No config → no timeout
        assert_eq!(server.next_timeout(), None);

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: Some(500_000),
        };
        server.set_timeouts(config, 100_000);

        // header timeout is 100_000 + 500_000 = 600_000
        // idle timeout is 100_000 + 1_000_000 = 1_100_000
        // earliest is 600_000
        assert_eq!(server.next_timeout(), Some(600_000));
    }
}
