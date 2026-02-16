//! HTTP/1.1 connection state machine.
//!
//! Pure codec following the milli-http pattern:
//! `feed_data()` → `poll_output()` → `poll_event()`
//!
//! # Buffer lifecycle
//!
//! The connection will not begin parsing the next request/response until the
//! application has consumed the current headers (via [`recv_headers`]) and body
//! data (via [`recv_body`]). This prevents data from one message leaking into
//! the next on keep-alive connections.
//!
//! # Stack usage
//!
//! [`try_parse_start_line`] allocates a temporary `heapless::Vec<u8, BUF>` on
//! the stack to work around borrow-checker limitations. With the default
//! `BUF = 8192` this adds 8 KiB to the call stack.

use crate::buf::Buf;
use crate::error::Error;
use super::parse;

/// Events produced by the HTTP/1.1 connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1Event {
    /// Connection ready. Emitted as the first event for API consistency with H2/H3.
    Connected,
    /// Headers received (request headers on server-side, response headers on client-side).
    /// The `u64` is a pseudo-stream-id for API consistency with H2/H3.
    Headers(u64),
    /// Body data available.
    Data(u64),
    /// Request/response complete.
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

/// Parse state for incoming messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Waiting for a request line (server) or status line (client).
    Idle,
    /// Reading body with known Content-Length.
    BodyContentLength { remaining: usize },
    /// Reading chunked transfer encoding.
    BodyChunked,
    /// Reading body until connection close (response only).
    BodyUntilClose,
    /// Current message is done; waiting for app to drain buffers before
    /// accepting the next message (keep-alive).
    Done,
}

/// Chunk decoding sub-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// Expecting a chunk-size line.
    Size,
    /// Reading chunk data bytes.
    Data { remaining: usize },
    /// Expecting CRLF after chunk data.
    DataTrailer,
    /// Final chunk received; expecting optional trailers + final CRLF.
    Trailers,
}

/// HTTP/1.1 connection state machine.
///
/// Generic parameters:
/// - `BUF`: size of internal send/recv buffers
/// - `HDRBUF`: header storage buffer size
/// - `DATABUF`: body data buffer size
pub struct Http1Connection<
    const BUF: usize = 8192,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    role: Role,
    state: ParseState,
    recv_buf: Buf<BUF>,
    send_buf: Buf<BUF>,
    send_offset: usize,
    /// Parsed headers stored as `name\0value\0` pairs.
    header_buf: Buf<HDRBUF>,
    headers_available: bool,
    /// Buffered body data for the application to read.
    data_buf: Buf<DATABUF>,
    events: heapless::Deque<Http1Event, 32>,
    /// Pseudo-stream-id (increments per request).
    current_stream_id: u64,
    /// Chunked decoding sub-state.
    chunk_state: ChunkState,
    /// Whether the current message uses keep-alive.
    keep_alive: bool,
    /// Whether end-of-stream has been signalled for the current message.
    body_finished: bool,
    /// Whether the Connected event has been emitted.
    connected_emitted: bool,
    // Timeout support
    timeout_config: crate::http::TimeoutConfig,
    last_activity: u64,
    connection_start: u64,
    headers_phase_complete: bool,
    closed: bool,
}

impl<const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    Http1Connection<BUF, HDRBUF, DATABUF>
{
    /// Create a new client-side HTTP/1.1 connection.
    pub fn new_client() -> Self {
        Self::new(Role::Client)
    }

    /// Create a new server-side HTTP/1.1 connection.
    pub fn new_server() -> Self {
        Self::new(Role::Server)
    }

    fn new(role: Role) -> Self {
        Self {
            role,
            state: ParseState::Idle,
            recv_buf: Buf::new(),
            send_buf: Buf::new(),
            send_offset: 0,
            header_buf: Buf::new(),
            headers_available: false,
            data_buf: Buf::new(),
            events: heapless::Deque::new(),
            current_stream_id: 0,
            chunk_state: ChunkState::Size,
            keep_alive: true,
            body_finished: false,
            connected_emitted: false,
            timeout_config: crate::http::TimeoutConfig::default(),
            last_activity: 0,
            connection_start: 0,
            headers_phase_complete: false,
            closed: false,
        }
    }

    /// Feed received TCP data into the connection.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.recv_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: self.recv_buf.len() + data.len(),
            });
        }
        let _ = self.recv_buf.extend_from_slice(data);
        self.process_recv()
    }

    /// Pull the next chunk of outgoing data.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
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

    /// Poll for the next event.
    pub fn poll_event(&mut self) -> Option<Http1Event> {
        if !self.connected_emitted {
            self.connected_emitted = true;
            return Some(Http1Event::Connected);
        }
        self.events.pop_front()
    }

    // ------------------------------------------------------------------
    // Application API
    // ------------------------------------------------------------------

    /// Send headers (request line + headers for client, status line + headers for server).
    ///
    /// Headers should include pseudo-headers (`:method`, `:path`, `:status`) which
    /// will be used to construct the request/status line.
    pub fn send_headers(
        &mut self,
        stream_id: u64,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        self.check_stream_id(stream_id)?;
        match self.role {
            Role::Client => self.encode_request(headers, end_stream),
            Role::Server => self.encode_response(headers, end_stream),
        }
    }

    /// Send body data.
    pub fn send_data(
        &mut self,
        stream_id: u64,
        data: &[u8],
        _end_stream: bool,
    ) -> Result<usize, Error> {
        self.check_stream_id(stream_id)?;
        self.queue_send(data)?;
        Ok(data.len())
    }

    /// Read received headers via callback.
    ///
    /// Iterates stored headers as `name\0value\0` pairs, calling `emit(name, value)`.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        mut emit: F,
    ) -> Result<(), Error> {
        self.check_stream_id(stream_id)?;
        if !self.headers_available {
            return Err(Error::WouldBlock);
        }

        let buf = &self.header_buf;
        let mut pos = 0;
        while pos < buf.len() {
            // Find name end (first \0)
            let name_end = buf[pos..]
                .iter()
                .position(|&b| b == 0)
                .map(|i| pos + i)
                .unwrap_or(buf.len());
            if name_end >= buf.len() {
                break;
            }
            let name = &buf[pos..name_end];

            // Find value end (second \0)
            let value_start = name_end + 1;
            let value_end = buf[value_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|i| value_start + i)
                .unwrap_or(buf.len());
            let value = &buf[value_start..value_end];

            emit(name, value);
            pos = value_end + 1;
        }

        self.header_buf.clear();
        self.headers_available = false;
        Ok(())
    }

    /// Read received body data.
    pub fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        self.check_stream_id(stream_id)?;
        if self.data_buf.is_empty() {
            if self.body_finished {
                return Ok((0, true));
            }
            return Err(Error::WouldBlock);
        }

        let copy_len = self.data_buf.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&self.data_buf[..copy_len]);

        // Shift remaining data
        self.data_buf.copy_within(copy_len.., 0);
        self.data_buf.truncate(self.data_buf.len() - copy_len);

        let fin = self.data_buf.is_empty() && self.body_finished;
        Ok((copy_len, fin))
    }

    /// Open a new stream (client-side: encode request).
    pub fn open_stream(
        &mut self,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        self.current_stream_id += 1;
        let sid = self.current_stream_id;
        self.send_headers(sid, headers, end_stream)?;
        Ok(sid)
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
        if self.closed {
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

    /// Check timeouts. If a timeout fires, sets `closed = true` and emits
    /// `Http1Event::Timeout`.
    pub fn handle_timeout(&mut self, now: u64) {
        if self.closed {
            return;
        }

        // Header timeout: fires if headers phase not complete
        if !self.headers_phase_complete {
            if let Some(hdr_us) = self.timeout_config.header_timeout_us {
                if now >= self.connection_start.saturating_add(hdr_us) {
                    self.closed = true;
                    let _ = self.events.push_back(Http1Event::Timeout);
                    return;
                }
            }
        }

        // Idle timeout
        if let Some(idle_us) = self.timeout_config.idle_timeout_us {
            if now >= self.last_activity.saturating_add(idle_us) {
                self.closed = true;
                let _ = self.events.push_back(Http1Event::Timeout);
            }
        }
    }

    /// Feed data with timestamp tracking. Updates `last_activity` then calls `feed_data`.
    pub fn feed_data_timed(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        self.last_activity = now;
        self.feed_data(data)
    }

    /// Whether the connection has been closed (by timeout or other means).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the connection is usable (not closed).
    pub fn is_established(&self) -> bool {
        !self.closed
    }

    // ------------------------------------------------------------------
    // Internal: validation
    // ------------------------------------------------------------------

    /// Validate that the stream_id matches the current active stream.
    fn check_stream_id(&self, stream_id: u64) -> Result<(), Error> {
        if stream_id != self.current_stream_id {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: encoding
    // ------------------------------------------------------------------

    fn encode_request(
        &mut self,
        headers: &[(&[u8], &[u8])],
        _end_stream: bool,
    ) -> Result<(), Error> {
        let mut method: &[u8] = b"GET";
        let mut path: &[u8] = b"/";
        let mut host: &[u8] = b"";

        // Collect pseudo-headers and regular headers
        for &(name, value) in headers {
            match name {
                b":method" => method = value,
                b":path" => path = value,
                b":authority" => host = value,
                _ => {}
            }
        }

        // Request line: METHOD PATH HTTP/1.1\r\n
        self.queue_send(method)?;
        self.queue_send(b" ")?;
        self.queue_send(path)?;
        self.queue_send(b" HTTP/1.1\r\n")?;

        // Host header
        if !host.is_empty() {
            self.queue_send(b"Host: ")?;
            self.queue_send(host)?;
            self.queue_send(b"\r\n")?;
        }

        // Regular headers
        for &(name, value) in headers {
            if name.starts_with(b":") {
                continue; // Skip pseudo-headers
            }
            self.queue_send(name)?;
            self.queue_send(b": ")?;
            self.queue_send(value)?;
            self.queue_send(b"\r\n")?;
        }

        // End of headers
        self.queue_send(b"\r\n")?;

        Ok(())
    }

    fn encode_response(
        &mut self,
        headers: &[(&[u8], &[u8])],
        _end_stream: bool,
    ) -> Result<(), Error> {
        let mut status: &[u8] = b"200";

        for &(name, value) in headers {
            if name == b":status" {
                status = value;
            }
        }

        let reason = status_reason(status);

        // Status line: HTTP/1.1 STATUS REASON\r\n
        self.queue_send(b"HTTP/1.1 ")?;
        self.queue_send(status)?;
        self.queue_send(b" ")?;
        self.queue_send(reason)?;
        self.queue_send(b"\r\n")?;

        // Regular headers
        for &(name, value) in headers {
            if name.starts_with(b":") {
                continue;
            }
            self.queue_send(name)?;
            self.queue_send(b": ")?;
            self.queue_send(value)?;
            self.queue_send(b"\r\n")?;
        }

        // End of headers
        self.queue_send(b"\r\n")?;

        Ok(())
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

    // ------------------------------------------------------------------
    // Internal: receive processing
    // ------------------------------------------------------------------

    fn process_recv(&mut self) -> Result<(), Error> {
        loop {
            match self.state {
                ParseState::Idle => {
                    if !self.try_parse_start_line()? {
                        return Ok(());
                    }
                }
                ParseState::BodyContentLength { remaining } => {
                    if !self.process_content_length_body(remaining)? {
                        return Ok(());
                    }
                }
                ParseState::BodyChunked => {
                    if !self.process_chunked_body()? {
                        return Ok(());
                    }
                }
                ParseState::BodyUntilClose => {
                    self.process_until_close_body();
                    return Ok(());
                }
                ParseState::Done => {
                    // Only transition to Idle once the app has consumed headers
                    // and body data. This prevents data from one message leaking
                    // into the next on keep-alive connections.
                    if self.headers_available || !self.data_buf.is_empty() {
                        return Ok(());
                    }
                    self.body_finished = false;
                    self.chunk_state = ChunkState::Size;
                    // Reset header phase for the next keep-alive request
                    self.headers_phase_complete = false;
                    self.connection_start = self.last_activity;
                    self.state = ParseState::Idle;
                }
            }
        }
    }

    /// Try to parse a request line (server) or status line (client) + headers.
    /// Returns true if we transitioned out of Idle.
    fn try_parse_start_line(&mut self) -> Result<bool, Error> {
        // Need at least the full headers block
        let end = match parse::find_end_of_headers(&self.recv_buf) {
            Some(e) => e,
            None => return Ok(false),
        };

        // Copy the header block out so we can parse from a separate buffer
        // while mutating self.header_buf. This puts BUF bytes on the stack.
        let mut hdr_copy: heapless::Vec<u8, BUF> = heapless::Vec::new();
        if hdr_copy.extend_from_slice(&self.recv_buf[..end]).is_err() {
            return Err(Error::BufferTooSmall { needed: end });
        }

        self.header_buf.clear();
        self.headers_available = false;

        let mut offset = 0;

        if self.role == Role::Server {
            // Parse request line from the copy (no borrow on self)
            let (method, path, consumed) = parse::parse_request_line(&hdr_copy[offset..])?;
            self.store_header(b":method", method)?;
            self.store_header(b":path", path)?;
            offset += consumed;
        } else {
            // Parse status line
            let (status, _reason, consumed) = parse::parse_status_line(&hdr_copy[offset..])?;
            let status_bytes = crate::http::StatusCode(status).to_bytes();
            self.store_header(b":status", &status_bytes)?;
            offset += consumed;
        }

        // Parse headers
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut connection_close = false;

        loop {
            let (name, value, consumed) = parse::parse_header_line(&hdr_copy[offset..])?;
            offset += consumed;

            if name.is_empty() {
                break; // End of headers
            }

            // Reject null bytes in header names and values (RFC 9110 forbids them,
            // and they would corrupt our \0-separated header_buf storage).
            if name.contains(&0) || value.contains(&0) {
                return Err(Error::InvalidState);
            }

            // Check for transfer-encoding and content-length (case-insensitive)
            if eq_ignore_case(name, b"content-length") {
                content_length = parse_usize_ascii(value);
            } else if eq_ignore_case(name, b"transfer-encoding") {
                if contains_ignore_case(value, b"chunked") {
                    chunked = true;
                }
            } else if eq_ignore_case(name, b"connection")
                && contains_ignore_case(value, b"close")
            {
                connection_close = true;
            }

            self.store_header(name, value)?;
        }

        // RFC 9112 §6.1: reject messages with both Content-Length and
        // Transfer-Encoding to prevent request smuggling.
        if chunked && content_length.is_some() {
            return Err(Error::InvalidState);
        }

        // Consume parsed bytes from recv_buf
        self.drain_recv(end);

        self.headers_available = true;
        self.keep_alive = !connection_close;

        // Determine body framing
        if chunked {
            self.state = ParseState::BodyChunked;
            self.chunk_state = ChunkState::Size;
        } else if let Some(len) = content_length {
            if len == 0 {
                self.state = ParseState::Done;
                self.body_finished = true;
            } else {
                self.state = ParseState::BodyContentLength { remaining: len };
            }
        } else if self.role == Role::Server {
            // Requests without Content-Length or Transfer-Encoding have no body
            self.state = ParseState::Done;
            self.body_finished = true;
        } else {
            // Responses without either might read until close
            self.state = ParseState::BodyUntilClose;
        }

        // Emit events
        self.headers_phase_complete = true;
        if self.role == Role::Server {
            self.current_stream_id += 1;
            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Headers(sid));
        } else {
            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Headers(sid));
        }

        if self.body_finished {
            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Finished(sid));
        }

        Ok(true)
    }

    fn process_content_length_body(&mut self, remaining: usize) -> Result<bool, Error> {
        if self.recv_buf.is_empty() {
            return Ok(false);
        }

        let to_consume = self.recv_buf.len().min(remaining);
        let can_store = (DATABUF - self.data_buf.len()).min(to_consume);

        if can_store > 0 {
            let _ = self.data_buf.extend_from_slice(&self.recv_buf[..can_store]);
            self.drain_recv(can_store);
            let new_remaining = remaining - can_store;

            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Data(sid));

            if new_remaining == 0 {
                self.body_finished = true;
                self.state = ParseState::Done;
                let _ = self.events.push_back(Http1Event::Finished(sid));
            } else {
                self.state = ParseState::BodyContentLength {
                    remaining: new_remaining,
                };
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn process_chunked_body(&mut self) -> Result<bool, Error> {
        match self.chunk_state {
            ChunkState::Size => {
                let result = parse::parse_chunk_size(&self.recv_buf);
                match result {
                    Ok((size, consumed)) => {
                        self.drain_recv(consumed);
                        if size == 0 {
                            self.chunk_state = ChunkState::Trailers;
                        } else {
                            self.chunk_state = ChunkState::Data { remaining: size };
                        }
                        Ok(true)
                    }
                    Err(Error::WouldBlock) => Ok(false),
                    Err(e) => Err(e),
                }
            }
            ChunkState::Data { remaining } => {
                if self.recv_buf.is_empty() {
                    return Ok(false);
                }
                let to_consume = self.recv_buf.len().min(remaining);
                let can_store = (DATABUF - self.data_buf.len()).min(to_consume);

                if can_store > 0 {
                    let _ = self.data_buf.extend_from_slice(&self.recv_buf[..can_store]);
                    self.drain_recv(can_store);
                    let new_remaining = remaining - can_store;

                    let sid = self.current_stream_id;
                    let _ = self.events.push_back(Http1Event::Data(sid));

                    if new_remaining == 0 {
                        self.chunk_state = ChunkState::DataTrailer;
                    } else {
                        self.chunk_state = ChunkState::Data {
                            remaining: new_remaining,
                        };
                    }
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ChunkState::DataTrailer => {
                // Expecting CRLF after chunk data
                if self.recv_buf.len() < 2 {
                    return Ok(false);
                }
                if self.recv_buf[0] == b'\r' && self.recv_buf[1] == b'\n' {
                    self.drain_recv(2);
                    self.chunk_state = ChunkState::Size;
                    Ok(true)
                } else {
                    Err(Error::InvalidState)
                }
            }
            ChunkState::Trailers => {
                // After last chunk (size=0), expect CRLF (no trailers supported)
                if self.recv_buf.len() < 2 {
                    return Ok(false);
                }
                if self.recv_buf[0] == b'\r' && self.recv_buf[1] == b'\n' {
                    self.drain_recv(2);
                    self.body_finished = true;
                    self.state = ParseState::Done;
                    let sid = self.current_stream_id;
                    let _ = self.events.push_back(Http1Event::Finished(sid));
                    Ok(true)
                } else {
                    // Skip trailer headers
                    let (_, _, consumed) = parse::parse_header_line(&self.recv_buf)?;
                    self.drain_recv(consumed);
                    Ok(true)
                }
            }
        }
    }

    fn process_until_close_body(&mut self) {
        if !self.recv_buf.is_empty() {
            let n = self.recv_buf.len().min(DATABUF - self.data_buf.len());
            if n > 0 {
                let _ = self.data_buf.extend_from_slice(&self.recv_buf[..n]);
                self.drain_recv(n);
                let sid = self.current_stream_id;
                let _ = self.events.push_back(Http1Event::Data(sid));
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn store_header(&mut self, name: &[u8], value: &[u8]) -> Result<(), Error> {
        let needed = name.len() + 1 + value.len() + 1; // name\0value\0
        if self.header_buf.len() + needed > HDRBUF {
            return Err(Error::BufferTooSmall { needed });
        }
        let _ = self.header_buf.extend_from_slice(name);
        let _ = self.header_buf.push(0);
        let _ = self.header_buf.extend_from_slice(value);
        let _ = self.header_buf.push(0);
        Ok(())
    }

    fn drain_recv(&mut self, count: usize) {
        self.recv_buf.copy_within(count.., 0);
        self.recv_buf.truncate(self.recv_buf.len() - count);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Case-insensitive comparison of ASCII bytes.
fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(&x, &y)| x.eq_ignore_ascii_case(&y))
}

/// Check if `haystack` contains `needle` (case-insensitive, for header values).
fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if eq_ignore_case(&haystack[i..i + needle.len()], needle) {
            return true;
        }
    }
    false
}

/// Parse ASCII decimal bytes to usize.
fn parse_usize_ascii(buf: &[u8]) -> Option<usize> {
    let mut n: usize = 0;
    if buf.is_empty() {
        return None;
    }
    for &b in buf {
        let d = b.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(d as usize)?;
    }
    Some(n)
}

/// Map status code to reason phrase.
fn status_reason(status: &[u8]) -> &'static [u8] {
    match status {
        b"100" => b"Continue",
        b"101" => b"Switching Protocols",
        b"200" => b"OK",
        b"201" => b"Created",
        b"204" => b"No Content",
        b"301" => b"Moved Permanently",
        b"302" => b"Found",
        b"304" => b"Not Modified",
        b"307" => b"Temporary Redirect",
        b"308" => b"Permanent Redirect",
        b"400" => b"Bad Request",
        b"401" => b"Unauthorized",
        b"403" => b"Forbidden",
        b"404" => b"Not Found",
        b"405" => b"Method Not Allowed",
        b"408" => b"Request Timeout",
        b"413" => b"Payload Too Large",
        b"429" => b"Too Many Requests",
        b"500" => b"Internal Server Error",
        b"502" => b"Bad Gateway",
        b"503" => b"Service Unavailable",
        _ => b"",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_parses_get_request() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Headers(1));

        // Should also get Finished since GET has no body
        let event2 = conn.poll_event().unwrap();
        assert_eq!(event2, Http1Event::Finished(1));

        // Read headers
        let mut method = heapless::Vec::<u8, 16>::new();
        let mut path = heapless::Vec::<u8, 64>::new();
        let mut host = heapless::Vec::<u8, 64>::new();
        conn.recv_headers(1, |name, value| {
            match name {
                b":method" => {
                    let _ = method.extend_from_slice(value);
                }
                b":path" => {
                    let _ = path.extend_from_slice(value);
                }
                b"Host" => {
                    let _ = host.extend_from_slice(value);
                }
                _ => {}
            }
        })
        .unwrap();
        assert_eq!(method.as_slice(), b"GET");
        assert_eq!(path.as_slice(), b"/");
        assert_eq!(host.as_slice(), b"example.com");
    }

    #[test]
    fn server_parses_post_with_body() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(
            b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Headers(1));

        // Data event
        let event2 = conn.poll_event().unwrap();
        assert_eq!(event2, Http1Event::Data(1));

        // Finished event
        let event3 = conn.poll_event().unwrap();
        assert_eq!(event3, Http1Event::Finished(1));

        // Read body
        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(fin);
    }

    #[test]
    fn server_parses_chunked_body() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(
            b"POST /data HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        .unwrap();

        // Collect all events
        let mut events = heapless::Vec::<Http1Event, 16>::new();
        while let Some(ev) = conn.poll_event() {
            let _ = events.push(ev);
        }

        assert!(events.contains(&Http1Event::Headers(1)));
        assert!(events.contains(&Http1Event::Finished(1)));

        // Read body
        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
        assert!(fin);
    }

    #[test]
    fn client_parses_response() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_client();
        conn.current_stream_id = 1; // Simulate having sent a request
        conn.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Headers(1));

        // Read status
        let mut status = heapless::Vec::<u8, 16>::new();
        conn.recv_headers(1, |name, value| {
            if name == b":status" {
                let _ = status.extend_from_slice(value);
            }
        })
        .unwrap();
        assert_eq!(status.as_slice(), b"200");

        // Data + finished
        let event2 = conn.poll_event().unwrap();
        assert_eq!(event2, Http1Event::Data(1));

        let event3 = conn.poll_event().unwrap();
        assert_eq!(event3, Http1Event::Finished(1));

        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(fin);
    }

    #[test]
    fn server_sends_response() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.current_stream_id = 1;

        conn.send_headers(
            1,
            &[
                (b":status", b"200"),
                (b"content-type", b"text/plain"),
                (b"content-length", b"5"),
            ],
            false,
        )
        .unwrap();

        conn.send_data(1, b"hello", true).unwrap();

        let mut out = [0u8; 4096];
        let data = conn.poll_output(&mut out).unwrap();

        let expected =
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello";
        assert_eq!(data, expected);
    }

    #[test]
    fn client_sends_request() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_client();

        let sid = conn
            .open_stream(
                &[
                    (b":method", b"GET"),
                    (b":path", b"/index.html"),
                    (b":authority", b"example.com"),
                ],
                true,
            )
            .unwrap();
        assert_eq!(sid, 1);

        let mut out = [0u8; 4096];
        let data = conn.poll_output(&mut out).unwrap();

        let expected = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(data, expected);
    }

    #[test]
    fn incremental_feed() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();

        // Feed partial request
        conn.feed_data(b"GET / HTTP/1.1\r\n").unwrap();
        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert!(conn.poll_event().is_none()); // Not complete yet

        conn.feed_data(b"Host: example.com\r\n").unwrap();
        assert!(conn.poll_event().is_none()); // Still incomplete

        conn.feed_data(b"\r\n").unwrap();
        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Headers(1));
    }

    #[test]
    fn keep_alive_multiple_requests() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();

        // First request
        conn.feed_data(b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));

        // Drain all events
        while conn.poll_event().is_some() {}

        // Drain headers so they're consumed
        conn.recv_headers(1, |_, _| {}).unwrap();

        // Second request on same connection
        conn.feed_data(b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let ev2 = conn.poll_event().unwrap();
        assert_eq!(ev2, Http1Event::Headers(2));
    }

    #[test]
    fn keep_alive_post_then_get() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();

        // First request: POST with body
        conn.feed_data(
            b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));

        // Drain events
        while conn.poll_event().is_some() {}

        // App reads headers and body
        conn.recv_headers(1, |_, _| {}).unwrap();
        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"abc");
        assert!(fin);

        // Second request: GET (no body)
        conn.feed_data(b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let ev2 = conn.poll_event().unwrap();
        assert_eq!(ev2, Http1Event::Headers(2));

        // body_finished should be false for the new request context
        // (recv_body should WouldBlock if called before Finished, but GET
        // goes straight to Done so body_finished is true again)
        let ev3 = conn.poll_event().unwrap();
        assert_eq!(ev3, Http1Event::Finished(2));
    }

    #[test]
    fn keep_alive_blocks_until_headers_consumed() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();

        // Feed two requests at once (pipelining)
        conn.feed_data(
            b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n\
              GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();

        // Should only see first request
        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));
        let ev2 = conn.poll_event().unwrap();
        assert_eq!(ev2, Http1Event::Finished(1));
        // No more events yet — second request is blocked
        assert!(conn.poll_event().is_none());

        // Consume first request's headers
        conn.recv_headers(1, |_, _| {}).unwrap();

        // Now feed_data (or process) can parse the second request
        conn.feed_data(b"").unwrap(); // Trigger processing
        let ev3 = conn.poll_event().unwrap();
        assert_eq!(ev3, Http1Event::Headers(2));
    }

    #[test]
    fn stream_id_validation() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();

        // Drain events
        while conn.poll_event().is_some() {}

        // Wrong stream_id should fail
        assert_eq!(conn.recv_headers(99, |_, _| {}), Err(Error::InvalidState));
        // Correct stream_id should work
        assert!(conn.recv_headers(1, |_, _| {}).is_ok());
    }

    #[test]
    fn reject_content_length_and_transfer_encoding() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        let result = conn.feed_data(
            b"POST /data HTTP/1.1\r\nHost: example.com\r\n\
              Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn reject_null_byte_in_header_value() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        let data = b"GET / HTTP/1.1\r\nHost: exam\x00ple.com\r\n\r\n".to_vec();
        // The null byte is in the header value
        let result = conn.feed_data(&data);
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn content_length_zero() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(
            b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));
        let ev2 = conn.poll_event().unwrap();
        assert_eq!(ev2, Http1Event::Finished(1));
        // No Data event
        assert!(conn.poll_event().is_none());
    }

    #[test]
    fn feed_data_buffer_overflow() {
        let mut conn = Http1Connection::<64, 64, 64>::new_server();
        let big = [b'X'; 100];
        let result = conn.feed_data(&big);
        assert_eq!(
            result,
            Err(Error::BufferTooSmall { needed: 100 })
        );
    }

    #[test]
    fn header_buf_overflow() {
        let mut conn = Http1Connection::<4096, 32, 1024>::new_server();
        // HDRBUF=32 is too small for the pseudo-headers + Host header
        let result = conn.feed_data(
            b"GET /very-long-path-that-will-overflow HTTP/1.1\r\n\
              Host: example.com\r\n\r\n",
        );
        assert_eq!(result, Err(Error::BufferTooSmall { needed: 41 }));
    }

    #[test]
    fn data_buf_backpressure() {
        let mut conn = Http1Connection::<4096, 1024, 8>::new_server();
        // DATABUF=8, body is 12 bytes
        conn.feed_data(
            b"POST /data HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nhello world!",
        )
        .unwrap();

        // Should get Connected + request + data event (first 8 bytes fill data_buf)
        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));
        let ev2 = conn.poll_event().unwrap();
        assert_eq!(ev2, Http1Event::Data(1));
        // No finished yet — 4 bytes remain but data_buf is full
        assert!(conn.poll_event().is_none());

        // Drain the data_buf
        let mut buf = [0u8; 16];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert!(!fin);

        // Now feed empty to trigger processing of remaining bytes
        conn.feed_data(b"").unwrap();
        let ev3 = conn.poll_event().unwrap();
        assert_eq!(ev3, Http1Event::Data(1));
        let ev4 = conn.poll_event().unwrap();
        assert_eq!(ev4, Http1Event::Finished(1));

        let (n2, fin2) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(n2, 4);
        assert!(fin2);
    }

    #[test]
    fn client_body_until_close() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_client();
        conn.current_stream_id = 1;

        // Response with no Content-Length and no Transfer-Encoding
        conn.feed_data(b"HTTP/1.1 200 OK\r\n\r\nhello").unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));
        let ev2 = conn.poll_event().unwrap();
        assert_eq!(ev2, Http1Event::Data(1));

        // More data arrives
        conn.feed_data(b" world").unwrap();
        let ev3 = conn.poll_event().unwrap();
        assert_eq!(ev3, Http1Event::Data(1));

        // Read all body data so far
        let mut buf = [0u8; 64];
        let (n, _fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
    }

    #[test]
    fn incremental_chunked_body() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();

        // Feed headers
        conn.feed_data(
            b"POST /data HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));

        // Feed chunk size + partial data
        conn.feed_data(b"5\r\nhel").unwrap();
        let ev2 = conn.poll_event().unwrap();
        assert_eq!(ev2, Http1Event::Data(1));

        // Feed rest of chunk + trailer CRLF + terminator
        conn.feed_data(b"lo\r\n0\r\n\r\n").unwrap();

        let mut events = heapless::Vec::<Http1Event, 8>::new();
        while let Some(ev) = conn.poll_event() {
            let _ = events.push(ev);
        }
        assert!(events.contains(&Http1Event::Finished(1)));

        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(fin);
    }

    #[test]
    fn malformed_request_no_spaces() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        let result = conn.feed_data(b"GET\r\n\r\n");
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn malformed_header_no_colon() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        let result = conn.feed_data(b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n");
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn client_server_e2e() {
        let mut client = Http1Connection::<4096, 1024, 1024>::new_client();
        let mut server = Http1Connection::<4096, 1024, 1024>::new_server();

        // Client sends request
        let stream_id = client
            .open_stream(
                &[
                    (b":method", b"GET"),
                    (b":path", b"/"),
                    (b":authority", b"localhost"),
                ],
                true,
            )
            .unwrap();

        // Transfer client → server
        let mut buf = [0u8; 4096];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy: heapless::Vec<u8, 4096> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            server.feed_data(&copy).unwrap();
        }

        // Server gets Connected then request
        assert!(matches!(server.poll_event(), Some(Http1Event::Connected)));
        let ev = server.poll_event().unwrap();
        assert!(matches!(ev, Http1Event::Headers(_)));

        // Drain remaining events
        while server.poll_event().is_some() {}

        // Server reads headers
        let mut got_method = false;
        server
            .recv_headers(1, |name, value| {
                if name == b":method" && value == b"GET" {
                    got_method = true;
                }
            })
            .unwrap();
        assert!(got_method);

        // Server sends response
        server
            .send_headers(
                1,
                &[
                    (b":status", b"200"),
                    (b"content-type", b"text/plain"),
                    (b"content-length", b"12"),
                ],
                false,
            )
            .unwrap();
        server.send_data(1, b"Hello World!", true).unwrap();

        // Transfer server → client
        let mut buf2 = [0u8; 4096];
        while let Some(data) = server.poll_output(&mut buf2) {
            let copy: heapless::Vec<u8, 4096> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            client.feed_data(&copy).unwrap();
        }

        // Client gets headers
        let mut got_headers = false;
        let mut got_data = false;
        let mut got_finished = false;
        while let Some(ev) = client.poll_event() {
            match ev {
                Http1Event::Headers(sid) if sid == stream_id => got_headers = true,
                Http1Event::Data(sid) if sid == stream_id => got_data = true,
                Http1Event::Finished(sid) if sid == stream_id => got_finished = true,
                _ => {}
            }
        }
        assert!(got_headers);
        assert!(got_data);
        assert!(got_finished);

        // Read response headers
        let mut status = heapless::Vec::<u8, 16>::new();
        client
            .recv_headers(stream_id, |name, value| {
                if name == b":status" {
                    let _ = status.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(status.as_slice(), b"200");

        // Read body
        let mut body = [0u8; 64];
        let (n, fin) = client.recv_body(stream_id, &mut body).unwrap();
        assert_eq!(&body[..n], b"Hello World!");
        assert!(fin);
    }

    #[test]
    fn eq_ignore_case_works() {
        assert!(eq_ignore_case(b"content-length", b"Content-Length"));
        assert!(eq_ignore_case(b"HOST", b"host"));
        assert!(!eq_ignore_case(b"foo", b"bar"));
        assert!(!eq_ignore_case(b"foo", b"fooo"));
    }

    #[test]
    fn contains_ignore_case_works() {
        assert!(contains_ignore_case(b"chunked", b"chunked"));
        assert!(contains_ignore_case(b"Chunked", b"chunked"));
        assert!(contains_ignore_case(b"gzip, chunked", b"chunked"));
        assert!(!contains_ignore_case(b"gzip", b"chunked"));
    }

    #[test]
    fn parse_usize_ascii_works() {
        assert_eq!(parse_usize_ascii(b"0"), Some(0));
        assert_eq!(parse_usize_ascii(b"123"), Some(123));
        assert_eq!(parse_usize_ascii(b"65535"), Some(65535));
        assert_eq!(parse_usize_ascii(b"abc"), None);
        assert_eq!(parse_usize_ascii(b""), None);
    }

    #[test]
    fn status_reason_lookup() {
        assert_eq!(status_reason(b"200"), b"OK");
        assert_eq!(status_reason(b"404"), b"Not Found");
        assert_eq!(status_reason(b"500"), b"Internal Server Error");
        assert_eq!(status_reason(b"999"), b""); // Unknown → empty
    }

    // ====== Wire-Format Compatibility Tests ======

    #[test]
    fn wire_curl_get_request() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(
            b"GET /index.html HTTP/1.1\r\n\
              Host: example.com\r\n\
              User-Agent: curl/8.0\r\n\
              Accept: */*\r\n\
              \r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Headers(1));
        let event2 = conn.poll_event().unwrap();
        assert_eq!(event2, Http1Event::Finished(1));

        let mut method = heapless::Vec::<u8, 16>::new();
        let mut path = heapless::Vec::<u8, 64>::new();
        let mut host = heapless::Vec::<u8, 64>::new();
        let mut ua = heapless::Vec::<u8, 64>::new();
        let mut accept = heapless::Vec::<u8, 16>::new();
        conn.recv_headers(1, |name, value| match name {
            b":method" => {
                let _ = method.extend_from_slice(value);
            }
            b":path" => {
                let _ = path.extend_from_slice(value);
            }
            b"Host" => {
                let _ = host.extend_from_slice(value);
            }
            b"User-Agent" => {
                let _ = ua.extend_from_slice(value);
            }
            b"Accept" => {
                let _ = accept.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(method.as_slice(), b"GET");
        assert_eq!(path.as_slice(), b"/index.html");
        assert_eq!(host.as_slice(), b"example.com");
        assert_eq!(ua.as_slice(), b"curl/8.0");
        assert_eq!(accept.as_slice(), b"*/*");
    }

    #[test]
    fn wire_nginx_200_response() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_client();
        conn.current_stream_id = 1;
        conn.feed_data(
            b"HTTP/1.1 200 OK\r\n\
              Server: nginx/1.24\r\n\
              Content-Type: text/html\r\n\
              Content-Length: 13\r\n\
              \r\n\
              <html></html>",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));

        let mut status = heapless::Vec::<u8, 16>::new();
        let mut server = heapless::Vec::<u8, 32>::new();
        let mut ctype = heapless::Vec::<u8, 32>::new();
        conn.recv_headers(1, |name, value| match name {
            b":status" => {
                let _ = status.extend_from_slice(value);
            }
            b"Server" => {
                let _ = server.extend_from_slice(value);
            }
            b"Content-Type" => {
                let _ = ctype.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(status.as_slice(), b"200");
        assert_eq!(server.as_slice(), b"nginx/1.24");
        assert_eq!(ctype.as_slice(), b"text/html");

        // Drain remaining events
        while conn.poll_event().is_some() {}

        let mut body = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut body).unwrap();
        assert_eq!(&body[..n], b"<html></html>");
        assert!(fin);
    }

    #[test]
    fn wire_nginx_301_redirect() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_client();
        conn.current_stream_id = 1;
        conn.feed_data(
            b"HTTP/1.1 301 Moved Permanently\r\n\
              Location: https://example.com/\r\n\
              Content-Length: 0\r\n\
              \r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));

        let mut status = heapless::Vec::<u8, 16>::new();
        let mut location = heapless::Vec::<u8, 64>::new();
        conn.recv_headers(1, |name, value| match name {
            b":status" => {
                let _ = status.extend_from_slice(value);
            }
            b"Location" => {
                let _ = location.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(status.as_slice(), b"301");
        assert_eq!(location.as_slice(), b"https://example.com/");
    }

    #[test]
    fn wire_chunked_response() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_client();
        conn.current_stream_id = 1;
        conn.feed_data(
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n\
              5\r\nhello\r\n0\r\n\r\n",
        )
        .unwrap();

        let mut events = heapless::Vec::<Http1Event, 16>::new();
        while let Some(ev) = conn.poll_event() {
            let _ = events.push(ev);
        }
        assert!(events.contains(&Http1Event::Headers(1)));
        assert!(events.contains(&Http1Event::Finished(1)));

        conn.recv_headers(1, |_, _| {}).unwrap();

        let mut body = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut body).unwrap();
        assert_eq!(&body[..n], b"hello");
        assert!(fin);
    }

    #[test]
    fn wire_connection_close() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));

        let mut connection_hdr = heapless::Vec::<u8, 16>::new();
        conn.recv_headers(1, |name, value| {
            if name == b"Connection" {
                let _ = connection_hdr.extend_from_slice(value);
            }
        })
        .unwrap();
        assert_eq!(connection_hdr.as_slice(), b"close");
    }

    #[test]
    fn wire_post_json() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(
            b"POST /api HTTP/1.1\r\n\
              Host: api.example.com\r\n\
              Content-Type: application/json\r\n\
              Content-Length: 27\r\n\
              \r\n\
              {\"key\":\"value\",\"count\":42}\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));

        let mut method = heapless::Vec::<u8, 16>::new();
        let mut path = heapless::Vec::<u8, 64>::new();
        let mut ctype = heapless::Vec::<u8, 64>::new();
        conn.recv_headers(1, |name, value| match name {
            b":method" => {
                let _ = method.extend_from_slice(value);
            }
            b":path" => {
                let _ = path.extend_from_slice(value);
            }
            b"Content-Type" => {
                let _ = ctype.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(method.as_slice(), b"POST");
        assert_eq!(path.as_slice(), b"/api");
        assert_eq!(ctype.as_slice(), b"application/json");

        // Drain remaining events
        while conn.poll_event().is_some() {}

        let mut body = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut body).unwrap();
        assert_eq!(&body[..n], b"{\"key\":\"value\",\"count\":42}\n");
        assert!(fin);
    }

    #[test]
    fn wire_case_insensitive_headers() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.feed_data(
            b"GET / HTTP/1.1\r\nHOST: example.com\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Headers(1));

        // Parser should accept uppercase HOST header
        let mut host = heapless::Vec::<u8, 64>::new();
        conn.recv_headers(1, |name, value| {
            if eq_ignore_case(name, b"host") {
                let _ = host.extend_from_slice(value);
            }
        })
        .unwrap();
        assert_eq!(host.as_slice(), b"example.com");
    }

    #[test]
    fn wire_server_response_encoding() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        conn.current_stream_id = 1;

        conn.send_headers(
            1,
            &[
                (b":status", b"200"),
                (b"Server", b"milli-http"),
                (b"Content-Length", b"2"),
            ],
            false,
        )
        .unwrap();
        conn.send_data(1, b"OK", true).unwrap();

        let mut out = [0u8; 4096];
        let data = conn.poll_output(&mut out).unwrap();
        assert_eq!(
            data,
            b"HTTP/1.1 200 OK\r\nServer: milli-http\r\nContent-Length: 2\r\n\r\nOK"
        );
    }

    // ====== Timeout + Connection State Tests ======

    #[test]
    fn idle_timeout_between_keepalive() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: None,
        };
        conn.set_timeouts(config, 0);

        // First request arrives
        conn.feed_data_timed(
            b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
            100_000,
        ).unwrap();

        // Drain events + headers
        while conn.poll_event().is_some() {}
        conn.recv_headers(1, |_, _| {}).unwrap();

        // Trigger Idle→Idle transition so connection_start resets
        conn.feed_data_timed(b"", 200_000).unwrap();

        // 2 seconds of inactivity
        conn.handle_timeout(2_200_000);
        assert!(conn.is_closed());

        let mut got_timeout = false;
        while let Some(ev) = conn.poll_event() {
            if ev == Http1Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout);
    }

    #[test]
    fn header_timeout_on_slow_headers() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        let config = crate::http::TimeoutConfig {
            idle_timeout_us: None,
            header_timeout_us: Some(500_000),
        };
        conn.set_timeouts(config, 0);

        // Partial request
        conn.feed_data_timed(b"GET / HTTP/1.1\r\n", 100_000).unwrap();

        // No complete headers after 600ms
        conn.handle_timeout(600_000);
        assert!(conn.is_closed());

        let mut got_timeout = false;
        while let Some(ev) = conn.poll_event() {
            if ev == Http1Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout);
    }

    #[test]
    fn header_timeout_resets_on_keepalive() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        let config = crate::http::TimeoutConfig {
            idle_timeout_us: None,
            header_timeout_us: Some(500_000),
        };
        conn.set_timeouts(config, 0);

        // First request completes at t=100ms
        conn.feed_data_timed(
            b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
            100_000,
        ).unwrap();

        // Drain events + headers
        while conn.poll_event().is_some() {}
        conn.recv_headers(1, |_, _| {}).unwrap();

        // Trigger transition to Idle for keep-alive
        conn.feed_data_timed(b"", 200_000).unwrap();

        // At t=600ms: 400ms since keep-alive Idle started (connection_start reset to 200ms)
        // Header timeout is 500ms, so 200_000 + 500_000 = 700_000 — NOT fired yet
        conn.handle_timeout(600_000);
        assert!(!conn.is_closed());

        // At t=800ms: 600ms since keep-alive Idle — timeout fires
        conn.handle_timeout(800_000);
        assert!(conn.is_closed());
    }

    #[test]
    fn is_closed_and_is_established() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();
        assert!(conn.is_established());
        assert!(!conn.is_closed());

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(100),
            header_timeout_us: None,
        };
        conn.set_timeouts(config, 0);
        conn.handle_timeout(1000);

        assert!(conn.is_closed());
        assert!(!conn.is_established());
    }
}
