//! HTTP/1.1 connection state machine.
//!
//! Pure codec following the milli-http pattern:
//! `feed_data()` → `poll_output()` → `poll_event()`

use crate::error::Error;
use super::parse;

/// Events produced by the HTTP/1.1 connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1Event {
    /// A complete request has been received (server) or response headers are ready (client).
    /// The `u32` is a pseudo-stream-id for API consistency with H2/H3.
    Request { stream_id: u32 },
    /// Response headers received (client-side).
    Headers(u32),
    /// Body data available.
    Data(u32),
    /// Request/response complete.
    Finished(u32),
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
    /// Current message is done; ready for next (keep-alive).
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
    recv_buf: heapless::Vec<u8, BUF>,
    send_buf: heapless::Vec<u8, BUF>,
    send_offset: usize,
    /// Parsed headers stored as `name\0value\0` pairs.
    header_buf: heapless::Vec<u8, HDRBUF>,
    headers_available: bool,
    /// Buffered body data for the application to read.
    data_buf: heapless::Vec<u8, DATABUF>,
    events: heapless::Deque<Http1Event, 8>,
    /// Pseudo-stream-id (increments per request).
    current_stream_id: u32,
    /// Chunked decoding sub-state.
    chunk_state: ChunkState,
    /// Whether the current message uses keep-alive.
    keep_alive: bool,
    /// Whether end-of-stream has been signalled for the current message.
    body_finished: bool,
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
            recv_buf: heapless::Vec::new(),
            send_buf: heapless::Vec::new(),
            send_offset: 0,
            header_buf: heapless::Vec::new(),
            headers_available: false,
            data_buf: heapless::Vec::new(),
            events: heapless::Deque::new(),
            current_stream_id: 0,
            chunk_state: ChunkState::Size,
            keep_alive: true,
            body_finished: false,
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
        _stream_id: u32,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        match self.role {
            Role::Client => self.encode_request(headers, end_stream),
            Role::Server => self.encode_response(headers, end_stream),
        }
    }

    /// Send body data.
    pub fn send_data(
        &mut self,
        _stream_id: u32,
        data: &[u8],
        _end_stream: bool,
    ) -> Result<usize, Error> {
        self.queue_send(data)?;
        Ok(data.len())
    }

    /// Read received headers via callback.
    ///
    /// Iterates stored headers as `name\0value\0` pairs, calling `emit(name, value)`.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        _stream_id: u32,
        mut emit: F,
    ) -> Result<(), Error> {
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
        _stream_id: u32,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        if self.data_buf.is_empty() {
            if self.body_finished {
                return Ok((0, true));
            }
            return Err(Error::WouldBlock);
        }

        let copy_len = self.data_buf.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&self.data_buf[..copy_len]);

        // Shift remaining data
        let remaining = self.data_buf.len() - copy_len;
        for i in 0..remaining {
            self.data_buf[i] = self.data_buf[copy_len + i];
        }
        self.data_buf.truncate(remaining);

        let fin = self.data_buf.is_empty() && self.body_finished;
        Ok((copy_len, fin))
    }

    /// Open a new stream (client-side: encode request).
    pub fn open_stream(
        &mut self,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u32, Error> {
        self.current_stream_id += 1;
        let sid = self.current_stream_id;
        self.send_headers(sid, headers, end_stream)?;
        Ok(sid)
    }

    // ------------------------------------------------------------------
    // Internal: encoding
    // ------------------------------------------------------------------

    fn encode_request(
        &mut self,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
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

        if end_stream {
            // No body follows
        }

        Ok(())
    }

    fn encode_response(
        &mut self,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
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

        if end_stream {
            // No body follows
        }

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
                    // Reset internal parse state for next request (keep-alive).
                    // Don't clear header_buf/data_buf — the app may not have read them yet.
                    self.chunk_state = ChunkState::Size;
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
        // while mutating self.header_buf.
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
        if self.role == Role::Server {
            self.current_stream_id += 1;
            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Request { stream_id: sid });
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
        let remaining = self.recv_buf.len() - count;
        for i in 0..remaining {
            self.recv_buf[i] = self.recv_buf[count + i];
        }
        self.recv_buf.truncate(remaining);
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
        _ => b"OK",
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

        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Request { stream_id: 1 });

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

        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Request { stream_id: 1 });

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

        assert!(events.contains(&Http1Event::Request { stream_id: 1 }));
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
        conn.feed_data(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        )
        .unwrap();

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

        let expected = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello";
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
        assert!(conn.poll_event().is_none()); // Not complete yet

        conn.feed_data(b"Host: example.com\r\n").unwrap();
        assert!(conn.poll_event().is_none()); // Still incomplete

        conn.feed_data(b"\r\n").unwrap();
        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Request { stream_id: 1 });
    }

    #[test]
    fn keep_alive_multiple_requests() {
        let mut conn = Http1Connection::<4096, 1024, 1024>::new_server();

        // First request
        conn.feed_data(b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let ev = conn.poll_event().unwrap();
        assert_eq!(ev, Http1Event::Request { stream_id: 1 });

        // Drain all events
        while conn.poll_event().is_some() {}

        // Drain headers so they're consumed
        conn.recv_headers(1, |_, _| {}).unwrap();

        // Second request on same connection
        conn.feed_data(b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let ev2 = conn.poll_event().unwrap();
        assert_eq!(ev2, Http1Event::Request { stream_id: 2 });
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

        // Server gets request
        let ev = server.poll_event().unwrap();
        assert!(matches!(ev, Http1Event::Request { .. }));

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
        assert_eq!(status_reason(b"999"), b"OK"); // Unknown → default
    }
}
