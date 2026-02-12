//! HTTP/3 server API.
//!
//! Wraps a QUIC [`Connection`] as an HTTP/3 server capable of receiving
//! requests and sending responses.

use crate::connection::{Connection, Transmit};
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::Instant;

use super::connection::{H3Connection, H3Event};

// ---------------------------------------------------------------------------
// H3Server
// ---------------------------------------------------------------------------

/// An HTTP/3 server built on top of a QUIC connection.
pub struct H3Server<
    C: CryptoProvider,
    const MAX_STREAMS: usize = 32,
    const SENT_PER_SPACE: usize = 128,
    const MAX_CIDS: usize = 4,
    const STREAM_BUF: usize = 1024,
    const SEND_QUEUE: usize = 16,
    const CRYPTO_BUF: usize = 4096,
> {
    inner: H3Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE, CRYPTO_BUF>,
}

impl<C: CryptoProvider, const MAX_STREAMS: usize, const SENT_PER_SPACE: usize, const MAX_CIDS: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize, const CRYPTO_BUF: usize>
    H3Server<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE, CRYPTO_BUF>
where
    C::Hkdf: Default,
{
    /// Wrap a QUIC connection as an HTTP/3 server.
    pub fn new(quic: Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE, CRYPTO_BUF>) -> Self {
        Self {
            inner: H3Connection::new(quic),
        }
    }

    /// Poll for HTTP/3 events.
    ///
    /// Before polling, this processes any pending QUIC events.
    pub fn poll_event(&mut self) -> Option<H3Event> {
        // Process QUIC events first (server is_server=true).
        let _ = self.inner.process_quic_events(true);
        self.inner.poll_event()
    }

    /// Read request headers for a stream (after receiving `H3Event::Headers`).
    ///
    /// Calls `emit(name, value)` for each decoded header.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.inner.recv_headers(stream_id, emit)
    }

    /// Read request body data from a stream.
    pub fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        self.inner.recv_body(stream_id, buf)
    }

    /// Send response headers on a request stream.
    ///
    /// Encodes the `:status` pseudo-header plus any additional headers.
    pub fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
    ) -> Result<(), Error> {
        // Format the status as a short string.
        let status_str = format_status(status);

        // Build the full header list: :status pseudo-header first, then extras.
        let mut all_headers: heapless::Vec<(&[u8], &[u8]), 20> = heapless::Vec::new();
        let _ = all_headers.push((b":status", &status_str[..status_len(status)]));

        for &(name, value) in headers {
            let _ = all_headers.push((name, value));
        }

        self.inner.send_headers(stream_id, &all_headers)
    }

    /// Send response body data.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner.send_data(stream_id, data, end_stream)
    }

    // ------------------------------------------------------------------
    // QUIC connection delegates
    // ------------------------------------------------------------------

    /// Process an incoming UDP datagram.
    pub fn recv(&mut self, datagram: &[u8], now: Instant) -> Result<(), Error> {
        self.inner.quic.recv(datagram, now)
    }

    /// Build the next outgoing UDP datagram.
    pub fn poll_transmit<'a>(
        &mut self,
        buf: &'a mut [u8],
        now: Instant,
    ) -> Option<Transmit<'a>> {
        self.inner.quic.poll_transmit(buf, now)
    }

    /// Get the next timer deadline.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.inner.quic.next_timeout()
    }

    /// Handle a timer expiration.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.inner.quic.handle_timeout(now);
    }
}

// ---------------------------------------------------------------------------
// Status code formatting helpers (no_std friendly)
// ---------------------------------------------------------------------------

/// Format an HTTP status code into a fixed-size byte array.
///
/// Returns an array large enough for any 3-digit status. The actual meaningful
/// bytes span `[0..status_len(status)]`.
fn format_status(status: u16) -> [u8; 3] {
    let d0 = (status / 100) as u8;
    let d1 = ((status / 10) % 10) as u8;
    let d2 = (status % 10) as u8;
    [b'0' + d0, b'0' + d1, b'0' + d2]
}

/// How many bytes does the formatted status occupy? Always 3 for HTTP status codes.
const fn status_len(_status: u16) -> usize {
    3
}
