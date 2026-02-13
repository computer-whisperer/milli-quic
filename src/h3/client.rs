//! HTTP/3 client API.
//!
//! Wraps a QUIC [`Connection`] as an HTTP/3 client capable of sending requests
//! and receiving responses.

use crate::connection::{Connection, HandshakePoolAccess, Transmit};
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::Instant;

use super::connection::{H3Connection, H3Event};

// ---------------------------------------------------------------------------
// H3Client
// ---------------------------------------------------------------------------

/// An HTTP/3 client built on top of a QUIC connection.
pub struct H3Client<
    C: CryptoProvider,
    const MAX_STREAMS: usize = 32,
    const SENT_PER_SPACE: usize = 128,
    const MAX_CIDS: usize = 4,
    const STREAM_BUF: usize = 1024,
    const SEND_QUEUE: usize = 16,
> {
    inner: H3Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE>,
}

impl<C: CryptoProvider, const MAX_STREAMS: usize, const SENT_PER_SPACE: usize, const MAX_CIDS: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize>
    H3Client<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE>
where
    C::Hkdf: Default,
{
    /// Wrap a QUIC connection as an HTTP/3 client.
    pub fn new(quic: Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE>) -> Self {
        Self {
            inner: H3Connection::new(quic),
        }
    }

    /// Send an HTTP request. Returns the request stream ID.
    ///
    /// Encodes pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`)
    /// plus any additional headers using QPACK, wraps in a HEADERS frame, and
    /// sends on a new bidirectional stream.
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        // Open a new bidirectional request stream.
        let stream_id = self.inner.quic.open_stream()?;

        // Build the full header list: pseudo-headers first, then regular headers.
        // We need to combine them into a single slice for QPACK encoding.
        // Max 16 extra headers + 4 pseudo-headers.
        let mut all_headers: heapless::Vec<(&[u8], &[u8]), 20> = heapless::Vec::new();
        let _ = all_headers.push((b":method", method.as_bytes()));
        let _ = all_headers.push((b":scheme", b"https"));
        let _ = all_headers.push((b":authority", authority.as_bytes()));
        let _ = all_headers.push((b":path", path.as_bytes()));

        for &(name, value) in headers {
            let _ = all_headers.push((name, value));
        }

        self.inner.send_headers(stream_id, &all_headers, end_stream)?;

        // Track this as a request stream.
        let _ = self
            .inner
            .request_streams
            .push(super::connection::RequestStreamState::new(stream_id));

        Ok(stream_id)
    }

    /// Send request body data on a stream.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner.send_data(stream_id, data, end_stream)
    }

    /// Poll for HTTP/3 events.
    ///
    /// Before polling, this processes any pending QUIC events.
    pub fn poll_event(&mut self) -> Option<H3Event> {
        // Process QUIC events first (client is_server=false).
        let _ = self.inner.process_quic_events(false);
        self.inner.poll_event()
    }

    /// Read response headers for a stream (after receiving `H3Event::Headers`).
    ///
    /// Calls `emit(name, value)` for each decoded header.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.inner.recv_headers(stream_id, emit)
    }

    /// Read response body data from a stream.
    pub fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        self.inner.recv_body(stream_id, buf)
    }

    // ------------------------------------------------------------------
    // QUIC connection delegates
    // ------------------------------------------------------------------

    /// Process an incoming UDP datagram.
    pub fn recv<const CRYPTO_BUF: usize>(&mut self, datagram: &[u8], now: Instant, pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>) -> Result<(), Error> {
        self.inner.quic.recv(datagram, now, pool)
    }

    /// Build the next outgoing UDP datagram.
    pub fn poll_transmit<'a, const CRYPTO_BUF: usize>(
        &mut self,
        buf: &'a mut [u8],
        now: Instant,
        pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Option<Transmit<'a>> {
        self.inner.quic.poll_transmit(buf, now, pool)
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
