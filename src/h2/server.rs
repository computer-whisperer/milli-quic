//! HTTP/2 server wrapper.

use crate::error::Error;
use super::connection::{H2Connection, H2Event};

/// HTTP/2 server.
pub struct H2Server<
    const MAX_STREAMS: usize = 8,
    const BUF: usize = 16384,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    inner: H2Connection<MAX_STREAMS, BUF, HDRBUF, DATABUF>,
}

impl<const MAX_STREAMS: usize, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    H2Server<MAX_STREAMS, BUF, HDRBUF, DATABUF>
{
    /// Create a new HTTP/2 server connection.
    pub fn new() -> Self {
        Self {
            inner: H2Connection::new_server(),
        }
    }

    /// Feed received TCP data.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner.feed_data(data)
    }

    /// Pull outgoing data to send on TCP.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        self.inner.poll_output(buf)
    }

    /// Poll for events.
    pub fn poll_event(&mut self) -> Option<H2Event> {
        self.inner.poll_event()
    }

    /// Read request headers.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.inner.recv_headers(stream_id, emit)
    }

    /// Read request body.
    pub fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        self.inner.recv_body(stream_id, buf)
    }

    /// Send response headers.
    pub fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        let status_str = crate::http::StatusCode(status).to_bytes();
        let mut all_headers: heapless::Vec<(&[u8], &[u8]), 20> = heapless::Vec::new();
        let _ = all_headers.push((b":status", &status_str[..]));
        for &(name, value) in headers {
            let _ = all_headers.push((name, value));
        }
        self.inner.send_headers(stream_id, &all_headers, end_stream)
    }

    /// Send response body.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner.send_data(stream_id, data, end_stream)
    }

    /// Send GOAWAY.
    pub fn send_goaway(&mut self, error_code: u32) -> Result<(), Error> {
        self.inner.send_goaway(error_code)
    }
}

impl<const MAX_STREAMS: usize, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    Default for H2Server<MAX_STREAMS, BUF, HDRBUF, DATABUF>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_creation() {
        let _server = H2Server::<16, 4096>::new();
    }

    #[test]
    fn server_generates_settings() {
        let mut server = H2Server::<16, 4096>::new();
        let mut buf = [0u8; 4096];
        let output = server.poll_output(&mut buf);
        assert!(output.is_some());
    }
}
