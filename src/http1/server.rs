//! HTTP/1.1 server wrapper.

use crate::error::Error;
use super::connection::{Http1Connection, Http1Event};

/// HTTP/1.1 server.
pub struct Http1Server<
    const BUF: usize = 8192,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    inner: Http1Connection<BUF, HDRBUF, DATABUF>,
}

impl<const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    Http1Server<BUF, HDRBUF, DATABUF>
{
    /// Create a new HTTP/1.1 server connection.
    pub fn new() -> Self {
        Self {
            inner: Http1Connection::new_server(),
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
    pub fn poll_event(&mut self) -> Option<Http1Event> {
        self.inner.poll_event()
    }

    /// Read request headers.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u32,
        emit: F,
    ) -> Result<(), Error> {
        self.inner.recv_headers(stream_id, emit)
    }

    /// Read request body.
    pub fn recv_body(
        &mut self,
        stream_id: u32,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        self.inner.recv_body(stream_id, buf)
    }

    /// Send response headers.
    ///
    /// Encodes `HTTP/1.1 {status} {reason}\r\n` + headers + `\r\n`.
    /// If `end_stream` is true, no body will follow.
    pub fn send_response(
        &mut self,
        stream_id: u32,
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

    /// Send response body data.
    pub fn send_body(
        &mut self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner.send_data(stream_id, data, end_stream)
    }
}

impl<const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    Default for Http1Server<BUF, HDRBUF, DATABUF>
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
        let _server = Http1Server::<4096>::new();
    }

    #[test]
    fn server_handles_request() {
        let mut server = Http1Server::<4096, 1024, 1024>::new();
        server
            .feed_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();

        let event = server.poll_event().unwrap();
        assert!(matches!(event, Http1Event::Request { stream_id: 1 }));
    }

    #[test]
    fn server_sends_response() {
        let mut server = Http1Server::<4096, 1024, 1024>::new();
        server
            .feed_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();

        // Drain events
        while server.poll_event().is_some() {}
        server.recv_headers(1, |_, _| {}).unwrap();

        server
            .send_response(1, 200, &[(b"content-length", b"5")], false)
            .unwrap();
        server.send_body(1, b"hello", true).unwrap();

        let mut buf = [0u8; 4096];
        let data = server.poll_output(&mut buf).unwrap();
        let s = core::str::from_utf8(data).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("content-length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }
}
