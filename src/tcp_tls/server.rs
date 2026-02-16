//! TLS server wrapper.

use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::tls::handshake::ServerTlsConfig;

use super::connection::{TlsConnection, TlsEvent};
use super::io::TlsIoBufs;

/// TLS server — owns both the connection state and I/O buffers.
pub struct TlsServer<C: CryptoProvider, const BUF: usize = 18432> {
    inner: TlsConnection<C>,
    io: TlsIoBufs<BUF>,
}

impl<C: CryptoProvider, const BUF: usize> TlsServer<C, BUF>
where
    C::Hkdf: Default,
{
    /// Create a new TLS server connection.
    pub fn new(provider: C, config: ServerTlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        Self {
            inner: TlsConnection::new_server(provider, config, secret, random),
            io: TlsIoBufs::new(),
        }
    }

    /// Feed received TCP data.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner.feed_data(&mut self.io.as_io(), data)
    }

    /// Pull outgoing data to send on TCP.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        self.inner.poll_output(&mut self.io.as_io(), buf)
    }

    /// Poll for events.
    pub fn poll_event(&mut self) -> Option<TlsEvent> {
        self.inner.poll_event()
    }

    /// Read decrypted application data.
    pub fn recv_app_data(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.inner.recv_app_data(&mut self.io.as_io(), buf)
    }

    /// Send application data (will be encrypted).
    pub fn send_app_data(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.inner.send_app_data(&mut self.io.as_io(), data)
    }

    /// Get negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.inner.alpn()
    }

    /// Whether handshake is complete and data can flow.
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Initiate graceful close.
    pub fn close(&mut self) -> Result<(), Error> {
        self.inner.close(&mut self.io.as_io())
    }
}
