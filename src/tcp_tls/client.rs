//! TLS client wrapper.

use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::tls::handshake::TlsConfig;

use super::connection::{TlsConnection, TlsEvent};

/// TLS client.
pub struct TlsClient<C: CryptoProvider, const BUF: usize = 18432> {
    inner: TlsConnection<C, BUF>,
}

impl<C: CryptoProvider, const BUF: usize> TlsClient<C, BUF>
where
    C::Hkdf: Default,
{
    /// Create a new TLS client connection.
    pub fn new(provider: C, config: TlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        Self {
            inner: TlsConnection::new_client(provider, config, secret, random),
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
    pub fn poll_event(&mut self) -> Option<TlsEvent> {
        self.inner.poll_event()
    }

    /// Read decrypted application data.
    pub fn recv_app_data(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.inner.recv_app_data(buf)
    }

    /// Send application data (will be encrypted).
    pub fn send_app_data(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.inner.send_app_data(data)
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
        self.inner.close()
    }
}
