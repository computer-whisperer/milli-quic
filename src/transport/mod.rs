pub mod flow_control;
pub mod stream;

/// Timestamp in microseconds from an arbitrary epoch.
/// Used for RTT measurement and loss detection timers.
pub type Instant = u64;

/// A UDP-like datagram transport for a single-peer connection (client side).
///
/// The caller is responsible for binding to a port and managing the
/// remote address. This trait just sends and receives datagrams.
pub trait DatagramSend {
    type Error;

    /// Send a datagram. The implementation handles addressing.
    fn send(&mut self, buf: &[u8]) -> impl core::future::Future<Output = Result<(), Self::Error>>;
}

/// Receive datagrams from a single peer.
pub trait DatagramRecv {
    type Error;

    /// Receive a datagram into `buf`. Returns bytes received.
    /// Must not block indefinitely — should return when data is available
    /// or when a timeout occurs.
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> impl core::future::Future<Output = Result<usize, Self::Error>>;
}

/// Clock for loss detection timers and RTT measurement.
pub trait Clock {
    /// Current time in microseconds from an arbitrary epoch.
    fn now(&self) -> Instant;
}

/// Random bytes for connection IDs and nonces.
///
/// On RP2350: implement via hardware TRNG peripheral.
/// Elsewhere: any cryptographic RNG source.
pub trait Rng {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

/// Address type — opaque to the QUIC stack, meaningful to the caller.
pub trait Address: Clone + PartialEq {}

// Blanket impl: anything Clone + PartialEq is an Address.
impl<T: Clone + PartialEq> Address for T {}

/// Server-side datagram transport with addressing.
pub trait ServerTransport {
    type Addr: Address;
    type Error;

    /// Send a datagram to a specific address.
    fn send_to(
        &mut self,
        buf: &[u8],
        addr: &Self::Addr,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;

    /// Receive a datagram, returning the source address.
    fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> impl core::future::Future<Output = Result<(usize, Self::Addr), Self::Error>>;
}
