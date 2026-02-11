# milli-quic Design Document

A `no_std` QUIC + HTTP/3 implementation for embedded systems.
Both client and server. Integrated TLS 1.3. Compliant browser upgrade path.

## Goals

- **Correct QUIC v1** per RFC 9000 (packets, frames, streams, flow control, loss detection)
- **Integrated TLS 1.3** per RFC 9001 (CRYPTO frames, key schedule, packet protection)
- **Loss detection & congestion control** per RFC 9002 (PTO, NewReno)
- **HTTP/3** per RFC 9114 (request/response over QUIC streams)
- **QPACK** per RFC 9204 (header compression for HTTP/3)
- **Browser-compatible discovery** via Alt-Svc headers over HTTP/1.1 or HTTP/2
- **Both client and server** roles
- **`no_std` without allocator** at the core — works on the most constrained targets
- **Optional `alloc` feature** for dynamic QPACK table and flexible buffers
- **Async-first** on caller-provided UDP send/recv traits, executor-agnostic
- **Zero-copy where possible** — frames and parsed data borrow from caller-provided buffers
- **Stable Rust** — no unstable features
- **Pluggable crypto** — trait-based AEAD, HKDF, key exchange; default impls via RustCrypto

## Non-Goals

- QUIC version 2 (RFC 9369) — future extension
- Connection migration — parsed but not initiated; requires OS network-change detection
- 0-RTT — adds significant complexity and replay attack surface; future extension
- Multipath QUIC — draft spec, not yet RFC
- QUIC datagrams (RFC 9221) — future extension
- HTTP/3 server push — rarely used in practice
- Full priority tree (RFC 9218) — parse but don't schedule by weight
- Acting as a QUIC load balancer or relay
- WebTransport — separate concern layered above

## Why QUIC Instead of HTTP/2 Over TCP

1. **No head-of-line blocking** — a lost UDP packet only blocks its own stream, not the entire connection
2. **Faster handshake** — 1-RTT to establish connection + TLS vs TCP 3-way + TLS handshake
3. **Multiplexing at transport layer** — streams are a first-class primitive, not bolted on
4. **Connection resilience** — connection IDs survive NAT rebinding (matters for embedded devices on flaky networks)
5. **Mandatory encryption** — every QUIC packet is authenticated; no cleartext mode to accidentally deploy
6. **Modern protocol** — browsers are moving toward HTTP/3; implementing QUIC now avoids a dead-end

The tradeoff: QUIC is substantially more complex than HTTP/2 over TCP. But for an embedded device that needs to serve browsers, QUIC is increasingly the expected path.

## Protocol Stack

```
┌──────────────────────────────────────────────────────────┐
│                    User Application                       │
├──────────────────────────────────────────────────────────┤
│                   HTTP/3 (RFC 9114)                       │
│              h3::Client / h3::Server                      │
├──────────────┬───────────────────────────────────────────┤
│   QPACK      │           HTTP/3 Framing                   │
│  (RFC 9204)  │  (HEADERS, DATA, SETTINGS, GOAWAY, etc.)  │
├──────────────┴───────────────────────────────────────────┤
│              QUIC Transport (RFC 9000)                     │
│       Streams · Flow Control · Loss Detection             │
├──────────────────────────────────────────────────────────┤
│          QUIC Packet Protection (RFC 9001)                 │
│    Header Protection · Payload AEAD · Key Schedule        │
├──────────────────────────────────────────────────────────┤
│         TLS 1.3 Handshake (via CRYPTO frames)             │
│    No TLS record layer — messages carried in QUIC         │
├──────────────────────────────────────────────────────────┤
│          UDP Transport (caller-provided trait)             │
└──────────────────────────────────────────────────────────┘
```

Key insight: TLS 1.3 is **not a layer below QUIC**. QUIC carries TLS handshake messages inside CRYPTO frames, and uses TLS-derived keys for its own packet protection. The TLS record layer is not used at all.

## Architecture

### Crate Layout

```
milli-quic/
├── Cargo.toml
└── src/
    ├── lib.rs                    # #![no_std], feature gates, re-exports
    ├── error.rs                  # Unified error types, transport error codes
    │
    ├── crypto/                   # Traits + impls for all cryptographic operations
    │   ├── mod.rs                # CryptoProvider trait, re-exports
    │   ├── aead.rs               # AEAD trait (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
    │   ├── hkdf.rs               # HKDF trait (key derivation)
    │   ├── header_protection.rs  # Header protection (AES-ECB / ChaCha20)
    │   ├── key_schedule.rs       # QUIC-specific key derivation from TLS secrets
    │   └── rustcrypto.rs         # Default impls via RustCrypto crates (feature-gated)
    │
    ├── tls/                      # TLS 1.3 handshake engine
    │   ├── mod.rs                # TlsSession trait, re-exports
    │   ├── handshake.rs          # TLS 1.3 handshake state machine (message-level, no records)
    │   ├── key_exchange.rs       # X25519 / P-256 key exchange
    │   ├── certificate.rs        # Certificate parsing (minimal X.509), verification
    │   ├── extensions.rs         # QUIC transport parameters TLS extension
    │   └── alert.rs              # TLS alert codes
    │
    ├── packet/                   # QUIC packet encode/decode
    │   ├── mod.rs                # Packet enum, header types
    │   ├── long_header.rs        # Initial, Handshake, 0-RTT, Retry packets
    │   ├── short_header.rs       # 1-RTT packets
    │   ├── number.rs             # Packet number encoding/decoding (variable-length)
    │   ├── protection.rs         # Packet protection (encrypt/decrypt using crypto traits)
    │   └── coalesce.rs           # Multiple packets in one UDP datagram
    │
    ├── frame/                    # QUIC frame encode/decode (pure, no I/O)
    │   ├── mod.rs                # Frame enum, codec
    │   ├── ack.rs                # ACK (0x02-0x03)
    │   ├── stream.rs             # STREAM (0x08-0x0f)
    │   ├── crypto.rs             # CRYPTO (0x06)
    │   ├── flow_control.rs       # MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, *_BLOCKED
    │   ├── connection.rs         # CONNECTION_CLOSE (0x1c-0x1d), HANDSHAKE_DONE
    │   ├── path.rs               # PATH_CHALLENGE, PATH_RESPONSE
    │   ├── new_connection_id.rs  # NEW_CONNECTION_ID, RETIRE_CONNECTION_ID
    │   └── misc.rs               # PADDING, PING, NEW_TOKEN, RESET_STREAM, STOP_SENDING
    │
    ├── transport/                # QUIC connection core
    │   ├── mod.rs
    │   ├── connection.rs         # Connection state machine, packet dispatch
    │   ├── stream.rs             # Stream state machine, stream map
    │   ├── flow_control.rs       # Connection + stream flow control
    │   ├── loss.rs               # Loss detection (RFC 9002)
    │   ├── congestion.rs         # Congestion control — NewReno (RFC 9002)
    │   ├── pacing.rs             # Packet pacing
    │   ├── timer.rs              # Timer trait + PTO/idle/handshake timeout management
    │   ├── recovery.rs           # Sent packet tracking, ack processing
    │   └── params.rs             # Transport parameters (initial values, encoding/decoding)
    │
    ├── h3/                       # HTTP/3 (RFC 9114)
    │   ├── mod.rs
    │   ├── frame.rs              # HTTP/3 frame types (DATA, HEADERS, SETTINGS, GOAWAY, etc.)
    │   ├── connection.rs         # HTTP/3 connection (control streams, settings exchange)
    │   ├── client.rs             # HTTP/3 client API
    │   ├── server.rs             # HTTP/3 server API
    │   └── qpack/                # QPACK (RFC 9204)
    │       ├── mod.rs
    │       ├── static_table.rs   # 99-entry static table
    │       ├── dynamic_table.rs  # Fixed-capacity ring buffer; Vec-backed behind alloc
    │       ├── encoder.rs        # Field section encoding
    │       ├── decoder.rs        # Field section decoding
    │       ├── huffman.rs        # Huffman tables (shared with HPACK)
    │       └── instructions.rs   # Encoder/decoder stream instructions
    │
    └── discovery/                # Browser discovery mechanisms
        ├── mod.rs
        └── alt_svc.rs            # Alt-Svc header generation for HTTP/1.1 and HTTP/2 responses
```

### Feature Flags

```toml
[features]
default = ["quic", "h3", "rustcrypto-chacha"]
quic = []                        # QUIC transport only (no HTTP/3)
h3 = ["quic"]                    # HTTP/3 over QUIC
alloc = []                       # Vec-backed dynamic tables, X.509 chain validation
nal = ["dep:embedded-nal-async"]  # Blanket impls from embedded-nal-async traits
rustcrypto-chacha = ["quic"]     # ChaCha20-Poly1305 + AES-128-GCM via RustCrypto
rustcrypto-aes = ["quic"]        # AES-128-GCM only via RustCrypto (for HW-AES targets)
discovery = []                   # Alt-Svc header generation helpers
```

| Combination | Use case |
|---|---|
| `quic` + `rustcrypto-chacha` | Raw QUIC transport. Preferred for RP2350 / Cortex-M without AES HW. |
| `quic` + `rustcrypto-aes` | Raw QUIC for STM32 or other targets with AES hardware. |
| `quic` + `h3` + `rustcrypto-chacha` | Full HTTP/3 stack. Default. |
| `quic` + `h3` + `nal` + `rustcrypto-chacha` | Full stack with embedded-nal-async interop. |
| `quic` + `h3` + `alloc` + `rustcrypto-chacha` | Full stack with dynamic QPACK tables + X.509 chain validation. |
| `quic` + `h3` + `discovery` + `rustcrypto-chacha` | Full stack + Alt-Svc helpers for browser compat. |

## Transport Abstraction

QUIC runs over UDP, not TCP. `embedded-io-async` provides byte-stream traits (Read/Write) which don't model datagrams.

### Why Not `embedded-nal-async` Directly?

`embedded-nal-async` v0.9.0 provides `UnconnectedUdp` which is close to what we need (address on every send/recv). However:

- **Still experimental** — breaking changes planned (GATs → native async fn)
- **Embassy-net UDP impl is incomplete** — not all trait methods implemented
- **Ecosystem fragmentation** — `edge-nal` is a competing alternative with different traits
- **We need less** — QUIC connections don't need the full `UdpStack` factory pattern

**Decision:** Define our own minimal traits, provide blanket impls from `embedded-nal-async` behind a `nal` feature flag. Our traits are stable; theirs can shift underneath.

```rust
/// Timestamp in microseconds from an arbitrary epoch.
/// The connection uses this for RTT measurement and loss detection timers.
pub type Instant = u64;

/// A UDP-like datagram transport for a single-peer connection (client side).
///
/// The caller is responsible for binding to a port and managing the
/// remote address. This trait just sends and receives datagrams.
pub trait DatagramSend {
    type Error;

    /// Send a datagram. The implementation handles addressing.
    async fn send(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
}

pub trait DatagramRecv {
    type Error;

    /// Receive a datagram into `buf`. Returns bytes received.
    /// Must not block indefinitely — should return when data is available
    /// or when a timeout occurs.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Clock for loss detection timers and RTT measurement.
pub trait Clock {
    fn now(&self) -> Instant;
}

/// Random bytes for connection IDs and nonces.
/// On RP2350: implement via hardware TRNG peripheral.
/// Elsewhere: any cryptographic RNG source.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}
```

For a server handling multiple clients, the recv side needs source address information:

```rust
/// Address type — opaque to the QUIC stack, meaningful to the caller.
pub trait Address: Clone + PartialEq {}

/// Server-side datagram transport with addressing.
pub trait ServerTransport {
    type Addr: Address;
    type Error;

    async fn send_to(&mut self, buf: &[u8], addr: &Self::Addr) -> Result<(), Self::Error>;
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, Self::Addr), Self::Error>;
}
```

### `embedded-nal-async` Interop (feature = "nal")

```rust
#[cfg(feature = "nal")]
impl<T> DatagramSend for embedded_nal_async::ConnectedUdp<T> { ... }
#[cfg(feature = "nal")]
impl<T> DatagramRecv for embedded_nal_async::ConnectedUdp<T> { ... }
// UnconnectedUdp → ServerTransport adapter
```

This lets embassy-net users plug in directly while keeping our core trait stable.

## Cryptographic Architecture

### Dependency Map

All crypto primitives come from the RustCrypto ecosystem. Every crate below is `no_std` compatible:

| Crate | Version | Role in QUIC | Hot path? |
|---|---|---|---|
| `chacha20poly1305` | 0.10 | **Primary AEAD** — packet encrypt/decrypt | Yes, every packet |
| `aes-gcm` | 0.10 | Mandatory AEAD (required by spec) | Yes, if negotiated |
| `aes` | 0.8 | AES-ECB for header protection | Yes, every packet |
| `chacha20` | 0.9 | ChaCha20 for header protection (when using ChaCha20-Poly1305) | Yes, if negotiated |
| `hkdf` | 0.12 | Key derivation (HKDF-Extract, HKDF-Expand-Label) | Handshake only |
| `sha2` | 0.10 | Hash for HKDF, handshake transcript | Handshake only |
| `hmac` | 0.12 | HMAC-SHA256 for TLS Finished messages | Handshake only |
| `x25519-dalek` | 2.0 | X25519 key exchange | Once per handshake |
| `p256` | 0.13 | P-256 ECDH (optional, for broader compat) | Once per handshake |
| `x509-cert` + `der` | 0.3-rc | Certificate parsing | Handshake only (needs `alloc`) |

**What we write ourselves:** TLS 1.3 handshake state machine, message construction/parsing, extension encoding, transcript hashing, Finished verification (~5-7K lines). **What we don't write:** any actual cryptographic math.

### Target Hardware: RP2350

The RP2350 (Cortex-M33 @ 150MHz) has:
- **SHA-256 hardware accelerator** — useful for HKDF during handshake
- **Hardware TRNG** — cryptographic-quality random bytes for connection IDs and nonces
- **No AES hardware** — all AES operations are software

This makes **ChaCha20-Poly1305 the preferred AEAD** — it's ~3x faster than AES-GCM in software on cores without AES instructions:

| Cipher | ~cycles/byte (Cortex-M33 SW) | Throughput @ 150MHz | Per-1200B packet |
|---|---|---|---|
| ChaCha20-Poly1305 | 65–85 | ~15 Mbps | ~0.7 ms |
| AES-128-GCM | ~250 | ~5 Mbps | ~2 ms |

Cipher suite negotiation order: `TLS_CHACHA20_POLY1305_SHA256` first, `TLS_AES_128_GCM_SHA256` as mandatory fallback.

The `CryptoProvider` trait allows hardware-backed impls (SHA-256 accelerator, TRNG) to be plugged in alongside software impls. A `Rp2350CryptoProvider` would use hardware SHA-256 via the `digest::Digest` trait and hardware TRNG via `rand_core::RngCore`.

### CryptoProvider Trait

QUIC needs several crypto primitives. Rather than hardcoding implementations, we define a trait bundle:

```rust
pub trait CryptoProvider {
    type Aead: Aead;
    type Hkdf: Hkdf;
    type HeaderProtection: HeaderProtection;

    /// AEAD algorithm for packet protection.
    /// QUIC mandates support for AES-128-GCM (TLS_AES_128_GCM_SHA256).
    fn aead(&self, key: &[u8]) -> Self::Aead;

    /// HKDF for key derivation.
    fn hkdf(&self) -> Self::Hkdf;

    /// Header protection cipher.
    fn header_protection(&self, key: &[u8]) -> Self::HeaderProtection;
}

pub trait Aead {
    const KEY_LEN: usize;
    const NONCE_LEN: usize;
    const TAG_LEN: usize;

    /// Encrypt in place. `buf[..payload_len]` is plaintext.
    /// Returns total length (payload + tag).
    fn seal_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        payload_len: usize,
    ) -> Result<usize, CryptoError>;

    /// Decrypt in place. `buf[..ciphertext_len]` is ciphertext + tag.
    /// Returns plaintext length.
    fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, CryptoError>;
}

pub trait Hkdf {
    fn extract(&self, salt: &[u8], ikm: &[u8], prk: &mut [u8]);
    fn expand(&self, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait HeaderProtection {
    /// Apply/remove header protection. `sample` is 16 bytes from the packet.
    fn mask(&self, sample: &[u8]) -> [u8; 5];
}
```

### QUIC Key Schedule

RFC 9001 defines how TLS 1.3 secrets map to QUIC packet protection keys:

```
TLS Handshake
    │
    ├── client_initial_secret ──► Initial keys (client)
    ├── server_initial_secret ──► Initial keys (server)
    │
    ├── client_handshake_secret ──► Handshake keys (client)
    ├── server_handshake_secret ──► Handshake keys (server)
    │
    ├── client_application_secret ──► 1-RTT keys (client)
    └── server_application_secret ──► 1-RTT keys (server)

Each secret derives:
    secret ──HKDF-Expand──► key (AEAD key)
    secret ──HKDF-Expand──► iv  (AEAD nonce base)
    secret ──HKDF-Expand──► hp  (header protection key)
```

Initial keys are special — derived from the client's Destination Connection ID using a well-known salt, before any TLS exchange. This allows Initial packet protection without TLS state.

```rust
/// Encryption level — determines which keys to use.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Initial,
    Handshake,
    Application,  // 1-RTT
}

/// Keys for one direction (send or recv) at one encryption level.
pub struct DirectionalKeys<A: Aead, H: HeaderProtection> {
    pub aead: A,
    pub header_protection: H,
    pub iv: [u8; 12],           // nonce base, XORed with packet number
}

/// All keys for a connection at a given point in time.
pub struct ConnectionKeys<C: CryptoProvider> {
    pub initial_send: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub initial_recv: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub handshake_send: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub handshake_recv: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub app_send: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
    pub app_recv: Option<DirectionalKeys<C::Aead, C::HeaderProtection>>,
}
```

## TLS 1.3 Integration

### The Problem

QUIC needs TLS 1.3, but not the way TCP uses it:
- **No TLS record layer** — QUIC carries raw TLS handshake messages in CRYPTO frames
- **No TLS content encryption** — QUIC does its own packet protection with TLS-derived keys
- **QUIC controls retransmission** — TLS doesn't retransmit; QUIC handles lost CRYPTO frames
- **QUIC transport parameters** are conveyed as a TLS extension
- TLS **EndOfEarlyData**, **ChangeCipherSpec**, **KeyUpdate**, and **Application Data** records are all explicitly not used

Existing libraries don't fit:
- **embedded-tls** — operates at the TLS record layer; cannot extract raw handshake messages for CRYPTO frames without major surgery
- **rustls** — has a perfect QUIC API (`rustls::quic` module), but requires `std` + `alloc`; the QUIC module uses `Box`, `Vec`, `VecDeque` internally

We must build the TLS 1.3 handshake engine ourselves, using RustCrypto crates for all cryptographic operations.

### TlsSession Trait

We define a trait that QUIC calls to drive the TLS handshake:

```rust
pub trait TlsSession {
    type Error;

    /// Process incoming TLS handshake bytes from a CRYPTO frame.
    /// `level` indicates which encryption level the bytes arrived at.
    fn read_handshake(
        &mut self,
        level: Level,
        data: &[u8],
    ) -> Result<(), Self::Error>;

    /// Write outgoing TLS handshake bytes into `buf`.
    /// Returns `(bytes_written, target_level)` — the encryption level
    /// at which the output should be sent in a CRYPTO frame.
    /// Returns `(0, _)` if there's nothing to send.
    fn write_handshake(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, Level), Self::Error>;

    /// Called after write_handshake produces data, to check if new
    /// keys are available.
    fn derived_keys(&mut self) -> Option<DerivedKeys>;

    /// Is the handshake complete?
    fn is_complete(&self) -> bool;

    /// Get the negotiated ALPN protocol (e.g., b"h3").
    fn alpn(&self) -> Option<&[u8]>;

    /// Get the peer's QUIC transport parameters (decoded from TLS extension).
    fn peer_transport_params(&self) -> Option<&TransportParams>;

    /// Set our QUIC transport parameters (encoded as TLS extension).
    fn set_transport_params(&mut self, params: &TransportParams);
}

pub struct DerivedKeys {
    pub level: Level,
    pub send_secret: [u8; 48],  // max hash output (SHA-384)
    pub recv_secret: [u8; 48],
    pub secret_len: usize,
}
```

### Built-in TLS 1.3 Implementation

We provide a built-in TLS 1.3 handshake engine that implements `TlsSession`. It operates at the handshake message level (no records) and covers the minimal subset needed for QUIC.

#### What We Build (~5-7K lines)

| Component | Est. Lines | What it does |
|---|---|---|
| Handshake state machine | 2000–3000 | Client/server role, message ordering, state transitions |
| Message encode/decode | 1500–2500 | ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished |
| Extensions | 800–1200 | QUIC transport params (0x39), ALPN, SNI, supported_versions, key_share, signature_algorithms |
| Key schedule integration | 300–500 | HKDF-Expand-Label with "quic key"/"quic iv"/"quic hp" labels |
| Certificate verification | 200–400 | Pinned certs initially; full chain validation later (needs `alloc` for x509-cert) |

#### What RustCrypto Provides (0 lines from us)

All actual cryptography — X25519 DH, HKDF-Extract/Expand, SHA-256 transcript hash, HMAC for Finished messages, AEAD for encrypted handshake messages. We just call trait methods.

#### TLS Handshake Messages (QUIC 1-RTT flow)

```
ClientHello                          →  CRYPTO frame in Initial packet
                                        Contains: random, cipher suites, key_share (X25519 pubkey),
                                        supported_versions (TLS 1.3), ALPN ("h3"),
                                        quic_transport_params (0x39)

                    ServerHello      ←  CRYPTO frame in Initial packet
                                        Contains: random, selected cipher suite, key_share

                                        [Handshake keys derived here]

              EncryptedExtensions    ←  CRYPTO frame in Handshake packet
                         Certificate ←  (server cert chain)
                   CertificateVerify ←  (signature over transcript)
                             Finished ←  (HMAC over transcript)

                                        [Application keys derived here]

Finished                             →  CRYPTO frame in Handshake packet

                       HANDSHAKE_DONE ←  QUIC frame in 1-RTT packet (not TLS)
```

#### Supported

- Full 1-RTT handshake (client and server roles)
- Key exchange: X25519 (primary), P-256 (optional, feature-gated)
- Cipher suites: `TLS_CHACHA20_POLY1305_SHA256` (preferred), `TLS_AES_128_GCM_SHA256` (mandatory)
- QUIC transport parameters extension (0x39)
- ALPN negotiation ("h3" for HTTP/3)
- SNI (Server Name Indication)
- Certificate verification: pinned certificates initially, chain validation later

#### Not Supported (initially)

- Session resumption / PSK — future extension
- 0-RTT early data — future extension
- Post-handshake authentication
- Certificate compression
- TLS_AES_256_GCM_SHA384 — rarely needed, easy to add later

This keeps the TLS implementation tractable for embedded while covering the common case. A browser connecting to our server will negotiate ChaCha20-Poly1305 (preferred) or AES-128-GCM (fallback) — both are universally supported.

## QUIC Packet Format

### Long Header (Initial, Handshake, 0-RTT, Retry)

```
Long Header Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2),        // 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
  Type-Specific Bits (4),
  Version (32),                // 0x00000001 for QUIC v1
  DCID Len (8),
  Destination Connection ID (0..160),
  SCID Len (8),
  Source Connection ID (0..160),
  [Type-Specific Payload...]
}
```

### Short Header (1-RTT)

```
Short Header Packet {
  Header Form (1) = 0,
  Fixed Bit (1) = 1,
  Spin Bit (1),
  Reserved (2),
  Key Phase (1),
  Packet Number Length (2),
  Destination Connection ID (..),   // length known from connection state
  Packet Number (8..32),
  Payload (..)
}
```

### Packet Types

```rust
pub enum Packet<'a> {
    Initial(InitialPacket<'a>),
    Handshake(HandshakePacket<'a>),
    ZeroRtt(ZeroRttPacket<'a>),     // parsed but not generated (no 0-RTT support)
    Retry(RetryPacket<'a>),
    Short(ShortPacket<'a>),
}

pub struct InitialPacket<'a> {
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    pub token: &'a [u8],          // address validation token
    pub packet_number: u32,
    pub payload: &'a [u8],        // decrypted frames
}

pub struct ShortPacket<'a> {
    pub dcid: &'a [u8],
    pub spin_bit: bool,
    pub key_phase: bool,
    pub packet_number: u32,
    pub payload: &'a [u8],
}
```

### Packet Number Encoding

QUIC uses variable-length packet number encoding (1-4 bytes) with truncation. The full packet number is reconstructed from the truncated value + largest acknowledged:

```rust
/// Encode packet number, choosing minimal length.
pub fn encode_pn(full_pn: u64, largest_acked: u64, buf: &mut [u8]) -> usize;

/// Decode truncated packet number given the largest acknowledged.
pub fn decode_pn(truncated: u32, pn_len: usize, largest_acked: u64) -> u64;
```

### Packet Protection

Every packet (except Retry and Version Negotiation) is protected:

1. **Payload encryption**: AEAD — authenticates the header, encrypts the payload
2. **Header protection**: XOR mask on parts of the first byte + packet number bytes

```
Sending:
  1. Encode packet with placeholder packet number
  2. AEAD encrypt payload (AAD = header up to and including packet number)
  3. Sample 16 bytes from encrypted payload
  4. Derive header protection mask from sample
  5. XOR mask onto first byte and packet number bytes

Receiving (reverse):
  1. Read header, sample encrypted payload
  2. Derive mask, XOR to recover first byte and packet number length
  3. Read full packet number
  4. AEAD decrypt payload (AAD = unprotected header)
```

## QUIC Frame Types

All frames are encoded within packet payloads. Pure encode/decode, no I/O.

```rust
pub enum Frame<'a> {
    Padding,                                    // 0x00
    Ping,                                       // 0x01
    Ack(AckFrame<'a>),                         // 0x02-0x03
    ResetStream(ResetStreamFrame),             // 0x04
    StopSending(StopSendingFrame),             // 0x05
    Crypto(CryptoFrame<'a>),                   // 0x06
    NewToken(NewTokenFrame<'a>),               // 0x07
    Stream(StreamFrame<'a>),                   // 0x08-0x0f
    MaxData(u64),                              // 0x10
    MaxStreamData(MaxStreamDataFrame),         // 0x11
    MaxStreams(MaxStreamsFrame),                // 0x12-0x13
    DataBlocked(u64),                          // 0x14
    StreamDataBlocked(StreamDataBlockedFrame), // 0x15
    StreamsBlocked(StreamsBlockedFrame),       // 0x16-0x17
    NewConnectionId(NewConnectionIdFrame<'a>), // 0x18
    RetireConnectionId(u64),                   // 0x19
    PathChallenge([u8; 8]),                    // 0x1a
    PathResponse([u8; 8]),                     // 0x1b
    ConnectionClose(ConnectionCloseFrame<'a>), // 0x1c-0x1d
    HandshakeDone,                             // 0x1e
}

pub struct AckFrame<'a> {
    pub largest_ack: u64,
    pub ack_delay: u64,
    pub ranges: &'a [u8],     // variable-length encoded ACK ranges
    pub ecn: Option<EcnCounts>,
}

pub struct StreamFrame<'a> {
    pub stream_id: u64,
    pub offset: u64,
    pub data: &'a [u8],
    pub fin: bool,
}

pub struct CryptoFrame<'a> {
    pub offset: u64,
    pub data: &'a [u8],
}
```

### Variable-Length Integer Encoding

QUIC uses a variable-length integer encoding (1, 2, 4, or 8 bytes) throughout:

```rust
/// Decode a QUIC variable-length integer. Returns (value, bytes_consumed).
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), Error>;

/// Encode a QUIC variable-length integer. Returns bytes written.
pub fn encode_varint(value: u64, buf: &mut [u8]) -> Result<usize, Error>;

/// How many bytes needed to encode this value?
pub fn varint_len(value: u64) -> usize;
```

| 2MSB | Length | Usable Bits | Range |
|------|--------|-------------|-------|
| 00 | 1 byte | 6 | 0–63 |
| 01 | 2 bytes | 14 | 0–16383 |
| 10 | 4 bytes | 30 | 0–1073741823 |
| 11 | 8 bytes | 62 | 0–4611686018427387903 |

## Connection Lifecycle

### Client-Initiated Handshake

```
Client                                    Server
  │                                         │
  │ ── Initial[CRYPTO(ClientHello)] ──────> │  1. Client sends Initial packet
  │                                         │     with TLS ClientHello
  │                                         │
  │ <── Initial[CRYPTO(ServerHello)] ────── │  2. Server responds with Initial
  │ <── Handshake[CRYPTO(EncExts,Cert,      │     + Handshake packets containing
  │              CertVerify,Finished)] ──── │     rest of TLS server handshake
  │                                         │
  │ ── Handshake[CRYPTO(Finished)] ───────> │  3. Client completes TLS handshake
  │ ── 1-RTT[STREAM...] ─────────────────> │     Can immediately send app data
  │                                         │
  │ <── 1-RTT[HANDSHAKE_DONE] ──────────── │  4. Server confirms handshake
  │ <── 1-RTT[STREAM...] ────────────────── │     Both sides in 1-RTT mode
```

### Connection State Machine

```rust
pub enum ConnectionState {
    /// Client: sent Initial, waiting for server response.
    /// Server: received Initial, processing.
    Handshaking,

    /// TLS handshake complete. Can send/recv application data.
    /// Waiting for handshake confirmation (HANDSHAKE_DONE from server,
    /// or handshake ACK from client's perspective).
    Active,

    /// GOAWAY sent or received. Draining existing streams,
    /// not accepting new ones.
    Draining,

    /// CONNECTION_CLOSE sent or received. Lingering briefly
    /// to retransmit the close if needed.
    Closing,

    /// Connection fully terminated.
    Closed,
}
```

## Connection API

```rust
pub struct Connection<C: CryptoProvider, Cfg: ConnectionConfig = DefaultConfig> {
    state: ConnectionState,
    role: Role,
    keys: ConnectionKeys<C>,
    tls: TlsEngine<C>,                                       // built-in TLS 1.3
    streams: StreamMap<{ Cfg::MAX_STREAMS }>,
    loss_detector: LossDetector<{ Cfg::SENT_PACKETS_PER_SPACE }>,
    congestion: CongestionController,
    flow_control: FlowController,
    crypto_buf: [u8; Cfg::CRYPTO_BUF_SIZE],                  // TLS handshake reassembly
    local_cids: heapless::Vec<ConnectionId, { Cfg::MAX_CIDS }>,
    remote_cid: ConnectionId,
    transport_params: TransportParams,
}

pub enum Role { Client, Server }

impl<C, Cfg> Connection<C, Cfg>
where
    C: CryptoProvider,
    Cfg: ConnectionConfig,
{
    /// Decode the Destination Connection ID from a raw datagram.
    /// Static helper for server-side connection routing.
    /// Returns None if the datagram is too short to contain a valid DCID.
    pub fn decode_dcid(datagram: &[u8]) -> Option<&[u8]>;

    /// Create a new client connection.
    pub fn client(
        crypto: C,
        server_name: &str,              // for SNI
        transport_params: TransportParams,
        rng: &mut impl Rng,
    ) -> Self;

    /// Create a new server connection from a received Initial packet.
    pub fn server(
        crypto: C,
        config: ServerConfig,
        initial_packet: &[u8],          // the raw received Initial
        rng: &mut impl Rng,
    ) -> Result<Self, Error>;

    /// Process a received UDP datagram.
    /// May contain multiple coalesced QUIC packets.
    /// Caller should call `poll_transmit` afterwards to send responses.
    pub fn recv(
        &mut self,
        datagram: &[u8],
        now: Instant,
        scratch: &mut [u8],             // decryption scratch space
    ) -> Result<(), Error>;

    /// Get the next datagram to transmit (if any).
    /// Caller sends this over UDP.
    /// Returns `None` when there's nothing to send.
    pub fn poll_transmit<'a>(
        &mut self,
        buf: &'a mut [u8],
        now: Instant,
    ) -> Option<Transmit<'a>>;

    /// Get the next event for the application.
    pub fn poll_event(&mut self) -> Option<Event>;

    /// Get the next timer deadline. Caller must call `handle_timeout`
    /// when this instant is reached.
    pub fn next_timeout(&self) -> Option<Instant>;

    /// A timer expired.
    pub fn handle_timeout(&mut self, now: Instant);

    // ── Stream operations ──

    /// Open a new bidirectional stream. Returns stream ID.
    pub fn open_stream(&mut self) -> Result<u64, Error>;

    /// Open a new unidirectional stream. Returns stream ID.
    pub fn open_uni_stream(&mut self) -> Result<u64, Error>;

    /// Write data to a stream.
    pub fn stream_send(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, Error>;

    /// Read data from a stream.
    pub fn stream_recv(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error>; // (bytes_read, fin)

    /// Reset a stream (send RESET_STREAM).
    pub fn stream_reset(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<(), Error>;

    /// Request peer stop sending on a stream (send STOP_SENDING).
    pub fn stream_stop_sending(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<(), Error>;

    /// Close the connection.
    pub fn close(
        &mut self,
        error_code: u64,
        reason: &[u8],
    );

    pub fn is_closed(&self) -> bool;
}

pub struct Transmit<'a> {
    pub data: &'a [u8],  // the UDP datagram payload
}

pub enum Event {
    /// TLS handshake completed. Connection is ready.
    Connected,
    /// A new stream was opened by the peer.
    StreamOpened(u64),
    /// Data is available to read on a stream.
    StreamReadable(u64),
    /// Space is available to write on a stream (flow control opened up).
    StreamWritable(u64),
    /// Stream was reset by peer.
    StreamReset { stream_id: u64, error_code: u64 },
    /// Peer requested we stop sending.
    StopSending { stream_id: u64, error_code: u64 },
    /// Stream finished (all data received, FIN processed).
    StreamFinished(u64),
    /// Connection is being closed.
    ConnectionClose { error_code: u64, reason: heapless::Vec<u8, 64> },
}
```

### Design Notes

The API is **event-driven, not async**. The connection is a state machine that:
1. Ingests datagrams via `recv()`
2. Produces datagrams via `poll_transmit()`
3. Produces application events via `poll_event()`
4. Requires timer management via `next_timeout()` / `handle_timeout()`

This keeps the QUIC core **executor-agnostic** and avoids internal async state machines. An async wrapper is straightforward:

```rust
// Thin async wrapper (in examples or a separate module)
async fn drive<C, T, const N: usize>(
    conn: &mut Connection<C, N>,
    transport: &mut T,
    clock: &impl Clock,
) where
    C: CryptoProvider,
    T: DatagramSend + DatagramRecv,
{
    loop {
        // Send pending datagrams
        let mut buf = [0u8; 1200];
        while let Some(transmit) = conn.poll_transmit(&mut buf, clock.now()) {
            transport.send(transmit.data).await.ok();
        }

        // Receive or timeout
        // (simplified — real impl would select between recv and timer)
        let n = transport.recv(&mut buf).await.unwrap();
        let mut scratch = [0u8; 1500];
        conn.recv(&buf[..n], clock.now(), &mut scratch).ok();
    }
}
```

## Stream Management

QUIC streams are identified by 62-bit IDs. The low 2 bits encode the stream type:

| Bits | Type |
|------|------|
| 0x00 | Client-initiated, bidirectional |
| 0x01 | Server-initiated, bidirectional |
| 0x02 | Client-initiated, unidirectional |
| 0x03 | Server-initiated, unidirectional |

### Stream State Machine

```
        send STREAM / STREAM_DATA_BLOCKED
                    ┌──────┐
                    │      │
                    v      │
    ┌──────┐    ┌──────┐   │   ┌──────────────┐
    │      │    │      │───┘   │              │
    │ Idle ├───>│ Open ├──────>│ Half-Closed  │
    │      │    │      │ FIN   │   (local)    │
    └──────┘    └──┬───┘       └──────┬───────┘
                   │                  │
                   │ recv FIN         │ recv FIN
                   v                  v
            ┌──────────────┐   ┌──────────┐
            │ Half-Closed  │   │          │
            │  (remote)    ├──>│  Closed  │
            └──────────────┘   └──────────┘
                  FIN
```

(RESET_STREAM and STOP_SENDING can transition to closed from any non-idle state.)

### StreamMap

```rust
pub struct StreamMap<const N: usize> {
    streams: [Option<StreamState>; N],
}

pub struct StreamState {
    pub id: u64,
    pub send: SendState,
    pub recv: RecvState,
}

pub struct SendState {
    pub offset: u64,        // next byte offset to send
    pub acked: u64,         // highest contiguously acked offset
    pub fin_sent: bool,
    pub window: u64,        // peer's MAX_STREAM_DATA
    pub blocked: bool,
}

pub struct RecvState {
    pub offset: u64,        // next expected byte offset
    pub max_data: u64,      // our advertised MAX_STREAM_DATA
    pub fin_received: bool,
    pub readable: bool,     // application hasn't read all available data
}
```

**Buffer strategy for stream data:** The QUIC core does **no internal stream buffering**. `stream_recv()` copies from the decrypted packet payload directly into the caller's buffer. Out-of-order stream data is dropped — QUIC's loss detection will retransmit it. If the application doesn't call `stream_recv()` promptly, the QUIC layer stops sending MAX_STREAM_DATA updates (backpressure via flow control).

This is a deliberate simplification for v1. It trades bandwidth efficiency on lossy links for a dramatically simpler `Connection` (no per-stream reassembly ring buffers, no gap tracking). If we later need reassembly, the `stream_recv()` API doesn't change — we add an internal slab and the caller never knows.

## Flow Control

QUIC has two levels of flow control, both receiver-driven:

### Connection-Level

- **MAX_DATA** frame: receiver advertises maximum total bytes across all streams
- **DATA_BLOCKED** frame: sender signals it's blocked by connection limit

### Stream-Level

- **MAX_STREAM_DATA** frame: receiver advertises max bytes for one stream
- **STREAM_DATA_BLOCKED** frame: sender signals it's blocked on one stream

### Stream Count

- **MAX_STREAMS** frame: limits how many streams the peer can open (separate for bidi/uni)
- **STREAMS_BLOCKED** frame: peer signals it wants to open more streams

```rust
pub struct FlowController {
    // Connection-level send
    send_max_data: u64,        // peer's MAX_DATA limit
    send_data_offset: u64,     // total bytes sent across all streams

    // Connection-level recv
    recv_max_data: u64,        // our advertised MAX_DATA
    recv_data_offset: u64,     // total bytes received across all streams

    // Stream count limits
    max_streams_bidi_local: u64,
    max_streams_uni_local: u64,
    max_streams_bidi_remote: u64,
    max_streams_uni_remote: u64,
}
```

We auto-send MAX_DATA and MAX_STREAM_DATA updates when the receive window drops below 50% of the configured maximum.

## Loss Detection & Congestion Control (RFC 9002)

### Loss Detection

```rust
pub struct LossDetector {
    /// Largest packet number acknowledged in each space.
    largest_acked: [Option<u64>; 3],   // per packet number space

    /// Smoothed RTT estimate.
    smoothed_rtt: u64,  // microseconds
    /// RTT variance.
    rttvar: u64,
    /// Minimum RTT observed.
    min_rtt: u64,
    /// Latest RTT sample.
    latest_rtt: u64,

    /// PTO backoff count.
    pto_count: u32,

    /// Sent packets awaiting acknowledgment.
    sent_packets: SentPacketTracker,

    /// Timer state.
    loss_timer: Option<Instant>,
    pto_timer: Option<Instant>,
}
```

**Packet loss is declared when:**
1. **Time threshold**: A packet sent `max(smoothed_rtt + max(4*rttvar, 1ms), ...)` ago hasn't been acked, and a later packet in the same space has been acked.
2. **Packet number threshold**: A packet's number is more than 3 below the largest acked in its space.

**Probe Timeout (PTO):**
- Fires when no ack received within `smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay`
- Sends 1-2 probe packets (ack-eliciting) to stimulate acks
- Does NOT collapse congestion window (unlike TCP RTO)

### Congestion Control (NewReno)

```rust
pub struct CongestionController {
    /// Congestion window in bytes.
    cwnd: u64,
    /// Slow start threshold.
    ssthresh: u64,
    /// Bytes in flight (sent but not acked).
    bytes_in_flight: u64,
    /// Recovery state.
    recovery_start_time: Option<Instant>,

    /// Constants
    max_datagram_size: u64,    // typically 1200 for QUIC
    initial_window: u64,       // 10 * max_datagram_size
    minimum_window: u64,       // 2 * max_datagram_size
}
```

**Phases:**
1. **Slow start**: cwnd increases by bytes acked, until a loss occurs
2. **Congestion avoidance**: cwnd increases by ~1 MSS per RTT
3. **Recovery**: On loss, ssthresh = cwnd/2, cwnd = ssthresh. One recovery period at a time.

### SentPacketTracker

For `no_std`, we need bounded tracking of sent-but-unacked packets:

```rust
pub struct SentPacketTracker<const N: usize = 128> {
    entries: [Option<SentPacket>; N],
}

pub struct SentPacket {
    pub pn: u64,
    pub level: Level,
    pub time_sent: Instant,
    pub size: u16,
    pub ack_eliciting: bool,
    pub in_flight: bool,
}
```

The const generic `N` bounds the number of in-flight packets. On constrained devices this might be 32-64; on less constrained, 256+.

## HTTP/3 Layer

### HTTP/3 Stream Types

HTTP/3 uses QUIC streams with specific roles:

| Stream | Direction | Purpose |
|--------|-----------|---------|
| Request streams | Bidirectional | One per HTTP request/response pair |
| Control stream | Unidirectional (one per side) | Connection settings, GOAWAY |
| QPACK encoder | Unidirectional (one per side) | Dynamic table updates |
| QPACK decoder | Unidirectional (one per side) | Table acknowledgments |

### HTTP/3 Frame Types

HTTP/3 frames are carried within QUIC streams (not to be confused with QUIC frames):

```rust
pub enum H3Frame<'a> {
    Data(&'a [u8]),                    // 0x00
    Headers(&'a [u8]),                 // 0x01 — QPACK-encoded field section
    CancelPush(u64),                   // 0x03
    Settings(H3Settings),              // 0x04
    PushPromise(PushPromiseFrame<'a>), // 0x05 — parsed but not generated
    GoAway(u64),                       // 0x07
    MaxPushId(u64),                    // 0x0d
}

pub struct H3Settings {
    pub max_field_section_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
}
```

### HTTP/3 Connection

```rust
pub struct H3Connection<C: CryptoProvider, const MAX_STREAMS: usize = 32> {
    quic: Connection<C, MAX_STREAMS>,
    // Control stream IDs (ours and peer's)
    local_control_stream: Option<u64>,
    peer_control_stream: Option<u64>,
    // QPACK state
    qpack_encoder: qpack::Encoder,
    qpack_decoder: qpack::Decoder,
    encoder_stream: Option<u64>,
    decoder_stream: Option<u64>,
    // Settings
    local_settings: H3Settings,
    peer_settings: Option<H3Settings>,
}
```

### HTTP/3 Client API

```rust
impl<C, const N: usize> h3::Client<C, N>
where C: CryptoProvider
{
    /// Wrap a QUIC connection as an HTTP/3 client.
    /// Performs HTTP/3 setup (opens control + QPACK streams, exchanges SETTINGS).
    pub fn new(quic: Connection<C, N>) -> Result<Self, Error>;

    /// Send a request. Returns the stream ID.
    /// Headers are QPACK-encoded and sent as an HTTP/3 HEADERS frame.
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        headers: &[(&str, &str)],
        buf: &mut [u8],
    ) -> Result<u64, Error>;

    /// Send request body data on `stream_id`.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end: bool,
    ) -> Result<usize, Error>;

    /// Poll for events. Drives the QUIC connection internally.
    pub fn poll_event(&mut self) -> Option<H3Event>;

    /// Read response headers for a stream (after H3Event::Headers).
    /// Calls `emit` for each decoded header.
    pub fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: impl FnMut(&str, &str),
    ) -> Result<(), Error>;

    /// Read response body data.
    pub fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error>;

    // Delegates to inner QUIC connection:
    pub fn recv(&mut self, datagram: &[u8], now: Instant, scratch: &mut [u8]) -> Result<(), Error>;
    pub fn poll_transmit<'a>(&mut self, buf: &'a mut [u8], now: Instant) -> Option<Transmit<'a>>;
    pub fn next_timeout(&self) -> Option<Instant>;
    pub fn handle_timeout(&mut self, now: Instant);
}

pub enum H3Event {
    /// Response headers received on a request stream.
    Headers(u64),
    /// Response body data available on a request stream.
    Data(u64),
    /// Server sent GOAWAY.
    GoAway(u64),
}
```

### HTTP/3 Server API

```rust
impl<C, const N: usize> h3::Server<C, N>
where C: CryptoProvider
{
    pub fn new(quic: Connection<C, N>) -> Result<Self, Error>;

    pub fn poll_event(&mut self) -> Option<H3ServerEvent>;

    /// Read request headers (after H3ServerEvent::Request).
    pub fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: impl FnMut(&str, &str),
    ) -> Result<(), Error>;

    /// Read request body.
    pub fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error>;

    /// Send response headers.
    pub fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&str, &str)],
        buf: &mut [u8],
    ) -> Result<(), Error>;

    /// Send response body.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end: bool,
    ) -> Result<usize, Error>;

    // Delegates to inner QUIC connection:
    pub fn recv(&mut self, datagram: &[u8], now: Instant, scratch: &mut [u8]) -> Result<(), Error>;
    pub fn poll_transmit<'a>(&mut self, buf: &'a mut [u8], now: Instant) -> Option<Transmit<'a>>;
    pub fn next_timeout(&self) -> Option<Instant>;
    pub fn handle_timeout(&mut self, now: Instant);
}

pub enum H3ServerEvent {
    /// New request received. Headers available via recv_headers().
    Request(u64),
    /// Request body data available.
    Data(u64),
    /// Client sent GOAWAY.
    GoAway(u64),
}
```

## QPACK

### Static Table

QPACK defines a 99-entry static table (larger than HPACK's 61 entries), covering common HTTP/3 headers:

```rust
pub static STATIC_TABLE: [(& str, &str); 99] = [
    (":authority", ""),           // 0
    (":path", "/"),               // 1
    ("age", "0"),                 // 2
    // ... 96 more entries
];
```

### Encoder / Decoder

```rust
/// Fixed-capacity QPACK encoder.
pub struct Encoder<const TABLE_SIZE: usize = 0> {
    dynamic_table: DynamicTable<TABLE_SIZE>,
}

impl<const TABLE_SIZE: usize> Encoder<TABLE_SIZE> {
    /// Encode a field section (list of headers) into `dst`.
    /// Returns bytes written.
    pub fn encode(
        &mut self,
        headers: &[(&str, &str)],
        dst: &mut [u8],
    ) -> Result<usize, Error>;

    /// Process acknowledgment from decoder stream.
    pub fn on_decoder_instruction(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Get pending encoder stream instructions (for dynamic table updates).
    pub fn pending_instructions(&mut self, dst: &mut [u8]) -> Result<usize, Error>;
}

/// Fixed-capacity QPACK decoder.
pub struct Decoder<const TABLE_SIZE: usize = 0> {
    dynamic_table: DynamicTable<TABLE_SIZE>,
}

impl<const TABLE_SIZE: usize> Decoder<TABLE_SIZE> {
    /// Decode a field section, calling `emit` for each header.
    pub fn decode(
        &mut self,
        src: &[u8],
        emit: impl FnMut(&str, &str) -> Result<(), Error>,
    ) -> Result<(), Error>;

    /// Process instruction from encoder stream.
    pub fn on_encoder_instruction(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Get pending decoder stream instructions (acknowledgments).
    pub fn pending_instructions(&mut self, dst: &mut [u8]) -> Result<usize, Error>;
}
```

**Minimal mode (TABLE_SIZE = 0):** When the dynamic table capacity is zero, QPACK degrades to static table + literal encoding only. No encoder/decoder streams needed. This is the simplest mode for constrained devices and still fully compliant.

## Browser Discovery

For a random web browser to discover and use the QUIC endpoint:

### The Flow

```
Browser                              Embedded Device
  │                                        │
  │ ── TCP connect ──────────────────────> │  1. Initial connection via TCP
  │ ── GET /index.html HTTP/1.1 ────────> │     (HTTP/1.1 or HTTP/2)
  │                                        │
  │ <── HTTP/1.1 200 OK ──────────────── │  2. Response includes Alt-Svc
  │     Alt-Svc: h3=":443"; ma=86400     │     header advertising QUIC
  │     [body...]                         │
  │                                        │
  │ ── UDP: QUIC Initial ───────────────> │  3. Browser opens QUIC connection
  │ <── UDP: QUIC Initial+Handshake ──── │     in parallel on next request
  │ ── UDP: QUIC Handshake ─────────────> │
  │                                        │
  │ ── HTTP/3 request (QUIC 1-RTT) ────> │  4. Subsequent requests use HTTP/3
  │ <── HTTP/3 response ─────────────────│
```

### Alt-Svc Helper

```rust
/// Generate an Alt-Svc header value.
///
/// Example output: `h3=":443"; ma=86400`
pub fn alt_svc_header(port: u16, max_age_secs: u32, buf: &mut [u8]) -> Result<usize, Error>;
```

The server needs to:
1. Listen on both TCP (for HTTP/1.1 or HTTP/2 via milli-http2) and UDP (for QUIC)
2. Include `Alt-Svc: h3=":port"` in TCP HTTP responses
3. Accept QUIC connections with ALPN `h3`
4. Serve the same content over both paths

This means milli-quic works **alongside** milli-http2, not replacing it. The embedded device runs both stacks, using milli-http2 for the initial TCP connection and milli-quic for the upgraded QUIC connection.

## Buffer Strategy

The crate never allocates (without `alloc`). All operations use caller-provided buffers:

| Buffer | Typical Size | Purpose |
|--------|-------------|---------|
| `datagram_buf` | 1500 | UDP datagram send/recv (MTU-sized) |
| `scratch` | 1500 | Packet decryption scratch space |
| `crypto_buf` | 4096 | TLS handshake message assembly |
| `hpack_buf` | 4096 | QPACK encoding scratch (HTTP/3 only) |

QUIC's minimum datagram size is 1200 bytes. Initial packets must be padded to at least 1200 bytes (anti-amplification).

## Error Handling

```rust
/// QUIC transport error codes (RFC 9000 §20).
#[repr(u64)]
pub enum TransportError {
    NoError                 = 0x00,
    InternalError           = 0x01,
    ConnectionRefused       = 0x02,
    FlowControlError        = 0x03,
    StreamLimitError        = 0x04,
    StreamStateError        = 0x05,
    FinalSizeError          = 0x06,
    FrameEncodingError      = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError  = 0x09,
    ProtocolViolation       = 0x0a,
    InvalidToken            = 0x0b,
    ApplicationError        = 0x0c,
    CryptoBufferExceeded    = 0x0d,
    KeyUpdateError          = 0x0e,
    AeadLimitReached        = 0x0f,
    NoViablePath            = 0x10,
    CryptoError(u8),        // 0x0100 + TLS alert code
}

/// HTTP/3 error codes (RFC 9114 §8.1).
#[repr(u64)]
pub enum H3Error {
    NoError                  = 0x0100,
    GeneralProtocolError     = 0x0101,
    InternalError            = 0x0102,
    StreamCreationError      = 0x0103,
    ClosedCriticalStream     = 0x0104,
    FrameUnexpected          = 0x0105,
    FrameError               = 0x0106,
    ExcessiveLoad            = 0x0107,
    IdError                  = 0x0108,
    SettingsError            = 0x0109,
    MissingSettings          = 0x010a,
    RequestRejected          = 0x010b,
    RequestCancelled         = 0x010c,
    RequestIncomplete        = 0x010d,
    MessageError             = 0x010e,
    ConnectError             = 0x010f,
    VersionFallback          = 0x0110,
    QpackDecompressionFailed = 0x0200,
    QpackEncoderStreamError  = 0x0201,
    QpackDecoderStreamError  = 0x0202,
}

/// Top-level crate error.
pub enum Error {
    /// QUIC transport error — connection must close.
    Transport(TransportError),
    /// HTTP/3 error.
    Http3(H3Error),
    /// Cryptographic operation failed.
    Crypto,
    /// TLS handshake error.
    Tls,
    /// Caller-provided buffer too small.
    BufferTooSmall { needed: usize },
    /// No more stream slots available.
    StreamLimitExhausted,
    /// Connection is closed.
    Closed,
    /// Would block — no data available.
    WouldBlock,
}
```

## Implementation Phases

### Phase 1: Foundation
- Cargo.toml with feature flags
- Variable-length integer codec
- Error types and transport error codes
- Transport traits (DatagramSend, DatagramRecv, Clock, Rng)
- CryptoProvider trait definitions

### Phase 2: QUIC Packet Codec
- Long header / short header parsing
- Packet number encoding/decoding
- Initial packet construction (client and server)
- Packet coalescing (multiple packets per datagram)

### Phase 3: QUIC Frame Codec
- All frame types: encode and decode
- Pure functions, no I/O, exhaustively testable
- Property: `decode(encode(frame)) == frame`
- ACK range encoding/decoding

### Phase 4: Crypto Layer
- RustCrypto-backed CryptoProvider impl (AES-128-GCM, HKDF-SHA256)
- Initial key derivation (from DCID)
- Packet protection: encrypt/decrypt
- Header protection: apply/remove

### Phase 5: TLS 1.3 Handshake
- TlsSession trait
- Built-in TLS 1.3 message-level handshake engine
- X25519 key exchange
- Certificate parsing and verification
- QUIC transport parameters extension
- ALPN negotiation

### Phase 6: Connection Core
- Connection state machine (Handshaking → Active → Draining → Closed)
- `recv()` → demux packets → decrypt → process frames
- `poll_transmit()` → build frames → encrypt → emit datagrams
- CRYPTO frame handling ↔ TLS session
- Key schedule progression (Initial → Handshake → Application)

### Phase 7: Streams & Flow Control
- Stream state machine
- StreamMap with bounded capacity
- Connection-level flow control (MAX_DATA / DATA_BLOCKED)
- Stream-level flow control (MAX_STREAM_DATA / STREAM_DATA_BLOCKED)
- Stream count limiting (MAX_STREAMS)
- `stream_send()` / `stream_recv()` API

### Phase 8: Loss Detection & Congestion Control
- RTT estimation (smoothed_rtt, rttvar, min_rtt)
- ACK processing → detect lost packets
- Probe Timeout (PTO) timer
- SentPacketTracker (bounded ring buffer)
- NewReno congestion controller
- Retransmission of lost frames

### Phase 9: HTTP/3 Framing
- HTTP/3 frame codec (DATA, HEADERS, SETTINGS, GOAWAY)
- Control stream setup
- Settings exchange

### Phase 10: QPACK
- 99-entry static table
- Huffman encode/decode
- Integer encode/decode
- Minimal mode (static + literals only, TABLE_SIZE = 0)
- Optional: dynamic table with encoder/decoder streams

### Phase 11: HTTP/3 Client & Server
- `h3::Client` — send_request, recv_response
- `h3::Server` — recv_request, send_response
- Pseudo-header handling (:method, :path, :scheme, :authority, :status)
- GOAWAY handling

### Phase 12: Browser Discovery
- Alt-Svc header generation
- Integration example: milli-http2 (TCP) + milli-quic (UDP) side by side
- ALPN "h3" configuration

### Phase 13: Hardening
- Fuzz testing (packet decode, frame decode, QPACK decode, TLS messages)
- Interop testing against curl + quiche / quinn
- Browser testing (Chrome, Firefox)
- Edge cases: packet coalescing, key phase changes, connection ID rotation
- Amplification attack protection (3x limit on server before address validation)
- Resource exhaustion resistance

## Resolved Decisions

1. **TLS library strategy**: **Build from scratch.** embedded-tls is record-layer-integrated and can't produce raw handshake messages. rustls has a perfect QUIC API but requires std. We build ~5-7K lines of TLS 1.3 handshake state machine, using RustCrypto crates for all cryptographic operations (zero crypto math written by us).

2. **Transport traits**: **Own traits with `nal` feature for interop.** embedded-nal-async is still experimental with breaking changes planned. We define `DatagramSend`/`DatagramRecv`/`ServerTransport`, provide blanket impls from embedded-nal-async behind a feature flag.

3. **Preferred cipher suite**: **ChaCha20-Poly1305** first, AES-128-GCM as mandatory fallback. On RP2350 (no AES hardware), ChaCha20 is ~3x faster in software. Separate feature flags (`rustcrypto-chacha` vs `rustcrypto-aes`) for targets with/without AES hardware.

4. **Certificate verification**: **Pinned certificates first** (compile-time trust anchors, ~200-400 lines). Full X.509 chain validation later behind `alloc` feature (requires `x509-cert` + `der` crates). This is the minimum viable story for embedded — most devices talk to known servers.

5. **Relationship with milli-http2**: **Fully independent crates, composed at the application level.** The embedded device runs both: milli-http2 on TCP for initial browser contact (with Alt-Svc header), milli-quic on UDP for HTTP/3. No cross-crate dependency.

6. **Hardware integration**: The `CryptoProvider` trait enables pluggable hardware crypto. For RP2350: hardware SHA-256 via `digest::Digest`, hardware TRNG via `Rng` trait. Software AEAD regardless (no AES/ChaCha HW on RP2350).

7. **Stream reassembly**: **No internal buffering to start.** Out-of-order stream data is dropped; QUIC retransmits. Flow control provides backpressure for slow consumers. This keeps `Connection` simple and small. If we later need reassembly (for throughput on lossy links), adding a caller-provided slab doesn't require API changes — `stream_recv()` already returns `(bytes_read, fin)` and the caller doesn't know where the bytes came from.

8. **Server connection demux**: **Caller-provided.** We expose `Connection::decode_dcid(datagram) -> Option<&[u8]>` as a static helper. The caller owns the connection table and event loop, routing datagrams to the right `Connection`. This follows the raven-net pattern (see below) — pure logic core returns commands, caller owns I/O. The upside: natural support for multiple logical HTTP/3 endpoints on one server without us imposing a container structure.

9. **`heapless` dependency**: **Yes, depend on `heapless`.** It's the standard no_std collection crate, avoids reinventing `Vec<u8, N>` and `String<N>` everywhere.

10. **Const generic strategy**: **Use a `ConnectionConfig` trait.** 4-5 const generics on `Connection` directly is acceptable. Group them in a trait so call sites stay clean:

    ```rust
    pub trait ConnectionConfig {
        const MAX_STREAMS: usize;           // default 32
        const SENT_PACKETS_PER_SPACE: usize; // default 64
        const MAX_CIDS: usize;              // default 4
        const CRYPTO_BUF_SIZE: usize;       // default 4096
    }

    pub struct DefaultConfig;
    impl ConnectionConfig for DefaultConfig {
        const MAX_STREAMS: usize = 32;
        const SENT_PACKETS_PER_SPACE: usize = 64;
        const MAX_CIDS: usize = 4;
        const CRYPTO_BUF_SIZE: usize = 4096;
    }

    pub struct Connection<C: CryptoProvider, Cfg: ConnectionConfig = DefaultConfig> { ... }
    ```

    If parts later benefit strongly from `alloc`, we gate specific behaviors behind a feature and discuss first.

11. **Retry / address validation**: **Deferred.** Not needed for initial implementation. Can be added later without changing the `Connection` API — it's a server-side concern handled before `Connection::server()` is called.

12. **QUIC-TLS interface boundary**: **Trait from day one.** `TlsSession` trait forces clean separation between the QUIC transport and TLS handshake engine. The built-in `TlsEngine<C>` will be the only implementation initially, but the trait boundary keeps the code honest — no reaching into TLS internals from the connection layer. Also leaves the door open for someone to plug in a different TLS backend if they need features we don't support (PSK, client certs, etc.).

## Server Event Loop Pattern

Following the raven-net pattern from Raven-Firmware: the QUIC core is a pure state machine that ingests datagrams and emits commands. The caller owns all I/O, connection routing, and the event loop itself. This means more boilerplate per server setup, but naturally supports multiple logical HTTP/3 endpoints, mixed protocol stacks, and custom routing.

### Caller Responsibilities

1. **Own the UDP socket** — bind, send, recv
2. **Own the connection table** — map DCID → `Connection`, create/destroy connections
3. **Drive the event loop** — poll for datagrams, poll for timeouts, execute transmits
4. **Compose with other stacks** — milli-http2 on TCP, milli-quic on UDP, same event loop

### What milli-quic Provides

- `Connection::decode_dcid(datagram) -> Option<&[u8]>` — static, pure, for routing
- `Connection::server(crypto, config, initial_packet, rng)` — creates a new connection from an Initial
- `Connection::recv()` / `poll_transmit()` / `poll_event()` / `next_timeout()` / `handle_timeout()` — the state machine interface
- `h3::Server::new(connection)` — wraps a QUIC connection as HTTP/3

### Example Server Event Loop

```rust
#[embassy_executor::task]
async fn quic_server_task(
    udp: &'static mut UdpSocket,
    crypto: ChaCha20Provider,
    server_config: ServerConfig,
    clock: &'static impl Clock,
    rng: &'static mut impl Rng,
) {
    // Connection table: DCID → index
    let mut connections: [Option<H3Server<ChaCha20Provider, DefaultConfig>>; 4] = Default::default();
    let mut rx_buf = [0u8; 1500];
    let mut tx_buf = [0u8; 1500];
    let mut scratch = [0u8; 1500];

    loop {
        // 1. POLL: recv datagram or timeout (whichever comes first)
        let next_timeout = connections.iter()
            .filter_map(|c| c.as_ref()?.quic().next_timeout())
            .min();

        let event = select(
            udp.recv_from(&mut rx_buf),
            maybe_timeout(next_timeout, clock),
        ).await;

        match event {
            // 2. DATAGRAM RECEIVED
            Either::First((len, addr)) => {
                let datagram = &rx_buf[..len];

                // Route by DCID
                if let Some(dcid) = Connection::decode_dcid(datagram) {
                    if let Some(conn) = find_connection_by_dcid(&mut connections, dcid) {
                        conn.quic_mut().recv(datagram, clock.now(), &mut scratch).ok();
                    }
                } else {
                    // New connection (Initial packet)
                    if let Some(slot) = connections.iter_mut().find(|c| c.is_none()) {
                        let quic = Connection::server(
                            crypto.clone(), server_config.clone(),
                            datagram, rng,
                        );
                        if let Ok(quic) = quic {
                            *slot = Some(H3Server::new(quic).unwrap());
                        }
                    }
                }
            }

            // 3. TIMEOUT
            Either::Second(()) => {
                let now = clock.now();
                for conn in connections.iter_mut().flatten() {
                    conn.quic_mut().handle_timeout(now);
                }
            }
        }

        // 4. TRANSMIT: drain all pending datagrams
        for conn in connections.iter_mut().flatten() {
            while let Some(transmit) = conn.quic_mut().poll_transmit(&mut tx_buf, clock.now()) {
                udp.send(transmit.data).await.ok();
            }
        }

        // 5. APPLICATION EVENTS: handle HTTP/3 requests
        for conn in connections.iter_mut().flatten() {
            while let Some(event) = conn.poll_event() {
                match event {
                    H3ServerEvent::Request(stream_id) => {
                        // Read headers, generate response...
                    }
                    H3ServerEvent::Data(stream_id) => { ... }
                    H3ServerEvent::GoAway(_) => { ... }
                }
            }
        }

        // 6. CLEANUP: remove closed connections
        for slot in connections.iter_mut() {
            if slot.as_ref().map_or(false, |c| c.quic().is_closed()) {
                *slot = None;
            }
        }
    }
}
```

This is more boilerplate than an `Endpoint::accept()` API, but it's fully transparent — the caller sees every datagram, every timeout, every event. Customization points are obvious: add rate limiting before `Connection::server()`, add connection limits by checking the table, route different SNI values to different handlers, etc.

## Open Questions

1. **`alloc` boundary for certificates**: The `x509-cert`/`der` crates need `alloc`. For no-alloc targets doing client connections (need to verify server certs), pinned certs work. Server-side cert storage (our own cert + private key) will likely use `&'static [u8]` DER blobs compiled in. Validate this during TLS implementation.

2. **Memory budget**: With `DefaultConfig`, one `Connection` is roughly:
   - StreamMap: 32 streams × ~48 bytes = ~1.5 KB
   - SentPacketTracker: 64 entries × 3 spaces × ~24 bytes = ~4.5 KB
   - ConnectionKeys: ~6 AEAD instances × ~64 bytes = ~0.4 KB
   - TLS handshake state: ~2-3 KB (temporary, freed after handshake)
   - CRYPTO reassembly: 4 KB
   - Flow control, congestion, loss detection: ~0.5 KB
   - **Total: ~10-13 KB per connection**
   - With 4 connections: ~40-52 KB — feasible on RP2350 (520 KB SRAM) but worth validating early.
