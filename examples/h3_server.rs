//! Simple HTTP/3 test server for use with `curl --http3`.
//!
//! Binds a UDP socket on `0.0.0.0:4433`, accepts one QUIC connection,
//! completes the TLS 1.3 handshake, and responds to every HTTP/3 request
//! with a plain-text "Hello, HTTP/3!\n" body.
//!
//! Usage:
//!   cargo run --example h3_server --features h3,rustcrypto-chacha
//!
//! Then from another terminal:
//!   curl -k --http3 https://127.0.0.1:4433/

use std::io::Write;
use std::net::UdpSocket;
use std::time;

use milli_quic::connection::{Connection, HandshakePool};
use milli_quic::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_quic::crypto::rustcrypto::Aes128GcmProvider;
use milli_quic::h3::server::H3Server;
use milli_quic::h3::H3Event;
use milli_quic::tls::handshake::ServerTlsConfig;
use milli_quic::tls::transport_params::TransportParams;
use milli_quic::Rng;

// ---------------------------------------------------------------------------
// RNG wrapper around the `rand` crate
// ---------------------------------------------------------------------------

struct StdRng(rand::rngs::ThreadRng);

impl StdRng {
    fn new() -> Self {
        Self(rand::rng())
    }
}

impl Rng for StdRng {
    fn fill(&mut self, buf: &mut [u8]) {
        use rand::RngCore;
        self.0.fill_bytes(buf);
    }
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

/// Convert a `std::time::Instant` to the library's microsecond-based `Instant`.
fn to_micros(epoch: time::Instant, now: time::Instant) -> u64 {
    now.duration_since(epoch).as_micros() as u64
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("milli-quic HTTP/3 test server");
    println!("=============================");

    // -- Generate a self-signed Ed25519 certificate --
    let seed: [u8; 32] = [0x42u8; 32];
    let pk = ed25519_public_key_from_seed(&seed);
    let mut cert_buf = [0u8; 512];
    let cert_len = build_ed25519_cert_der(&pk, &mut cert_buf)
        .expect("failed to build certificate DER");
    // Leak into 'static references required by ServerTlsConfig.
    let cert_der: &'static [u8] = Box::leak(cert_buf[..cert_len].to_vec().into_boxed_slice());
    let private_key_der: &'static [u8] = Box::leak(Box::new(seed));

    println!("[init] generated self-signed Ed25519 certificate ({cert_len} bytes)");

    // -- Bind UDP socket --
    let socket = UdpSocket::bind("0.0.0.0:4433").expect("failed to bind UDP socket on :4433");
    println!("[init] listening on 0.0.0.0:4433 (UDP)");

    // Use a short read timeout so the main loop stays responsive.
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(5)))
        .expect("set_read_timeout");

    let epoch = time::Instant::now();

    // -- Wait for the first UDP datagram (QUIC Initial from client) --
    let mut recv_buf = [0u8; 65535];
    let (first_len, client_addr) = loop {
        match socket.recv_from(&mut recv_buf) {
            Ok(pair) => break pair,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => panic!("recv_from error: {e}"),
        }
    };

    println!("[conn] received first datagram ({first_len} bytes) from {client_addr}");

    // -- Create the server connection --
    let tp = TransportParams::default_params();
    let tls_config = ServerTlsConfig {
        cert_der,
        private_key_der,
        alpn_protocols: &[b"h3"],
        transport_params: tp.clone(),
    };

    let mut rng = StdRng::new();
    let mut pool = HandshakePool::<Aes128GcmProvider, 4>::new();
    let conn = Connection::<Aes128GcmProvider>::server(Aes128GcmProvider, tls_config, tp, &mut rng, &mut pool)
        .expect("failed to create server Connection");

    let mut h3 = H3Server::new(conn);

    // Feed the first datagram.
    let now = to_micros(epoch, time::Instant::now());
    if let Err(e) = h3.recv(&recv_buf[..first_len], now, &mut pool) {
        eprintln!("[conn] error processing first datagram: {e}");
    }

    // -- Main event loop --
    // Open packet log file for debugging
    let mut pkt_log = std::fs::File::create("/tmp/quic_packets.log").expect("create packet log");

    println!("[loop] entering main loop");

    loop {
        let now = to_micros(epoch, time::Instant::now());

        // 1. Send any outgoing datagrams.
        let mut tx_buf = [0u8; 65535];
        loop {
            match h3.poll_transmit(&mut tx_buf, now, &mut pool) {
                Some(tx) => {
                    println!("[send] sending {} bytes to {client_addr}", tx.data.len());
                    let _ = writeln!(pkt_log, "SEND {} {}", tx.data.len(),
                        tx.data.iter().map(|b| format!("{b:02x}")).collect::<String>());
                    let _ = pkt_log.flush();
                    if let Err(e) = socket.send_to(tx.data, client_addr) {
                        eprintln!("[send] error: {e}");
                    }
                }
                None => break,
            }
        }

        // 2. Handle timeouts.
        if let Some(deadline) = h3.next_timeout() {
            let now = to_micros(epoch, time::Instant::now());
            if now >= deadline {
                h3.handle_timeout(now);
            }
        }

        // 3. Receive incoming datagrams.
        match socket.recv_from(&mut recv_buf) {
            Ok((len, addr)) => {
                if addr == client_addr {
                    println!("[recv] received {len} bytes from {addr} (first_byte=0x{:02x})", recv_buf[0]);
                    let _ = writeln!(pkt_log, "RECV {} {}", len,
                        recv_buf[..len].iter().map(|b| format!("{b:02x}")).collect::<String>());
                    let _ = pkt_log.flush();
                    let now = to_micros(epoch, time::Instant::now());
                    match h3.recv(&recv_buf[..len], now, &mut pool) {
                        Ok(()) => {},
                        Err(e) => eprintln!("[recv] error: {e}"),
                    }
                } else {
                    eprintln!("[recv] ignoring datagram from {addr} (expected {client_addr})");
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("[recv] error: {e}");
            }
        }

        // 4. Process H3 events.
        while let Some(event) = h3.poll_event() {
            match event {
                H3Event::Connected => {
                    println!("[h3] connection established");
                }

                H3Event::Headers(stream_id) => {
                    println!("[h3] request headers on stream {stream_id}");

                    // Print the request headers.
                    h3.recv_headers(stream_id, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<binary>");
                        let v = core::str::from_utf8(value).unwrap_or("<binary>");
                        println!("[h3]   {n}: {v}");
                    })
                    .ok();

                    // Drain any body (we don't use it).
                    let mut body_buf = [0u8; 4096];
                    loop {
                        match h3.recv_body(stream_id, &mut body_buf) {
                            Ok((_n, true)) => break,
                            Ok((_n, false)) => continue,
                            Err(_) => break,
                        }
                    }

                    // Send a simple response.
                    let body = b"Hello, HTTP/3!\n";
                    let content_length = body.len().to_string();
                    let extra_headers: &[(&[u8], &[u8])] = &[
                        (b"content-type", b"text/plain"),
                        (b"content-length", content_length.as_bytes()),
                        (b"server", b"milli-quic/0.1"),
                    ];

                    if let Err(e) = h3.send_response(stream_id, 200, extra_headers) {
                        eprintln!("[h3] error sending response headers: {e}");
                        continue;
                    }
                    println!("[h3] sent 200 response on stream {stream_id}");

                    match h3.send_body(stream_id, body, true) {
                        Ok(n) => println!("[h3] sent {n} body bytes (fin) on stream {stream_id}"),
                        Err(e) => eprintln!("[h3] error sending body: {e}"),
                    }
                }

                H3Event::Data(stream_id) => {
                    // Drain additional body data if it arrives as a separate event.
                    let mut body_buf = [0u8; 4096];
                    loop {
                        match h3.recv_body(stream_id, &mut body_buf) {
                            Ok((_n, true)) => break,
                            Ok((_n, false)) => continue,
                            Err(_) => break,
                        }
                    }
                }

                H3Event::Finished(stream_id) => {
                    println!("[h3] stream {stream_id} finished");
                }

                H3Event::GoAway(id) => {
                    println!("[h3] received GOAWAY (id={id})");
                    return;
                }
            }
        }
    }
}
