//! Memory budget analysis for an embedded server target:
//!   1 HTTPS/1.1 connection + 4 active H3 connections + 2 H3 handshake slots
//!   Goal: < 100 KB total SRAM

use core::mem::size_of;

use milli_http::crypto::rustcrypto::ChaCha20Provider;

// -- Component types --
use milli_http::connection::Connection;
use milli_http::connection::handshake_pool::{HandshakeContext, HandshakePool};
use milli_http::connection::io::QuicStreamIoBufs;
use milli_http::connection::keys::ConnectionKeys;
use milli_http::h3::server::H3Server;
use milli_http::h3::connection::H3Connection;
use milli_http::https1::Https1Server;
use milli_http::http1::connection::Http1Connection;
use milli_http::http1::io::Http1IoBufs;
use milli_http::tcp_tls::connection::TlsConnection;
use milli_http::tls::handshake::TlsEngine;
use milli_http::buf::Buf;
use milli_http::transport::stream::StreamMap;
use milli_http::transport::recovery::SentPacketTracker;

type C = ChaCha20Provider;

#[test]
fn print_memory_budget() {
    println!();
    println!("============================================================");
    println!("  MEMORY BUDGET ANALYSIS");
    println!("============================================================");
    println!();

    // ---- Core building blocks ----
    println!("--- Core building blocks ---");
    println!("  TlsEngine<C>:               {:>6} bytes", size_of::<TlsEngine<C>>());
    println!("  ConnectionKeys<C>:           {:>6} bytes", size_of::<ConnectionKeys<C>>());
    println!("  StreamMap<8>:                {:>6} bytes", size_of::<StreamMap<8>>());
    println!("  StreamMap<16>:               {:>6} bytes", size_of::<StreamMap<16>>());
    println!("  StreamMap<32>:               {:>6} bytes", size_of::<StreamMap<32>>());
    println!("  SentPacketTracker<32>:       {:>6} bytes", size_of::<SentPacketTracker<32>>());
    println!("  SentPacketTracker<64>:       {:>6} bytes", size_of::<SentPacketTracker<64>>());
    println!("  SentPacketTracker<128>:      {:>6} bytes", size_of::<SentPacketTracker<128>>());
    println!("  Buf<1024>:                   {:>6} bytes", size_of::<Buf<1024>>());
    println!("  Buf<2048>:                   {:>6} bytes", size_of::<Buf<2048>>());
    println!("  Buf<4096>:                   {:>6} bytes", size_of::<Buf<4096>>());
    println!("  Buf<8192>:                   {:>6} bytes", size_of::<Buf<8192>>());
    println!();

    // ---- QUIC Connection (various configs) ----
    println!("--- QUIC Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS> ---");
    println!("  Connection<C, 32, 128, 4>:   {:>6} bytes  (defaults)", size_of::<Connection<C, 32, 128, 4>>());
    println!("  Connection<C, 8, 32, 2>:     {:>6} bytes  (compact)", size_of::<Connection<C, 8, 32, 2>>());
    println!("  Connection<C, 4, 16, 2>:     {:>6} bytes  (tiny)", size_of::<Connection<C, 4, 16, 2>>());
    println!();

    // ---- QuicStreamIoBufs ----
    println!("--- QuicStreamIoBufs<MAX_STREAMS, STREAM_BUF, SEND_QUEUE> ---");
    println!("  IoBufs<32, 1024, 16>:        {:>6} bytes  (defaults)", size_of::<QuicStreamIoBufs<32, 1024, 16>>());
    println!("  IoBufs<8, 512, 8>:           {:>6} bytes  (compact)", size_of::<QuicStreamIoBufs<8, 512, 8>>());
    println!("  IoBufs<4, 256, 4>:           {:>6} bytes  (tiny)", size_of::<QuicStreamIoBufs<4, 256, 4>>());
    println!();

    // ---- HandshakeContext / Pool ----
    println!("--- Handshake ---");
    println!("  HandshakeContext<C, 4096>:   {:>6} bytes  (default)", size_of::<HandshakeContext<C, 4096>>());
    println!("  HandshakeContext<C, 2048>:   {:>6} bytes  (half)", size_of::<HandshakeContext<C, 2048>>());
    println!("  HandshakeContext<C, 1024>:   {:>6} bytes  (quarter)", size_of::<HandshakeContext<C, 1024>>());
    println!("  HandshakePool<C, 2, 4096>:   {:>6} bytes  (2 slots default)", size_of::<HandshakePool<C, 2, 4096>>());
    println!("  HandshakePool<C, 2, 2048>:   {:>6} bytes  (2 slots half)", size_of::<HandshakePool<C, 2, 2048>>());
    println!();

    // ---- H3 Server (various configs) ----
    println!("--- H3Server<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE> ---");
    println!("  H3Server<C> (defaults):      {:>6} bytes", size_of::<H3Server<C>>());
    println!("  H3Server<C, 8, 32, 2, 512, 8>: {:>5} bytes  (compact)", size_of::<H3Server<C, 8, 32, 2, 512, 8>>());
    println!("  H3Server<C, 4, 16, 2, 256, 4>: {:>5} bytes  (tiny)", size_of::<H3Server<C, 4, 16, 2, 256, 4>>());
    println!();

    // ---- HTTPS/1.1 Server ----
    println!("--- HTTPS/1.1 Server ---");
    println!("  Https1Server<C> (defaults):  {:>6} bytes  (BUF=18432)", size_of::<Https1Server<C>>());
    println!("  Https1Server<C, 4096, 1024, 2048>: {:>5} bytes  (compact)", size_of::<Https1Server<C, 4096, 1024, 2048>>());
    println!("  Https1Server<C, 2048, 512, 1024>:  {:>5} bytes  (tiny)", size_of::<Https1Server<C, 2048, 512, 1024>>());
    println!("  Http1Connection (defaults):  {:>6} bytes  (HDRBUF=2048, DATABUF=4096)", size_of::<Http1Connection>());
    println!("  Http1Connection<512, 1024>:  {:>6} bytes", size_of::<Http1Connection<512, 1024>>());
    println!("  Http1IoBufs<8192>:           {:>6} bytes  (default)", size_of::<Http1IoBufs>());
    println!("  Http1IoBufs<2048>:           {:>6} bytes", size_of::<Http1IoBufs<2048>>());
    println!("  TlsConnection<C>:           {:>6} bytes", size_of::<TlsConnection<C>>());
    println!();

    // ---- Target budget: 1 HTTPS/1.1 + 4 H3 + 2 handshake slots ----
    println!("============================================================");
    println!("  TARGET: 1 HTTPS/1.1 + 4 H3 active + 2 handshake slots");
    println!("============================================================");
    println!();

    // Defaults
    let h3_default = size_of::<H3Server<C>>();
    let https1_default = size_of::<Https1Server<C>>();
    let hs_pool_default = size_of::<HandshakePool<C, 2, 4096>>();
    let total_default = https1_default + 4 * h3_default + hs_pool_default;
    println!("  WITH DEFAULTS:");
    println!("    1x Https1Server<C>:        {:>6} bytes", https1_default);
    println!("    4x H3Server<C>:            {:>6} bytes", 4 * h3_default);
    println!("    1x HandshakePool<C,2>:     {:>6} bytes", hs_pool_default);
    println!("    TOTAL:                     {:>6} bytes  ({:.1} KB)", total_default, total_default as f64 / 1024.0);
    println!();

    // Compact config
    let h3_compact = size_of::<H3Server<C, 8, 32, 2, 512, 8>>();
    let https1_compact = size_of::<Https1Server<C, 4096, 1024, 2048>>();
    let hs_pool_compact = size_of::<HandshakePool<C, 2, 2048>>();
    let total_compact = https1_compact + 4 * h3_compact + hs_pool_compact;
    println!("  COMPACT CONFIG:");
    println!("    1x Https1Server<C, 4096, 1024, 2048>: {:>6} bytes", https1_compact);
    println!("    4x H3Server<C, 8, 32, 2, 512, 8>:    {:>6} bytes", 4 * h3_compact);
    println!("    1x HandshakePool<C, 2, 2048>:         {:>6} bytes", hs_pool_compact);
    println!("    TOTAL:                                {:>6} bytes  ({:.1} KB)", total_compact, total_compact as f64 / 1024.0);
    println!();

    // Tiny config
    let h3_tiny = size_of::<H3Server<C, 4, 16, 2, 256, 4>>();
    let https1_tiny = size_of::<Https1Server<C, 2048, 512, 1024>>();
    let hs_pool_tiny = size_of::<HandshakePool<C, 2, 1024>>();
    let total_tiny = https1_tiny + 4 * h3_tiny + hs_pool_tiny;
    println!("  TINY CONFIG:");
    println!("    1x Https1Server<C, 2048, 512, 1024>:  {:>6} bytes", https1_tiny);
    println!("    4x H3Server<C, 4, 16, 2, 256, 4>:     {:>6} bytes", 4 * h3_tiny);
    println!("    1x HandshakePool<C, 2, 1024>:          {:>6} bytes", hs_pool_tiny);
    println!("    TOTAL:                                 {:>6} bytes  ({:.1} KB)", total_tiny, total_tiny as f64 / 1024.0);
    println!();

    println!("  Goal: < 102400 bytes (100 KB)");
    println!("============================================================");
}
