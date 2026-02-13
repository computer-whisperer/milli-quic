//! Minimal HTTP/1.1 server example (placeholder).
//!
//! This example will serve HTTP/1.1 over a TCP socket once the `http1` feature
//! is implemented. For now it demonstrates the intended API shape.
//!
//! Usage (once implemented):
//!   cargo run --example http1_server --features http1
//!
//! Then from another terminal:
//!   curl http://127.0.0.1:8080/

// TODO: Uncomment when http1 feature is implemented.
//
// use std::io::{Read, Write};
// use std::net::TcpListener;
//
// use milli_http::http1::server::Http1Server;
// use milli_http::http1::Http1Event;
//
// fn main() {
//     println!("milli-http HTTP/1.1 server");
//     println!("=========================");
//
//     let listener = TcpListener::bind("0.0.0.0:8080")
//         .expect("failed to bind TCP on :8080");
//     println!("[init] listening on 0.0.0.0:8080 (TCP)");
//
//     let (mut stream, client_addr) = listener.accept().expect("accept failed");
//     println!("[conn] accepted connection from {client_addr}");
//
//     stream.set_nonblocking(true).expect("set_nonblocking");
//
//     let mut http1 = Http1Server::new();
//
//     let body = b"<!DOCTYPE html>\n<html>\n<head><title>milli-http</title></head>\n<body>\n<h1>Hello from milli-http!</h1>\n<p>You are connected via HTTP/1.1.</p>\n</body>\n</html>\n";
//
//     loop {
//         // Read from TCP.
//         let mut recv_buf = [0u8; 8192];
//         match stream.read(&mut recv_buf) {
//             Ok(0) => {
//                 println!("[conn] client disconnected");
//                 return;
//             }
//             Ok(n) => {
//                 if let Err(e) = http1.feed_data(&recv_buf[..n]) {
//                     eprintln!("[http1] feed_data error: {e}");
//                     return;
//                 }
//             }
//             Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
//             Err(e) => {
//                 eprintln!("[conn] read error: {e}");
//                 return;
//             }
//         }
//
//         // Write pending output.
//         let mut out_buf = [0u8; 8192];
//         while let Some(data) = http1.poll_output(&mut out_buf) {
//             if let Err(e) = stream.write_all(data) {
//                 eprintln!("[conn] write error: {e}");
//                 return;
//             }
//         }
//
//         // Process events.
//         while let Some(event) = http1.poll_event() {
//             match event {
//                 Http1Event::Request { stream_id } => {
//                     println!("[http1] request on stream {stream_id}");
//
//                     http1.recv_headers(stream_id, |name, value| {
//                         let n = core::str::from_utf8(name).unwrap_or("<bin>");
//                         let v = core::str::from_utf8(value).unwrap_or("<bin>");
//                         println!("[http1]   {n}: {v}");
//                     }).ok();
//
//                     let content_length = body.len().to_string();
//                     http1.send_response(stream_id, 200, &[
//                         (b"content-type", b"text/html"),
//                         (b"content-length", content_length.as_bytes()),
//                         (b"server", b"milli-http/0.1"),
//                     ]).ok();
//                     http1.send_body(stream_id, body, true).ok();
//                 }
//                 _ => {}
//             }
//         }
//     }
// }

fn main() {
    eprintln!("HTTP/1.1 server is not yet implemented.");
    eprintln!("The `http1` feature and src/http1/ module are planned for Phase 8.");
    eprintln!("See the commented-out code in this file for the intended API.");
    std::process::exit(1);
}
