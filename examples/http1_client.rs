//! Minimal HTTP/1.1 client example (placeholder).
//!
//! This example will make HTTP/1.1 requests over TCP once the `http1` feature
//! is implemented. For now it demonstrates the intended API shape.
//!
//! Usage (once implemented):
//!   cargo run --example http1_client --features http1
//!
//! Expects an HTTP server on 127.0.0.1:8080.

// TODO: Uncomment when http1 feature is implemented.
//
// use std::io::{Read, Write};
// use std::net::TcpStream;
//
// use milli_http::http1::client::Http1Client;
// use milli_http::http1::Http1Event;
//
// fn main() {
//     println!("milli-http HTTP/1.1 client");
//     println!("=========================");
//
//     let mut stream = TcpStream::connect("127.0.0.1:8080")
//         .expect("failed to connect to 127.0.0.1:8080");
//     println!("[conn] connected to 127.0.0.1:8080");
//
//     stream.set_nonblocking(true).expect("set_nonblocking");
//
//     let mut http1 = Http1Client::new();
//
//     let stream_id = http1.send_request("GET", "/", "127.0.0.1:8080", &[], true)
//         .expect("send_request failed");
//     println!("[http1] sent GET / (stream {stream_id})");
//
//     for _round in 0..100 {
//         // Write pending output.
//         let mut out_buf = [0u8; 8192];
//         while let Some(data) = http1.poll_output(&mut out_buf) {
//             stream.write_all(data).expect("write failed");
//         }
//
//         // Read from TCP.
//         let mut recv_buf = [0u8; 8192];
//         match stream.read(&mut recv_buf) {
//             Ok(0) => { println!("[conn] server disconnected"); break; }
//             Ok(n) => { http1.feed_data(&recv_buf[..n]).ok(); }
//             Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
//             Err(e) => { eprintln!("[conn] read error: {e}"); return; }
//         }
//
//         // Process events.
//         while let Some(event) = http1.poll_event() {
//             match event {
//                 Http1Event::Headers(sid) => {
//                     println!("[http1] response headers:");
//                     http1.recv_headers(sid, |name, value| {
//                         let n = core::str::from_utf8(name).unwrap_or("<bin>");
//                         let v = core::str::from_utf8(value).unwrap_or("<bin>");
//                         println!("[http1]   {n}: {v}");
//                     }).ok();
//                 }
//                 Http1Event::Data(sid) => {
//                     let mut body = [0u8; 8192];
//                     if let Ok((n, _fin)) = http1.recv_body(sid, &mut body) {
//                         let text = core::str::from_utf8(&body[..n]).unwrap_or("<binary>");
//                         println!("[http1] body ({n} bytes):\n{text}");
//                     }
//                 }
//                 Http1Event::Finished(_) => {
//                     println!("[done] request complete");
//                     return;
//                 }
//                 _ => {}
//             }
//         }
//
//         std::thread::sleep(std::time::Duration::from_millis(5));
//     }
// }

fn main() {
    eprintln!("HTTP/1.1 client is not yet implemented.");
    eprintln!("The `http1` feature and src/http1/ module are planned for Phase 8.");
    eprintln!("See the commented-out code in this file for the intended API.");
    std::process::exit(1);
}
