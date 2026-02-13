#![no_main]

use libfuzzer_sys::fuzz_target;
use milli_http::tls::messages;

fuzz_target!(|data: &[u8]| {
    // Fuzz all TLS message parsers: should never panic on any input.

    // Try reading a handshake header
    if let Ok((msg_type, body_len)) = messages::read_handshake_header(data) {
        // If header parsed, try to parse the body based on the message type
        if data.len() >= 4 + body_len {
            let body = &data[4..4 + body_len];

            match messages::HandshakeType::from_u8(msg_type) {
                Some(messages::HandshakeType::ClientHello) => {
                    let _ = messages::parse_client_hello(body);
                }
                Some(messages::HandshakeType::ServerHello) => {
                    let _ = messages::parse_server_hello(body);
                }
                Some(messages::HandshakeType::EncryptedExtensions) => {
                    let _ = messages::parse_encrypted_extensions(body);
                }
                Some(messages::HandshakeType::Certificate) => {
                    if let Ok(cert) = messages::parse_certificate(body) {
                        // Try iterating certificate entries
                        for entry in messages::iter_certificate_entries(cert.entries) {
                            let _ = entry;
                        }
                    }
                }
                Some(messages::HandshakeType::CertificateVerify) => {
                    let _ = messages::parse_certificate_verify(body);
                }
                Some(messages::HandshakeType::Finished) => {
                    let _ = messages::parse_finished(body);
                }
                None => {}
            }
        }
    }

    // Also try each parser directly on the raw data
    let _ = messages::parse_client_hello(data);
    let _ = messages::parse_server_hello(data);
    let _ = messages::parse_encrypted_extensions(data);
    let _ = messages::parse_certificate(data);
    let _ = messages::parse_certificate_verify(data);
    let _ = messages::parse_finished(data);
});
