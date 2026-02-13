#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let first_byte = data[0];
    let is_long = first_byte & 0x80 != 0;

    if is_long {
        // Try parsing as a long header
        let _ = milli_http::packet::parse_long_header(data);

        // Try parsing as an Initial header
        let _ = milli_http::packet::parse_initial_header(data);

        // Try parsing as a Handshake header
        let _ = milli_http::packet::parse_handshake_header(data);
    } else {
        // Try parsing as a short header with various DCID lengths
        for dcid_len in 0..=20 {
            let _ = milli_http::packet::parse_short_header(data, dcid_len);
        }
    }

    // Try coalesced packet parsing
    let mut iter = milli_http::packet::CoalescedPackets::new(data);
    while let Some(result) = iter.next() {
        match result {
            Ok(_pkt_data) => {}
            Err(_) => break,
        }
    }

    // Try DCID extraction with various lengths
    for dcid_len in 0..=20 {
        let _ = milli_http::packet::decode_dcid(data, dcid_len);
    }
});
