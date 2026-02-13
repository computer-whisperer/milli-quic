#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz HTTP/3 frame decode: should never panic on any input.
    let _ = milli_http::h3::decode_h3_frame(data);

    // Also try decoding multiple H3 frames sequentially
    let mut pos = 0;
    while pos < data.len() {
        match milli_http::h3::decode_h3_frame(&data[pos..]) {
            Ok((_frame, consumed)) => {
                if consumed == 0 {
                    break; // prevent infinite loop
                }
                pos += consumed;
            }
            Err(_) => break,
        }
    }
});
