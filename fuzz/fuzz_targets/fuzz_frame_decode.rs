#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz QUIC frame decode: should never panic on any input.
    // It may return Ok or Err, but must not panic.
    let _ = milli_quic::frame::decode(data);

    // Also try decoding multiple frames sequentially from the buffer
    let mut pos = 0;
    while pos < data.len() {
        match milli_quic::frame::decode(&data[pos..]) {
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
