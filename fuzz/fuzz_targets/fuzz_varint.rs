#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz varint decode: should never panic on any input
    if let Ok((value, consumed)) = milli_quic::varint::decode_varint(data) {
        // If decode succeeded, verify roundtrip
        let mut buf = [0u8; 8];
        if let Ok(written) = milli_quic::varint::encode_varint(value, &mut buf) {
            // Re-decode and check we get the same value
            let (value2, consumed2) = milli_quic::varint::decode_varint(&buf[..written]).unwrap();
            assert_eq!(value, value2);
            assert_eq!(consumed2, written);
            // The consumed bytes from original input should match the expected encoding length
            assert_eq!(consumed, milli_quic::varint::varint_len(value));
        }
    }
});
