#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz QPACK field section decode: should never panic on any input.
    let decoder = milli_quic::h3::QpackDecoder::new();

    // Decode with a callback that does nothing -- we just want to ensure no panic
    let _ = decoder.decode_field_section(data, |_name, _value| {
        // Deliberately empty: just verify it doesn't panic
    });
});
