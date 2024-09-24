#![no_main]

use libfuzzer_sys::fuzz_target;
use tlv_parser::tlv::Tlv;

fuzz_target!(|data: &[u8]| {
    match Tlv::from_vec(data) {
        Ok(tlv) => {
            let restored_tlv = tlv.to_vec();
            assert!(!restored_tlv.is_empty());
        }
        Err(_) => (),
    }
});
