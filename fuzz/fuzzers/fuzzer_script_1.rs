#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate tlv_parser;

use tlv_parser::*;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    match tlv::Tlv::from_vec(data) {
        Ok(tlv) => {
            let restored_tlv = tlv.to_vec();
            assert!(!restored_tlv.is_empty());
        },
        Err(_) => (),
    }
});

