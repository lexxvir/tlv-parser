#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate tlv_parser;

use tlv_parser::tlv::*;

fuzz_target!(|data: &[u8]| {
    let tlv = Tlv::new(0x6a, Value::Nothing);
    let s = String::from_utf8_lossy(data);
    let _ = tlv.find_val(&s);
});
