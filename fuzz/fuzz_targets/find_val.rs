#![no_main]

use libfuzzer_sys::fuzz_target;
use tlv_parser::tlv::{Tlv, Value};

fuzz_target!(|data: &[u8]| {
    let tlv = Tlv::new(0x6a, Value::Nothing).unwrap();
    let s = String::from_utf8_lossy(data);
    let _ = tlv.find_val(&s);
});
