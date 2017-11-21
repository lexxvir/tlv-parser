extern crate quickcheck;
extern crate tlv_parser;

use tlv_parser::*;
use quickcheck::{quickcheck, TestResult};

#[test]
fn quickcheck_from_vec() {
    fn prop(xs: Vec<u8>) -> TestResult {
        match tlv::Tlv::from_vec(&xs) {
            Ok(tlv) => {
                let restored_tlv = tlv.to_vec();
                let truncacted_xs = xs.into_iter().take(restored_tlv.len()).collect::<Vec<u8>>();

                TestResult::from_bool(restored_tlv == truncacted_xs)
            }
            Err(_) => TestResult::discard(),
        }
    }

    quickcheck(prop as fn(Vec<u8>) -> TestResult);
}
