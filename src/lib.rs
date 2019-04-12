#![no_std]
#![feature(alloc)]

//! A library to parse and emit [BER-TLV](https://en.wikipedia.org/wiki/X.690#BER_encoding) data.
//!
//! #Examples
//!
//! Parse TLV:
//!
//! ```
//! use tlv_parser::tlv::{Tlv, Value};
//!
//! let input: Vec<u8> = vec![0x21, 0x05, 0x22, 0x03, 0x03, 0x01, 0xaa];
//! let tlv = Tlv::from_vec( &input ).unwrap();
//!
//! if let Some(&Value::Val(ref val)) = tlv.find_val("21 / 22 / 03") {
//!     assert_eq!(*val, vec![0xaa]);
//! }
//! ```
//!
//! Emit constructed TLV incapsulated primitive TLV:
//!
//! ```
//! use tlv_parser::tlv::*;
//!
//! let primitive_tlv = Tlv::new(0x01, Value::Nothing).unwrap();
//! let constructed_tlv = Tlv::new(0x21, Value::TlvList(vec![primitive_tlv])).unwrap();
//!
//! assert_eq!(constructed_tlv.to_vec(), vec![0x21, 0x02, 0x01, 0x00]);
//! ```

extern crate core as std;
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate failure;

pub mod tlv;

type Result<T> = core::result::Result<T, TlvError>;

#[derive(Debug, Fail)]
pub enum TlvError {
    #[fail(display = "Too short input vector")]
    TruncatedTlv,

    #[fail(display = "Invalid length value")]
    InvalidLength,

    #[fail(display = "Invalid tag number")]
    InvalidTagNumber,

    #[fail(display = "Too short body: expected {}, found {}", expected, found)]
    TooShortBody { expected: usize, found: usize },

    #[fail(display = "Tag number defines constructed TLV, but value is not Value::TlvList: {}",
           tag_number)]
    TlvListExpected { tag_number: usize },

    #[fail(display = "Tag number defines primitive TLV, but value is not Value::Val: {}",
           tag_number)]
    ValExpected { tag_number: usize },

    #[fail(display = "Provided 'tag-path' have error")]
    TagPathError,
}
