#![no_std]

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

extern crate alloc;

pub mod tlv;

type Result<T> = core::result::Result<T, TlvError>;

#[derive(Debug)]
pub enum TlvError {
    TruncatedTlv,
    InvalidLength,
    InvalidTagNumber,
    TooShortBody { expected: usize, found: usize },
    ValExpected { tag_number: usize },
    TagPathError,
}

use core::fmt;

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TlvError::*;

        match self {
            TruncatedTlv => write!(f, "Too short input vector"),
            InvalidLength => writeln!(f, "Invalid length value"),
            InvalidTagNumber => write!(f, "Invalid tag number"),
            TooShortBody { expected, found } => {
                write!(f, "Too short body: expected {expected}, found {found}")
            }
            ValExpected { tag_number } => write!(
                f,
                "Tag number defines primitive TLV, but value is not Value::Val: {tag_number}"
            ),
            TagPathError => write!(f, "Provided 'tag-path' has error"),
        }
    }
}

impl core::error::Error for TlvError {}
