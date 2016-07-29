#![crate_name = "tlv_parser"]
#![feature(question_mark)]

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

#[macro_use]
extern crate error_chain;

extern crate byteorder;
extern crate rustc_serialize;

pub mod tlv;
pub mod errors;

