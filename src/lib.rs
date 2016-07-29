//! A library to parse and emit [BER-TLV](https://en.wikipedia.org/wiki/X.690#BER_encoding) data.
//!

#![crate_name = "tlv_parser"]
#![feature(question_mark)]

#[macro_use]
extern crate error_chain;

extern crate byteorder;
extern crate rustc_serialize;

pub mod tlv;
pub mod errors;

