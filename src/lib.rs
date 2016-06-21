#![crate_name = "tlv_parser"]
#![feature(question_mark)]

#[macro_use]
extern crate error_chain;

extern crate byteorder;
extern crate rustc_serialize;

pub mod tlv;
pub mod errors;

