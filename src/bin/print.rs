#![feature(io)]

extern crate tlv_parser;
extern crate "rustc-serialize" as serialize;

use std::io::{Read};
use tlv_parser::*;

use serialize::hex::FromHex;

fn main() {
	let mut input = String::new();
	std::io::stdin().read_to_string( &mut input ).unwrap();

	let mut tlv = Tlv::new();
	tlv.from_vec(&input.from_hex().unwrap());

	println!("{:}", tlv);
}
