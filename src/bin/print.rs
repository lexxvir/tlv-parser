
extern crate tlv_parser;
extern crate rustc_serialize;

use std::io::{Read};
use tlv_parser::*;

use rustc_serialize::hex::FromHex;

fn main() {
	let mut input = String::new();
	std::io::stdin().read_to_string( &mut input ).unwrap();

	let tlv = Tlv::from_vec(&input.from_hex().unwrap());

	println!("{:}", tlv);
}
