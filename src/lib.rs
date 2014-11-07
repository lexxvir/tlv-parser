#![crate_name = "tlv_parser"]
#![allow(dead_code, unused_variables)]

extern crate core;

use core::iter::{range_step};

#[deriving(Show)]
pub enum Value {
	TlvList( Vec<Tlv> ),
	Val( Vec<u8> ),
	Nothing
}

#[deriving(Show)]
pub struct Tlv {
	// FIXME: deny explicit assignment
	pub tag: Vec<u8>,
	pub val: Value,
}

impl Tlv {
	/// Creates blank Tlv object
	pub fn new() -> Tlv {
		Tlv { tag: vec![], val: Val( vec![] ) }
	}

	/// Returns size of TLV-string in bytes
	pub fn len( &self ) -> uint {
		let val_len = self.val.len();
		self.tag.len() + self.val.encode_len().len() + val_len
	}

	/// Returns encoded array of bytes
	pub fn to_vec( &self ) -> Vec<u8>  {
		let mut out: Vec<u8> = vec![];

		out = out.add( &self.tag );
		out = out.add( &self.val.encode_len() );

		// FXIME: remove intermediate object
		let v: Vec<u8> = match self.val {
				TlvList( ref list ) => list.iter().fold(vec![], |sum, ref x| sum.add(&x.to_vec())),
				Val( ref v ) => v.clone(),
				Nothing => vec![],
			};

		out = out.add( &v );
		return out;
	}

	/// Initializes Tlv object from Vec<u8>
	pub fn from_vec( &mut self, vec: &Vec<u8> ) {
	}
}

impl Value {
	/// Returns size of value in bytes
	fn len( &self ) -> uint {
		match *self {
			TlvList(ref list) => list.iter().fold(0, |sum, ref x| sum + x.len()),
			Val(ref v) => v.len(),
			Nothing => 0,
		}
	}

	/// Returns bytes array that represents encoded-len
	/// Note: implements only definite form
	fn encode_len( &self ) -> Vec<u8> {
		let len = self.len();
		if len <= 0x7f {
			return vec![len as u8];
		}

		let mut out: Vec<u8> = vec![];

		for x in range_step(0u, std::uint::BITS, 8u) { // FIXME: use variable-depended size
			let b: u8 = (len >> x) as u8;
			if b == 0 {
				break;
			}
			out.insert( 0, b );
		}

		let bytes = out.len() as u8;
		out.insert(0, 0x80 | bytes);
		return out;
	}
}

#[test]
fn it_works() {
	println!("test")
}
