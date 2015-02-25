#![crate_name = "tlv_parser"]
#![allow(dead_code, unused_variables)]

#![feature(core)]

extern crate core;

use core::default::Default;
use core::iter::{range_step};
use core::ops::{Add};
use core::fmt::{Debug, Pointer};

pub enum Value {
	TlvList( Vec<Tlv> ),
	Val( Vec<u8> ),
	Nothing
}

pub struct Tlv {
	// FIXME: deny explicit assignment
	pub tag: Vec<u8>,
	pub val: Value,
}

impl Tlv {
	/// Creates blank Tlv object
	pub fn new() -> Tlv {
		Tlv { tag: vec![], val: Value::Val( vec![] ) }
	}

	/// Returns size of TLV-string in bytes
	pub fn len( &self ) -> usize {
		let val_len = self.val.len();
		self.tag.len() + self.val.encode_len().len() + val_len
	}

	/// Returns encoded array of bytes
	pub fn to_vec( &self ) -> Vec<u8>  {
		let mut out: Vec<u8> = vec![];

		out = out.add( &self.tag );
		out = out.add( &self.val.encode_len() );

		out = out.add( &match self.val {
				Value::TlvList( ref list ) => list.iter().fold(vec![], |sum, ref x| sum.add(&x.to_vec())),
				Value::Val( ref v ) => v.clone(),
				_ => vec![],
			});

		return out;
	}

	/// Initializes Tlv object from Vec<u8>
	pub fn from_vec( &mut self, vec: &Vec<u8> ) {
	}
}

impl Value {
	/// Returns size of value in bytes
	fn len( &self ) -> usize {
		match *self {
			Value::TlvList(ref list) => list.iter().fold(0, |sum, ref x| sum + x.len()),
			Value::Val(ref v) => v.len(),
			Value::Nothing => 0,
		}
	}

	/// Returns bytes array that represents encoded-len
	/// Note: implements only definite form
	pub fn encode_len( &self ) -> Vec<u8> {
		let len = self.len();
		if len <= 0x7f {
			return vec![len as u8];
		}

		let mut out: Vec<u8> = vec![];

		for x in range_step(24, -8, -8) { // FIXME: use variable-depended size
			let b: u8 = (len >> x) as u8;

			if b != 0 || out.len() != 0 {
				out.push( b );
			}
		}

		let bytes = out.len() as u8;
		out.insert(0, 0x80 | bytes);
		return out;
	}
}

impl Default for Tlv {
    fn default() -> Tlv {
        Tlv::new()
    }
}

impl core::fmt::Display for Tlv {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		for x in self.tag.iter() {
			try!(write!(f, "{:02X}", x));
		}
		try!(write!(f, " "));

		for x in self.val.encode_len()  {
			try!(write!(f, "{:02X}", x));
		}
		try!(write!(f, " "));

		self.val.fmt(f)
    }
}

impl core::fmt::Display for Vec< Tlv > {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		for x in self.iter() {
			let _ = try!(x.fmt(f));
		}
		Ok(())
	}
}

impl core::fmt::Display for Value {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		match self {
			&Value::TlvList( ref list ) => { let _ = f.pad("--->"); list.fmt(f) },
			&Value::Val( ref v ) => { for x in v { try!(write!(f, "{:02X}", x)); } Ok(()) },
			_ => ().fmt(f),
		}

    }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn it_works() {
		let tlv = Tlv {
			tag: vec![0x01],
			val: Value::Val( vec![0] )
		};

		assert_eq!(format!( "{}", tlv ), "01 01 00" );

		let tlv = Tlv {
			tag: vec![0x01],
			val: Value::Val( vec![0; 256] )
		};

		assert_eq!(format!( "{}", tlv ), "01 820100 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" );
	}
}
