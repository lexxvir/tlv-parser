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

		assert_eq!(tlv.to_vec(), vec![0x01, 0x01, 0x00] );

		let tlv = Tlv {
			tag: vec![0x01],
			val: Value::Val( vec![0; 127] )
		};

		assert_eq!(&tlv.to_vec()[0 .. 3], vec![0x01, 0x7F, 0x00] );

		let tlv = Tlv {
			tag: vec![0x01],
			val: Value::Val( vec![0; 255] )
		};

		assert_eq!(&tlv.to_vec()[0 .. 4], vec![0x01, 0x81, 0xFF, 0x00] );

		let tlv = Tlv {
			tag: vec![0x02],
			val: Value::Val( vec![0; 256] )
		};

		assert_eq!(&tlv.to_vec()[0 .. 4], vec![0x02, 0x82, 0x01, 0x00]);

		let tlv = Tlv {
			tag: vec![0x03],
			val: Value::Val( vec![0; 0xffff01] )
		};

		assert_eq!(&tlv.to_vec()[0 .. 5], vec![0x03, 0x83, 0xFF, 0xFF, 0x01]);
	}
}
