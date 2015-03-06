#![crate_name = "tlv_parser"]
#![allow(dead_code, unused_variables)]

#![feature(core, collections)]

extern crate core;

use core::default::Default;
use core::iter::{range_step};
use core::fmt::{Debug, Pointer};

pub enum Value {
	TlvList( Vec<Tlv> ),
	Val( Vec<u8> ),
	Nothing
}

/* TODO: use it instead of Vec<u8> for tag
pub enum Tag {
	Array( Vec<u8> ),
	Integer( usize ),
} */

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

		out.push_all( &self.tag );
		out.append( &mut self.val.encode_len() );

		match self.val {
			Value::TlvList( ref list ) => {
				for x in list.iter() {
					out.append( &mut x.to_vec() );
				}
			},
			Value::Val( ref v ) => out.push_all( v ),
			_ => (),
		};

		return out;
	}

	/// Initializes Tlv object iterator of Vec<u8>
	fn from_iter<'a>( &mut self, iter: &mut core::slice::Iter<'a, u8> ) {
		let first = *(*iter).next().unwrap();
		self.tag.push( first );

		if first & 0x1F == 0x1F {
			// long form - find the end
			for x in &mut *iter {
				self.tag.push( *x );
				if x & 0x80 == 0 {
					break;
				}
			}
		}

		let mut len: usize = match iter.next() {
			Some( x ) => *x as usize,
			None => panic!( "invalid tlv" ),
		};

		if len & 0x80 != 0 {
			let octet_num = len & 0x7F;
			if octet_num == 0 {
				panic!("invalid len!");
			}

			len = 0;

			for _ in range(0, octet_num) {
				len = len << 8;
				len = len | match iter.next() {
					Some( x ) => *x as usize,
					None => panic!( "invalid tlv2" ),
				}
			}
		}

		let (_, remain) = iter.size_hint();
		if remain.unwrap() < len {
			panic!("invalid len 2!");
		}

		if self.tag[0] & 0x20 == 0x20 {
			// constructed tag
			self.val = Value::TlvList(vec![]);
			loop {
				let (_, remain) = iter.size_hint();
				if remain.unwrap() == 0 {
					break;
				}

				let mut child = Tlv::new();
				child.from_iter( iter );

                match self.val {
                    Value::TlvList( ref mut list ) => list.push( child ),
                    _ => panic!( "invalid tlv4" ),
                }
			}
		}
		else {
			match self.val {
				Value::Val(ref mut val) => {
					for x in iter.take(len) {
						val.push( *x );
					}
				},
				_ => panic!("self.val is constructed"),
			};
		}
	}

	/// Initializes Tlv object from Vec<u8>
	pub fn from_vec( &mut self, vec: &Vec<u8> ) {
		if vec.is_empty() {
			return;
		}

		let mut iter = vec.iter();
		self.from_iter( &mut iter );
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
			try!(write!(f, ", "));
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
	fn from_vec_test() {
		// simple two bytes TLV
		let mut tlv = Tlv::new();
		let input: Vec<u8> = vec![0x01, 0x02, 0x00, 0x00];

		tlv.from_vec( &input );
		assert_eq!(tlv.to_vec(), input );

		// TLV with two bytes tag
		let mut tlv = Tlv::new();
		let input: Vec<u8> = vec![0x9F, 0x02, 0x02, 0x00, 0x00 ];

		tlv.from_vec( &input );
		assert_eq!(tlv.to_vec(), input );

		// TLV with two bytes length
		let mut tlv = Tlv::new();
		let input: Vec<u8> = vec![0x9F, 0x02, 0x81, 0x80] + &[0; 0x80];

		tlv.from_vec( &input );
		assert_eq!(tlv.to_vec(), input );
	}

	#[test]
	fn to_vec_test() {
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
