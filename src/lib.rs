#![crate_name = "tlv_parser"]
#![feature(question_mark)]

extern crate byteorder;

use std::default::Default;
use std::fmt::{Debug, Display};

use byteorder::{WriteBytesExt, BigEndian};

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
		self.tag.len() + self.val.encode_len().len() + self.val.len()
	}

    /// Returns true if TLV-object is empty (len() == 0)
    pub fn is_empty( &self ) -> bool {
		self.tag.is_empty() && self.val.is_empty()
    }

	/// Returns encoded array of bytes
	pub fn to_vec( &self ) -> Vec<u8>  {
		let mut out: Vec<u8> = vec![];

		out.extend_from_slice( &self.tag );
		out.append( &mut self.val.encode_len() );

		match self.val {
			Value::TlvList( ref list ) => for x in list.iter() {
				out.append( &mut x.to_vec() );
			},
			Value::Val( ref v ) => out.extend_from_slice( v ),
			Value::Nothing => (),
		};

		out
	}

	/// Initializes Tlv object iterator of Vec<u8>
	fn from_iter<'a>( &mut self, iter: &mut std::slice::Iter<'a, u8> ) {
		let first: u8 = match iter.next() {
			Some( x ) => *x,
			None => panic!( "Too short TLV, no data at all" ),
		};

		self.tag.push( first );

		if first & 0x1F == 0x1F {
			// long form - find the end
			for x in &mut *iter {
				self.tag.push( *x );
				if *x & 0x80 == 0 {
					break;
				}
			}
		}

		let mut len: usize = match iter.next() {
			Some( x ) => *x as usize,
			None => panic!( "Too short TLV, only tag exists" ),
		};

		if len & 0x80 != 0 {
			let octet_num = len & 0x7F;
			if octet_num == 0 || iter.size_hint().1.unwrap() < octet_num {
				panic!("Invalid length value!");
			}

			// FIXME: try to use byteorder
			//let vec_len: Vec<u8> = iter.take(octet_num).map(|x| *x).collect();
			//len = <BigEndian as ByteOrder>::read_u32(&vec_len) as usize;

			len = 0;
			for x in iter.take(octet_num) {
				len = (len << 8) | *x as usize;
			}
		}

		let remain = iter.size_hint().1.unwrap();
		if remain < len {
			panic!("Too short body, expected {} found {}", len, remain);
		}

		if self.tag[0] & 0x20 == 0x20 {
			// constructed tag
			let mut children: Vec<Tlv> = vec![];

			while iter.size_hint().1.unwrap() != 0 {
				let mut child = Tlv::new();
				child.from_iter( iter );
                children.push( child );
			}

			self.val = Value::TlvList(children);
		}
		else {
			let val = iter.take(len).cloned().collect();
			self.val = Value::Val(val);
		}
	}

	/// Initializes Tlv object from [u8] slice
	pub fn from_vec( &mut self, slice: &[u8] ) {
		if slice.is_empty() {
			return;
		}

		self.from_iter( &mut slice.iter() );
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

    /// Returns true if Value is empty (len() == 0)
    pub fn is_empty( &self ) -> bool {
        match *self {
			Value::TlvList( ref list ) => list.is_empty(),
			Value::Val( ref v ) => v.is_empty(),
			Value::Nothing => true,
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
		out.write_u64::<BigEndian>(len as u64).unwrap();
		out = out.iter().skip_while(|&x| *x == 0 ).cloned().collect();

		let bytes = out.len() as u8;
		out.insert(0, 0x80 | bytes);
		out
	}
}

impl Default for Tlv {
    fn default() -> Tlv {
        Tlv::new()
    }
}

impl Display for Tlv {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "tag=")?;
		for x in &self.tag {
			write!(f, "{:02X}", x)?;
		}
		write!(f, ",")?;

		let mut p = String::new();
		for _ in 0..(12 - (self.tag.len() * 2 + 5)) {
			p.push(' ');
		}

		f.pad(p.as_ref())?;
		write!(f, "len={},", self.val.len())?;

		match self.val {
			Value::Val( _ ) => {
				let len = self.val.len();
				let mut num1 = 1;
				let mut num2 = 10;

				while len / num2 != 0 {
					num1 += 1;
					num2 *= 10;
				}
 
				let mut p = String::new();
				for _ in 0..10 - (num1 + 5) {
					p.push(' ');
				}
				f.pad(p.as_ref())?;
			},
			_ => f.pad("")?,
		}

		self.val.fmt(f)?;
		f.pad("")
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match *self {
			Value::TlvList( ref list ) => {
				for x in list.iter() {
					write!(f, "\n")?;
					x.fmt(f)?;
				}
				Ok(())
			},

			Value::Val( ref v ) => {
				write!(f, "data=")?;
				for x in v { write!(f, "{:02X}", x)?; } Ok(())
			},
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
		let mut input: Vec<u8> = vec![0x9F, 0x02, 0x81, 0x80];
		input.extend_from_slice( &[0; 0x80] );

		tlv.from_vec( &input );
		assert_eq!(tlv.to_vec(), input );
	}

	#[test]
	fn to_vec_test() {
		let tlv = Tlv {
			tag: vec![0x01],
			val: Value::Val( vec![0] )
		};

		assert_eq!(tlv.to_vec(), vec![0x01, 0x01, 0x00]);

		let tlv = Tlv {
			tag: vec![0x01],
			val: Value::Val( vec![0; 127] )
		};

		assert_eq!(&tlv.to_vec()[0 .. 3], [0x01, 0x7F, 0x00]);

		let tlv = Tlv {
			tag: vec![0x01],
			val: Value::Val( vec![0; 255] )
		};

		assert_eq!(&tlv.to_vec()[0 .. 4], [0x01, 0x81, 0xFF, 0x00]);

		let tlv = Tlv {
			tag: vec![0x02],
			val: Value::Val( vec![0; 256] )
		};

		assert_eq!(&tlv.to_vec()[0 .. 4], [0x02, 0x82, 0x01, 0x00]);

		let tlv = Tlv {
			tag: vec![0x03],
			val: Value::Val( vec![0; 0xffff01] )
		};

		assert_eq!(&tlv.to_vec()[0 .. 5], [0x03, 0x83, 0xFF, 0xFF, 0x01]);
	}

    #[test]
    fn is_empty_test() {
        let tlv = Tlv::new();
        assert_eq!(tlv.is_empty(), true);

		let tlv = Tlv {
			tag: vec![0x03],
            val: Value::Val( vec![] )
		};
        assert_eq!(tlv.is_empty(), false);
    }
}
