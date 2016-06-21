use std::default::Default;
use std::fmt;
use std::fmt::{Debug};

use byteorder::{WriteBytesExt, ByteOrder, BigEndian};

use errors::{Error, ErrorKind};

use rustc_serialize::hex::FromHex;

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
    tag: Vec<u8>,
    val: Value,
}

impl Tlv {
    /// Creates blank Tlv object
    pub fn new() -> Tlv {
        Tlv { tag: vec![], val: Value::Val( vec![] ) }
    }

    /// Returns tag number of TLV
    pub fn tag(&self) -> Vec<u8> {
        self.tag.clone()
    }

    /// Returns size of TLV-string in bytes
    pub fn len(&self) -> usize {
        self.tag.len() + self.val.encode_len().len() + self.val.len()
    }

    /// Returns value if TLV
    pub fn val(&self) -> &Value {
        &self.val
    }

    /// Returns true if TLV-object is empty (len() == 0)
    pub fn is_empty(&self) -> bool {
        self.tag.is_empty() && self.val.is_empty()
    }

    /// Returns encoded array of bytes
    pub fn to_vec(&self) -> Vec<u8>  {
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

    fn get_path(path: &str) -> Option<Vec<Vec<u8>>> {
        let mut hex_tags: Vec<String> = vec!();
        let mut tags: Vec<Vec<u8>> = vec!();
        let mut tag = String::new();

        for c in path.chars() {
            match c {
                '/' => {
                    hex_tags.push(tag.clone());
                    tag.clear();
                },
                ' ' => (),
                _ => tag.push(c),
            }
        }

        if !tag.is_empty() {
            hex_tags.push(tag);
        }

        for hex_tag in hex_tags {
            match hex_tag.from_hex() {
                Ok(bin) => tags.push(bin),
                Err(_) => return None,
            }
        }

        Some(tags)
    }

    /// Returns value of TLV
    /// Example: find_val( "6F / A5 / BF0C / DF7F" )
    pub fn find_val(&self, path: &str) -> Option<&Value> {
        let path = match Tlv::get_path(path) {
            Some(x) => x,
            None => return None,
        };

        if path.is_empty() {
            return None;
        }

        if path[0] != self.tag {
            return None;
        }

        if path.len() == 1 {
            return Some(&self.val);
        }

        let mut tlv: &Tlv = &self;
        let mut i = 1;

        for tag in path.iter().skip(1) {
            i += 1;
            match tlv.val {
                Value::TlvList(ref list) => for subtag in list {
                    if *tag == subtag.tag {
                        if path.len() == i {
                            return Some(&subtag.val);
                        }
                        else {
                            tlv = &subtag;
                            continue;
                        }
                    }
                },
                _ => return None,

            }
        }

        None
    }

    /// Reads out tag number
    fn read_tag( iter: &mut Iterator<Item=&u8> ) -> Result<Vec<u8>, Error> {
        let mut tag: Vec<u8> = vec!();

        let first: u8 = match iter.next() {
            Some( x ) => *x,
            None => return Err(ErrorKind::TruncatedTlv.into()),
        };

        tag.push( first );

        if first & 0x1F == 0x1F {
            // long form - find the end
            for x in &mut *iter {
                tag.push( *x );
                if *x & 0x80 == 0 {
                    break;
                }
            }
        }

        Ok(tag)
    }

    /// Reads out TLV value's length
    fn read_len( iter: &mut Iterator<Item=&u8> ) -> Result<usize, Error> {
        let mut len: usize = match iter.next() {
            Some( x ) => *x as usize,
            None => return Err(ErrorKind::TruncatedTlv.into()),
        };

        if len & 0x80 != 0 {
            let octet_num = len & 0x7F;
            if octet_num == 0 || iter.size_hint().1.unwrap() < octet_num {
                return Err(ErrorKind::InvalidLength.into());
            }

            let tlv_len: Vec<u8> = iter.take(octet_num).map(|x| *x).collect();
            len = BigEndian::read_uint(&tlv_len, octet_num) as usize;
        }

        let remain = iter.size_hint().1.unwrap();
        if remain < len {
            return Err(ErrorKind::TooShortBody(len, remain).into());
        }

        Ok(len)
    }

    /// Initializes Tlv object iterator of Vec<u8>
    fn from_iter( iter: &mut Iterator<Item=&u8> ) -> Result<Tlv, Error> {
        let tag = Tlv::read_tag( iter )?;
        let len = Tlv::read_len( iter )?;

        let mut val = &mut iter.take(len);

        if tag[0] & 0x20 != 0x20 { // primitive tag
            return Ok( Tlv {
                tag: tag,
                val: Value::Val(val.cloned().collect()),
            })
        }

        let mut tlv = Tlv {
            tag: tag,
            val: Value::TlvList(vec![])
        };

        while 0 != val.size_hint().1.unwrap() {
            if let Value::TlvList( ref mut children ) = tlv.val {
                children.push( Tlv::from_iter( val )? );
            }
        }

        return Ok(tlv)
    }

    /// Initializes Tlv object from [u8] slice
    pub fn from_vec(slice: &[u8]) -> Result<Tlv, Error> {
        let mut iter = &mut slice.iter();
        Tlv::from_iter( iter )
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

impl fmt::Display for Tlv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
                for x in v { write!(f, "{:02X}", x)?; }
                write!(f, " ")?;
                for x in v {
                    if *x >= 0x20 && *x <= 0x7f {
                        write!(f, "{}", *x as char)?;
                    }
                    else {
                        write!(f, ".")?;
                    }
                }
                Ok(())
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
        let input: Vec<u8> = vec![0x01, 0x02, 0x00, 0x00];
        assert_eq!(Tlv::from_vec( &input ).unwrap().to_vec(), input );

        // TLV with two bytes tag
        let input: Vec<u8> = vec![0x9F, 0x02, 0x02, 0x00, 0x00 ];
        assert_eq!(Tlv::from_vec( &input ).unwrap().to_vec(), input );

        // TLV with two bytes length
        let mut input: Vec<u8> = vec![0x9F, 0x02, 0x81, 0x80];
        input.extend_from_slice( &[0; 0x80] );
        assert_eq!(Tlv::from_vec( &input ).unwrap().to_vec(), input );
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

    #[test]
    fn find_val_test() {
        let tlv = Tlv {
            tag: vec![0x01],
            val: Value::TlvList(
                vec![ Tlv {
                    tag: vec![0x02],
                    val: Value::Val( vec![ 0xaa ] ) } ] ) };

        match tlv.find_val("01 / 02") {
            Some(x) => match x {
                &Value::Val(ref xx) => assert_eq!(*xx, vec![0xaa]),
                _ => assert_eq!(false, true),
            },
            None => assert_eq!(false, true),
        };
    }
}
