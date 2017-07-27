extern crate tlv_parser;
extern crate hex;

use std::io::Read;
use tlv_parser::tlv::{Tlv, Value};

use hex::FromHex;

fn print(tlv: &Tlv, ident: usize) {
    for _ in 0..ident {
        print!(" ");
    }

    match *tlv.val() {
        Value::TlvList(ref list) => {
            println!("tag={:02X}", tlv.tag());

            for t in list {
                print(t, ident + 2);
            }
        }
        Value::Val(_) => {
            println!("{}", tlv);
        }
        _ => (),
    }
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    input = input.replace("\n", "");

    let buf: Vec<u8> = FromHex::from_hex(&input).unwrap();
    let mut idx = 0;

    while idx < buf.len() {
        match Tlv::from_vec(&buf[idx..]) {
            Ok(tlv) => {
                print(&tlv, 0);
                println!("");
                idx += tlv.len();
            }
            Err(err) => {
                println!("Error: {}", err);
                break;
            }
        }
    }
}
