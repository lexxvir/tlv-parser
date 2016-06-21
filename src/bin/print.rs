extern crate tlv_parser;
extern crate rustc_serialize;

use std::io::{Read};
use tlv_parser::*;

use rustc_serialize::hex::FromHex;

fn print_tag( tag: &Vec<u8> ) {
    print!( "tag=" );
    for x in tag {
        print!("{:02X}", x);
    }
    println!("");
}

fn print( tlv: &Tlv, ident: usize ) {
    for _ in 0..ident {
        print!(" ");
    }

    match tlv.val {
        Value::TlvList( ref list ) => {
            print_tag( &tlv.tag );

            for t in list {
                print(&t, ident + 2);
            }
        },
        Value::Val( _ ) => {
            println!("{}", tlv);
        },
        _ => (),
    }
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string( &mut input ).unwrap();

    let buf = input.from_hex().unwrap();
    let mut idx = 0;

    while idx < buf.len() {
        match Tlv::from_vec(&buf[idx..]) {
            Ok(tlv) => {
                print( &tlv, 0 );
                println!("");
                idx += tlv.len();
            },
            Err(err) => {
                println!("Error: {}", err);
                break;
            }
        }
    }
}
