extern crate tlv_parser;

fn print( input: &tlv_parser::Tlv )
{
	print!("tlv = " );
	for x in input.to_vec().iter() {
		print!("{:02X} ", *x );
	}
	println!("");
	println!("size = {}", input.len());
}

fn main() {
	let tlv = tlv_parser::Tlv {
		tag: vec![0xA2],
		val: tlv_parser::Val( Vec::from_elem(10, 0u8) )
	};

	print( &tlv );

	let ctlv = tlv_parser::Tlv {
		tag: vec![0xA3],
		val: tlv_parser::TlvList( vec![tlv])
	};

	print( &ctlv );
}
