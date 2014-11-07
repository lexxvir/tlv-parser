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
		val: tlv_parser::Val( vec![0, 1, 2, 3, 4] )
	};

	let tlv2 = tlv_parser::Tlv {
		tag: vec![0xA2],
		val: tlv_parser::Val( vec![4, 3, 2, 1, 0] )
	};

	print( &tlv );

	let ctlv = tlv_parser::Tlv {
		tag: vec![0xA3],
		val: tlv_parser::TlvList( vec![tlv, tlv2])
	};

	print( &ctlv );
}
