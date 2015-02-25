extern crate tlv_parser;

fn main() {
	let tlv = tlv_parser::Tlv {
		tag: vec![0x01],
		val: tlv_parser::Value::Val( vec![0; 256] )
	};

	println!( "{}", tlv );

	let tlv2 = tlv_parser::Tlv {
		tag: vec![0x22],
		val: tlv_parser::Value::TlvList( vec![tlv] )
	};

	println!( "{}", tlv2 );

	let tlv3 = tlv_parser::Tlv {
		tag: vec![0x23],
		val: tlv_parser::Value::TlvList( vec![tlv2])
	};

	println!( "{}", tlv3 );
}
