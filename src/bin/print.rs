extern crate tlv_parser;

fn main() {
	let tlv = tlv_parser::Tlv {
		tag: vec![0x01],
		val: tlv_parser::Val( vec![0, 1, 2, 3, 4] )
	};

	let tlv2 = tlv_parser::Tlv {
		tag: vec![0x02],
		val: tlv_parser::TlvList( vec![tlv] )
	};

	println!( "{}", tlv2 );

	let tlv3 = tlv_parser::Tlv {
		tag: vec![0x03],
		val: tlv_parser::TlvList( vec![tlv2])
	};

	println!( "{}", tlv3 );

}
