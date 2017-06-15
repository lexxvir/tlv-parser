#![feature(test)]
extern crate test;
extern crate tlv_parser;

#[cfg(test)]
mod tests {
    use test::Bencher;
    use tlv_parser::tlv::*;

    #[bench]
    fn bench_from_vec(b: &mut Bencher) {
        let tlv_vec = vec![
            0x6F,
            0x3B,
            0x84,
            0x0E,
            0x32,
            0x50,
            0x41,
            0x59,
            0x2E,
            0x53,
            0x59,
            0x53,
            0x2E,
            0x44,
            0x44,
            0x46,
            0x30,
            0x31,
            0xA5,
            0x29,
            0xBF,
            0x0C,
            0x26,
            0x61,
            0x24,
            0x4F,
            0x08,
            0xA0,
            0x00,
            0x00,
            0x00,
            0x25,
            0x01,
            0x04,
            0x03,
            0x50,
            0x10,
            0x41,
            0x6D,
            0x65,
            0x72,
            0x69,
            0x63,
            0x61,
            0x6E,
            0x20,
            0x45,
            0x78,
            0x70,
            0x72,
            0x65,
            0x73,
            0x73,
            0x87,
            0x01,
            0x01,
            0x9F,
            0x28,
            0x02,
            0x40,
            0x04,
        ];
        b.iter(|| Tlv::from_vec(&tlv_vec))
    }
}
