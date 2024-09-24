# tlv-parser
![Build status](https://github.com/lexxvir/tlv-parser/actions/workflows/rust.yml/badge.svg)
[![Latest Version](https://img.shields.io/crates/v/tlv_parser.svg)](https://crates.io/crates/tlv_parser)
[![Docs](https://docs.rs/tlv_parser/badge.svg)](https://docs.rs/tlv_parser)

Library for parsing BER-TLV

Library supports parsing from `&[u8]` and emitting `Vec<u8>`.

*This is `no_std` crate if you can use `core::alloc`.*

For usage see [`decode-tlv/src/main.rs`](https://github.com/lexxvir/tlv-parser/blob/master/decode-tlv/src/main.rs).

```
$ echo "7003820151" | cargo run
     Running `target/debug/decode-tlv`
	 tag=70
	   tag=82,     len=1,    data=51 Q
```

