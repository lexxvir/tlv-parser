# tlv-parser
[![Build Status](https://travis-ci.org/lexxvir/tlv-parser.svg?branch=master)](https://travis-ci.org/lexxvir/tlv-parser.svg)
[![Latest Version](https://img.shields.io/crates/v/tlv_parser.svg)](https://crates.io/crates/tlv_parser)
[![Docs](https://docs.rs/tlv_parser/badge.svg)](https://docs.rs/tlv_parser)

Library for parsing BER-TLV

[Documentation](https://lexxvir.github.io/tlv-parser/tlv_parser/index.html)

Library is early development stage and supports parsing from `&[u8]` and emitting `Vec<u8>`.

*For now, it only builds on nightly.*

For usage see [`src/bin/decode-tlv.rs`](https://github.com/lexxvir/tlv-parser/blob/master/examples/src/bin/decode-tlv.rs).

```
$ echo "7003820151" | cargo run
     Running `target/debug/decode-tlv`
	 tag=70
	   tag=82,     len=1,    data=51 Q
```

