# tlv-parser
Library for parsing BER-TLV

Library is early development stage.
Library supports parsing from Vec<u8> and emitting Vec<u8>.

For usage see 'examples/print.rs'.

```
$ echo "7003820151" | cargo run --example print
     Running `target/debug/examples/print`
	 tag=70
	   tag=82,     len=1,    data=51 Q
```

[![Build Status](https://travis-ci.org/lexxvir/tlv-parser.svg?branch=master)](https://travis-ci.org/lexxvir/tlv-parser.svg)
