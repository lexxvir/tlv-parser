
extern crate error_chain;

error_chain! {
    types {
        Error, ErrorKind, ChainErr, Result;
    }

    links {
    }

    foreign_links {
    }

    errors {
        TruncatedTlv {
            display("Too short input vector")
        }
        InvalidLength {
            display("Invalid length value")
        }
        TooShortBody( expected: usize, found: usize ) {
            display("Too short body: expected {}, found {}", expected, found)
        }
    }
}

