extern crate mbed;

use mbed::base64::{encode, decode};

fn main () {
    let content = "abcabc";
    let expected_base64 = "YWJjYWJj";
    println!("{}", encode(content));
    assert_eq!(expected_base64, encode(content));


    let expected_content = "abcabc";
    let base64 = "YWJjYWJj";
    println!("{}", decode(base64));
    assert_eq!(expected_content, decode(base64));
}
