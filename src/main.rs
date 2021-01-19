//use source::x509_header;
mod x509;

mod bignum;


fn main() {
    println!("Hello, world!");
    bignum::print(); //testing
    x509::print(); //testing
    x509::x509_header::print(); //testing
    x509::md_header::print(); //testing
    x509::pk_header::print(); //testing
    x509::x509::prnt(); //testing
    x509::asn1parse::print(); //testing

    bignum::self_test(); //testing
}