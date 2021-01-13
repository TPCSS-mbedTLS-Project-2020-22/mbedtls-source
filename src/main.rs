//use source::x509_header;
mod x509;


fn main() {
    println!("Hello, world!");
    x509::print(); //testing
    x509::x509_header::print(); //testing
    x509::md_header::print(); //testing
    x509::pk_header::print(); //testing
    x509::x509::prnt(); //testing
    x509::asn1parse::print(); //testing
}