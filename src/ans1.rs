#[cfg(feature = "BIGNUM")]
use super::bignum;
#[allow(dead_code)]
///
/// \name ASN1 Error codes
/// These error codes are OR'ed to X509 error codes for
/// higher error granularity.
/// ASN1 is a standard to specify data structures.
///

/// Error when trying to determine the length or invalid length.
pub const ERR_INVALID_LENGTH: i32 = -0x0064;
/// Buffer too small when writing ASN.1 data structure.
pub const ERR_BUF_TOO_SMALL: i32 = -0x006C;

///
/// DER constants
/// These constants comply with the DER encoded ASN.1 type tags.
/// DER encoding uses hexadecimal representation.
/// An example DER sequence is:\n
/// - 0x02 -- tag indicating INTEGER
/// - 0x01 -- length in octets
/// - 0x05 -- value
/// Such sequences are typically read into \c ::mbedtls_x509_buf.
///

pub const BOOLEAN: i32 = 0x01;
pub const INTEGER: i32 = 0x02;
pub const BIT_STRING: i32 = 0x03;
pub const OCTET_STRING: i32 = 0x04;
pub const NULL: i32 = 0x05;
pub const OID: i32 = 0x06;
pub const ENUMERATED: i32 = 0x0A;
pub const UTF8_STRING: i32 = 0x0C;
pub const SEQUENCE: i32 = 0x10;
pub const PRINTABLE_STRING: i32 = 0x13;
pub const IA5_STRING: i32 = 0x16;
pub const CONSTRUCTED: i32 = 0x20;
