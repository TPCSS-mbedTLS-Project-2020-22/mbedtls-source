//#if !defined(MBEDTLS_X509_MAX_INTERMEDIATE_CA)
pub const MBEDTLS_X509_MAX_INTERMEDIATE_CA   : i32 =  8;

pub const MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE              : i32 = -0x2080;  /**< Unavailable feature, e.g. RSA hashing/encryption combination. */
pub const MBEDTLS_ERR_X509_UNKNOWN_OID                      : i32 = -0x2100;  /**< Requested OID is unknown. */
pub const MBEDTLS_ERR_X509_INVALID_FORMAT                   : i32 = -0x2180;  /**< The CRT/CRL/CSR format is invalid, e.g. different type expected. */
pub const MBEDTLS_ERR_X509_INVALID_VERSION                  : i32 = -0x2200;  /**< The CRT/CRL/CSR version element is invalid. */
pub const MBEDTLS_ERR_X509_INVALID_SERIAL                   : i32 = -0x2280;  /**< The serial tag or value is invalid. */
pub const MBEDTLS_ERR_X509_INVALID_ALG                      : i32 = -0x2300; /**< The algorithm tag or value is invalid. */
pub const MBEDTLS_ERR_X509_INVALID_NAME                     : i32 = -0x2380;  /**< The name tag or value is invalid. */
pub const MBEDTLS_ERR_X509_INVALID_DATE                     : i32 = -0x2400;  /**< The date tag or value is invalid. */
pub const MBEDTLS_ERR_X509_INVALID_SIGNATURE                : i32 = -0x2480;  /**< The signature tag or value invalid. */
pub const MBEDTLS_ERR_X509_INVALID_EXTENSIONS               : i32 = -0x2500;  /**< The extension tag or value is invalid. */
pub const MBEDTLS_ERR_X509_UNKNOWN_VERSION                  : i32 = -0x2580;  /**< CRT/CRL/CSR has an unsupported version number. */
pub const MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG                  : i32 = -0x2600;  /**< Signature algorithm (oid) is unsupported. */
pub const MBEDTLS_ERR_X509_SIG_MISMATCH                     : i32 = -0x2680;  /**< Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid) */
pub const MBEDTLS_ERR_X509_CERT_VERIFY_FAILED               : i32 = -0x2700;  /**< Certificate verification failed, e.g. CRL, CA or signature check failed. */
pub const MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT              : i32 = -0x2780;  /**< Format not recognized as DER or PEM. */
pub const MBEDTLS_ERR_X509_BAD_INPUT_DATA                   : i32 = -0x2800;  /**< Input invalid. */
pub const MBEDTLS_ERR_X509_ALLOC_FAILED                     : i32 = -0x2880;  /**< Allocation of memory failed. */
pub const MBEDTLS_ERR_X509_FILE_IO_ERROR                    : i32 = -0x2900;  /**< Read/write of file failed. */
pub const MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 : i32 = -0x2980;  /**< Destination buffer is too small. */
pub const MBEDTLS_ERR_X509_FATAL_ERROR                      : i32 = -0x3000;  /**< A fatal error occurred, eg the chain is too long or the vrfy callback failed. */


pub const MBEDTLS_X509_BADCERT_EXPIRED             : i32 = 0x01;  /**< The certificate validity has expired. */
pub const MBEDTLS_X509_BADCERT_REVOKED             : i32 = 0x02;  /**< The certificate has been revoked (is on a CRL). */
pub const MBEDTLS_X509_BADCERT_CN_MISMATCH         : i32 = 0x04;  /**< The certificate Common Name (CN) does not match with the expected CN. */
pub const MBEDTLS_X509_BADCERT_NOT_TRUSTED         : i32 = 0x08;  /**< The certificate is not correctly signed by the trusted CA. */
pub const MBEDTLS_X509_BADCRL_NOT_TRUSTED          : i32 = 0x10;  /**< The CRL is not correctly signed by the trusted CA. */
pub const MBEDTLS_X509_BADCRL_EXPIRED              : i32 = 0x20;  /**< The CRL is expired. */
pub const MBEDTLS_X509_BADCERT_MISSING             : i32 = 0x40;  /**< Certificate was missing. */
pub const MBEDTLS_X509_BADCERT_SKIP_VERIFY         : i32 = 0x80;  /**< Certificate verification was skipped. */
pub const MBEDTLS_X509_BADCERT_OTHER             : i32 = 0x0100;  /**< Other reason (can be used by verify callback) */
pub const MBEDTLS_X509_BADCERT_FUTURE            : i32 = 0x0200;  /**< The certificate validity starts in the future. */
pub const MBEDTLS_X509_BADCRL_FUTURE             : i32 = 0x0400;  /**< The CRL is from the future */
pub const MBEDTLS_X509_BADCERT_KEY_USAGE         : i32 = 0x0800;  /**< Usage does not match the keyUsage extension. */
pub const MBEDTLS_X509_BADCERT_EXT_KEY_USAGE     : i32 = 0x1000;  /**< Usage does not match the extendedKeyUsage extension. */
pub const MBEDTLS_X509_BADCERT_NS_CERT_TYPE      : i32 = 0x2000;  /**< Usage does not match the nsCertType extension. */
pub const MBEDTLS_X509_BADCERT_BAD_MD            : i32 = 0x4000;  /**< The certificate is signed with an unacceptable hash. */
pub const MBEDTLS_X509_BADCERT_BAD_PK            : i32 = 0x8000;  /**< The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
pub const MBEDTLS_X509_BADCERT_BAD_KEY         : i32 = 0x010000;  /**< The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
pub const MBEDTLS_X509_BADCRL_BAD_MD           : i32 = 0x020000;  /**< The CRL is signed with an unacceptable hash. */
pub const MBEDTLS_X509_BADCRL_BAD_PK           : i32 = 0x040000;  /**< The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
pub const MBEDTLS_X509_BADCRL_BAD_KEY          : i32 = 0x080000; /**< The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */

pub const MBEDTLS_X509_SAN_OTHER_NAME                     : i32 = 0;
pub const MBEDTLS_X509_SAN_RFC822_NAME                    : i32 = 1;
pub const MBEDTLS_X509_SAN_DNS_NAME                       : i32 = 2;
pub const MBEDTLS_X509_SAN_X400_ADDRESS_NAME              : i32 = 3;
pub const MBEDTLS_X509_SAN_DIRECTORY_NAME                 : i32 = 4;
pub const MBEDTLS_X509_SAN_EDI_PARTY_NAME                 : i32 = 5;
pub const MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER    : i32 = 6;
pub const MBEDTLS_X509_SAN_IP_ADDRESS                     : i32 = 7;
pub const MBEDTLS_X509_SAN_REGISTERED_ID                  : i32 = 8;


pub const MBEDTLS_X509_KU_DIGITAL_SIGNATURE            : i32 = 0x80;  /* bit 0 */
pub const MBEDTLS_X509_KU_NON_REPUDIATION              : i32 = 0x40;  /* bit 1 */
pub const MBEDTLS_X509_KU_KEY_ENCIPHERMENT             : i32 = 0x20;  /* bit 2 */
pub const MBEDTLS_X509_KU_DATA_ENCIPHERMENT            : i32 = 0x10;  /* bit 3 */
pub const MBEDTLS_X509_KU_KEY_AGREEMENT                : i32 = 0x08;  /* bit 4 */
pub const MBEDTLS_X509_KU_KEY_CERT_SIGN                : i32 = 0x04;  /* bit 5 */
pub const MBEDTLS_X509_KU_CRL_SIGN                     : i32 = 0x02;  /* bit 6 */
pub const MBEDTLS_X509_KU_ENCIPHER_ONLY                : i32 = 0x01;  /* bit 7 */
pub const MBEDTLS_X509_KU_DECIPHER_ONLY              : i32 = 0x8000;  /* bit 8 */

pub const MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT         : i32 = 0x80;  /* bit 0 */
pub const MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER         : i32 = 0x40;  /* bit 1 */
pub const MBEDTLS_X509_NS_CERT_TYPE_EMAIL              : i32 = 0x20;  /* bit 2 */
pub const MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING     : i32 = 0x10;  /* bit 3 */
pub const MBEDTLS_X509_NS_CERT_TYPE_RESERVED           : i32 = 0x08;  /* bit 4 */
pub const MBEDTLS_X509_NS_CERT_TYPE_SSL_CA             : i32 = 0x04;  /* bit 5 */
pub const MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA           : i32 = 0x02;  /* bit 6 */
pub const MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA  : i32 = 0x01;  /* bit 7 */


//check if theis is ok
pub const MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER : &str = "MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER";
pub const MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER   : &str = "MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER";
pub const MBEDTLS_X509_EXT_KEY_USAGE                : &str = "MBEDTLS_OID_X509_EXT_KEY_USAGE";
pub const MBEDTLS_X509_EXT_CERTIFICATE_POLICIES     : &str = "MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES";
pub const MBEDTLS_X509_EXT_POLICY_MAPPINGS          : &str = "MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS";
pub const MBEDTLS_X509_EXT_SUBJECT_ALT_NAME         : &str = "MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME";         /* Supported (DNS) */
pub const MBEDTLS_X509_EXT_ISSUER_ALT_NAME          : &str = "MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME";
pub const MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS  : &str = "MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS";
pub const MBEDTLS_X509_EXT_BASIC_CONSTRAINTS        : &str = "MBEDTLS_OID_X509_EXT_BASIC_pub constRAINTS";        /* Supported */
pub const MBEDTLS_X509_EXT_NAME_CONSTRAINTS         : &str = "MBEDTLS_OID_X509_EXT_NAME_pub constRAINTS";
pub const MBEDTLS_X509_EXT_POLICY_CONSTRAINTS       : &str = "MBEDTLS_OID_X509_EXT_POLICY_pub constRAINTS";
pub const MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE       : &str = "MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE";
pub const MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS  : &str = "MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS";
pub const MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY       : &str = "MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY";
pub const MBEDTLS_X509_EXT_FRESHEST_CRL             : &str = "MBEDTLS_OID_X509_EXT_FRESHEST_CRL";
pub const MBEDTLS_X509_EXT_NS_CERT_TYPE             : &str = "MBEDTLS_OID_X509_EXT_NS_CERT_TYPE";

pub const MBEDTLS_X509_FORMAT_DER                 : i32 = 1;
pub const MBEDTLS_X509_FORMAT_PEM                 : i32 = 2;

pub const MBEDTLS_X509_MAX_DN_NAME_SIZE         : i32 = 256; /* Maximum value size of a DN entry */








//asn1.h file
//===========================================================================================================================================

pub const MBEDTLS_ERR_ASN1_OUT_OF_DATA                      : i32 = -0x0060;  /**< Out of data when parsing an ASN1 data structure. */
pub const MBEDTLS_ERR_ASN1_UNEXPECTED_TAG                   : i32 = -0x0062;  /**< ASN1 tag was of an unexpected value. */
pub const MBEDTLS_ERR_ASN1_INVALID_LENGTH                   : i32 = -0x0064;  /**< Error when trying to determine the length or invalid length. */
pub const MBEDTLS_ERR_ASN1_LENGTH_MISMATCH                  : i32 = -0x0066;  /**< Actual length differs from expected length. */
pub const MBEDTLS_ERR_ASN1_INVALID_DATA                     : i32 = -0x0068;  /**< Data is invalid. */
pub const MBEDTLS_ERR_ASN1_ALLOC_FAILED                     : i32 = -0x006A;  /**< Memory allocation failed */
pub const MBEDTLS_ERR_ASN1_BUF_TOO_SMALL                    : i32 = -0x006C;  /**< Buffer too small when writing ASN.1 data structure. */

pub const MBEDTLS_ASN1_BOOLEAN                 : u8 = 0x01;
pub const MBEDTLS_ASN1_INTEGER                 : u8 = 0x02;
pub const MBEDTLS_ASN1_BIT_STRING              : u8 = 0x03;
pub const MBEDTLS_ASN1_OCTET_STRING            : u8 = 0x04;
pub const MBEDTLS_ASN1_NULL                    : u8 = 0x05;
pub const MBEDTLS_ASN1_OID                     : u8 = 0x06;
pub const MBEDTLS_ASN1_ENUMERATED              : u8 = 0x0A;
pub const MBEDTLS_ASN1_UTF8_STRING             : u8 = 0x0C;
pub const MBEDTLS_ASN1_SEQUENCE                : u8 = 0x10;
pub const MBEDTLS_ASN1_SET                     : u8 = 0x11;
pub const MBEDTLS_ASN1_PRINTABLE_STRING        : u8 = 0x13;
pub const MBEDTLS_ASN1_T61_STRING              : u8 = 0x14;
pub const MBEDTLS_ASN1_IA5_STRING              : u8 = 0x16;
pub const MBEDTLS_ASN1_UTC_TIME                : u8 = 0x17;
pub const MBEDTLS_ASN1_GENERALIZED_TIME        : u8 = 0x18;
pub const MBEDTLS_ASN1_UNIVERSAL_STRING        : u8 = 0x1C;
pub const MBEDTLS_ASN1_BMP_STRING              : u8 = 0x1E;
pub const MBEDTLS_ASN1_PRIMITIVE               : u8 = 0x00;
pub const MBEDTLS_ASN1_CONSTRUCTED             : u8 = 0x20;
pub const MBEDTLS_ASN1_CONTEXT_SPECIFIC        : u8 = 0x80;

pub const MBEDTLS_ASN1_TAG_CLASS_MASK          : u8 = 0xC0;
pub const MBEDTLS_ASN1_TAG_PC_MASK             : u8 = 0x20;
pub const MBEDTLS_ASN1_TAG_VALUE_MASK          : u8 = 0x1F;

//#define MBEDTLS_OID_SIZE(x) (sizeof(x) - 1)


//error.h file
//===========================================================================================================================================

pub const MBEDTLS_ERR_ERROR_GENERIC_ERROR       : i32 = -0x0001;  /**< Generic error */
pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED : i32 = -0x006E;  /**< This is a bug in the library */

pub fn print(){
    println!("In x509/x509_header.rs");
}