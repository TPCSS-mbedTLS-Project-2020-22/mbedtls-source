//#if !defined(MBEDTLS_X509_MAX_INTERMEDIATE_CA)
const MBEDTLS_X509_MAX_INTERMEDIATE_CA   : i32 =  8;

pub fn print(){
    println!("Done!!");
}

const MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE              : i32 = -0x2080;  /**< Unavailable feature, e.g. RSA hashing/encryption combination. */
const MBEDTLS_ERR_X509_UNKNOWN_OID                      : i32 = -0x2100;  /**< Requested OID is unknown. */
const MBEDTLS_ERR_X509_INVALID_FORMAT                   : i32 = -0x2180;  /**< The CRT/CRL/CSR format is invalid, e.g. different type expected. */
const MBEDTLS_ERR_X509_INVALID_VERSION                  : i32 = -0x2200;  /**< The CRT/CRL/CSR version element is invalid. */
const MBEDTLS_ERR_X509_INVALID_SERIAL                   : i32 = -0x2280;  /**< The serial tag or value is invalid. */
const MBEDTLS_ERR_X509_INVALID_ALG                      : i32 = -0x2300; /**< The algorithm tag or value is invalid. */
const MBEDTLS_ERR_X509_INVALID_NAME                     : i32 = -0x2380;  /**< The name tag or value is invalid. */
const MBEDTLS_ERR_X509_INVALID_DATE                     : i32 = -0x2400;  /**< The date tag or value is invalid. */
const MBEDTLS_ERR_X509_INVALID_SIGNATURE                : i32 = -0x2480;  /**< The signature tag or value invalid. */
const MBEDTLS_ERR_X509_INVALID_EXTENSIONS               : i32 = -0x2500;  /**< The extension tag or value is invalid. */
const MBEDTLS_ERR_X509_UNKNOWN_VERSION                  : i32 = -0x2580;  /**< CRT/CRL/CSR has an unsupported version number. */
const MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG                  : i32 = -0x2600;  /**< Signature algorithm (oid) is unsupported. */
const MBEDTLS_ERR_X509_SIG_MISMATCH                     : i32 = -0x2680;  /**< Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid) */
const MBEDTLS_ERR_X509_CERT_VERIFY_FAILED               : i32 = -0x2700;  /**< Certificate verification failed, e.g. CRL, CA or signature check failed. */
const MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT              : i32 = -0x2780;  /**< Format not recognized as DER or PEM. */
const MBEDTLS_ERR_X509_BAD_INPUT_DATA                   : i32 = -0x2800;  /**< Input invalid. */
const MBEDTLS_ERR_X509_ALLOC_FAILED                     : i32 = -0x2880;  /**< Allocation of memory failed. */
const MBEDTLS_ERR_X509_FILE_IO_ERROR                    : i32 = -0x2900;  /**< Read/write of file failed. */
const MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 : i32 = -0x2980;  /**< Destination buffer is too small. */
const MBEDTLS_ERR_X509_FATAL_ERROR                      : i32 = -0x3000;  /**< A fatal error occurred, eg the chain is too long or the vrfy callback failed. */


const MBEDTLS_X509_BADCERT_EXPIRED             : i32 = 0x01;  /**< The certificate validity has expired. */
const MBEDTLS_X509_BADCERT_REVOKED             : i32 = 0x02;  /**< The certificate has been revoked (is on a CRL). */
const MBEDTLS_X509_BADCERT_CN_MISMATCH         : i32 = 0x04;  /**< The certificate Common Name (CN) does not match with the expected CN. */
const MBEDTLS_X509_BADCERT_NOT_TRUSTED         : i32 = 0x08;  /**< The certificate is not correctly signed by the trusted CA. */
const MBEDTLS_X509_BADCRL_NOT_TRUSTED          : i32 = 0x10;  /**< The CRL is not correctly signed by the trusted CA. */
const MBEDTLS_X509_BADCRL_EXPIRED              : i32 = 0x20;  /**< The CRL is expired. */
const MBEDTLS_X509_BADCERT_MISSING             : i32 = 0x40;  /**< Certificate was missing. */
const MBEDTLS_X509_BADCERT_SKIP_VERIFY         : i32 = 0x80;  /**< Certificate verification was skipped. */
const MBEDTLS_X509_BADCERT_OTHER             : i32 = 0x0100;  /**< Other reason (can be used by verify callback) */
const MBEDTLS_X509_BADCERT_FUTURE            : i32 = 0x0200;  /**< The certificate validity starts in the future. */
const MBEDTLS_X509_BADCRL_FUTURE             : i32 = 0x0400;  /**< The CRL is from the future */
const MBEDTLS_X509_BADCERT_KEY_USAGE         : i32 = 0x0800;  /**< Usage does not match the keyUsage extension. */
const MBEDTLS_X509_BADCERT_EXT_KEY_USAGE     : i32 = 0x1000;  /**< Usage does not match the extendedKeyUsage extension. */
const MBEDTLS_X509_BADCERT_NS_CERT_TYPE      : i32 = 0x2000;  /**< Usage does not match the nsCertType extension. */
const MBEDTLS_X509_BADCERT_BAD_MD            : i32 = 0x4000;  /**< The certificate is signed with an unacceptable hash. */
const MBEDTLS_X509_BADCERT_BAD_PK            : i32 = 0x8000;  /**< The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
const MBEDTLS_X509_BADCERT_BAD_KEY         : i32 = 0x010000;  /**< The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
const MBEDTLS_X509_BADCRL_BAD_MD           : i32 = 0x020000;  /**< The CRL is signed with an unacceptable hash. */
const MBEDTLS_X509_BADCRL_BAD_PK           : i32 = 0x040000;  /**< The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
const MBEDTLS_X509_BADCRL_BAD_KEY          : i32 = 0x080000; /**< The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */

const MBEDTLS_X509_SAN_OTHER_NAME                     : i32 = 0;
const MBEDTLS_X509_SAN_RFC822_NAME                    : i32 = 1;
const MBEDTLS_X509_SAN_DNS_NAME                       : i32 = 2;
const MBEDTLS_X509_SAN_X400_ADDRESS_NAME              : i32 = 3;
const MBEDTLS_X509_SAN_DIRECTORY_NAME                 : i32 = 4;
const MBEDTLS_X509_SAN_EDI_PARTY_NAME                 : i32 = 5;
const MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER    : i32 = 6;
const MBEDTLS_X509_SAN_IP_ADDRESS                     : i32 = 7;
const MBEDTLS_X509_SAN_REGISTERED_ID                  : i32 = 8;

//significance of bracket??
/*
const MBEDTLS_X509_KU_DIGITAL_SIGNATURE            (0x80)  /* bit 0 */
const MBEDTLS_X509_KU_NON_REPUDIATION              (0x40)  /* bit 1 */
const MBEDTLS_X509_KU_KEY_ENCIPHERMENT             (0x20)  /* bit 2 */
const MBEDTLS_X509_KU_DATA_ENCIPHERMENT            (0x10)  /* bit 3 */
const MBEDTLS_X509_KU_KEY_AGREEMENT                (0x08)  /* bit 4 */
const MBEDTLS_X509_KU_KEY_CERT_SIGN                (0x04)  /* bit 5 */
const MBEDTLS_X509_KU_CRL_SIGN                     (0x02)  /* bit 6 */
const MBEDTLS_X509_KU_ENCIPHER_ONLY                (0x01)  /* bit 7 */
const MBEDTLS_X509_KU_DECIPHER_ONLY              (0x8000)  /* bit 8 */

const MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT         (0x80)  /* bit 0 */
const MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER         (0x40)  /* bit 1 */
const MBEDTLS_X509_NS_CERT_TYPE_EMAIL              (0x20)  /* bit 2 */
const MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING     (0x10)  /* bit 3 */
const MBEDTLS_X509_NS_CERT_TYPE_RESERVED           (0x08)  /* bit 4 */
const MBEDTLS_X509_NS_CERT_TYPE_SSL_CA             (0x04)  /* bit 5 */
const MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA           (0x02)  /* bit 6 */
const MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA  (0x01)  /* bit 7 */*/

const MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER : &str = "MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER";
const MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER   : &str = "MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER";
const MBEDTLS_X509_EXT_KEY_USAGE                : &str = "MBEDTLS_OID_X509_EXT_KEY_USAGE";
const MBEDTLS_X509_EXT_CERTIFICATE_POLICIES     : &str = "MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES";
const MBEDTLS_X509_EXT_POLICY_MAPPINGS          : &str = "MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS";
const MBEDTLS_X509_EXT_SUBJECT_ALT_NAME         : &str = "MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME";         /* Supported (DNS) */
const MBEDTLS_X509_EXT_ISSUER_ALT_NAME          : &str = "MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME";
const MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS  : &str = "MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS";
const MBEDTLS_X509_EXT_BASIC_CONSTRAINTS        : &str = "MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS";        /* Supported */
const MBEDTLS_X509_EXT_NAME_CONSTRAINTS         : &str = "MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS";
const MBEDTLS_X509_EXT_POLICY_CONSTRAINTS       : &str = "MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS";
const MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE       : &str = "MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE";
const MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS  : &str = "MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS";
const MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY       : &str = "MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY";
const MBEDTLS_X509_EXT_FRESHEST_CRL             : &str = "MBEDTLS_OID_X509_EXT_FRESHEST_CRL";
const MBEDTLS_X509_EXT_NS_CERT_TYPE             : &str = "MBEDTLS_OID_X509_EXT_NS_CERT_TYPE";

const MBEDTLS_X509_FORMAT_DER                 : i32 = 1;
const MBEDTLS_X509_FORMAT_PEM                 : i32 = 2;

const MBEDTLS_X509_MAX_DN_NAME_SIZE         : i32 = 256; /* Maximum value size of a DN entry */




