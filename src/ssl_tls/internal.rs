// file ssl_internal.h
use crate::hashing::MdTypeT;
use crate::ssl_tls;

const MBEDTLS_SSL_MAX_BUFFERED_HS: usize =  4;



#[allow(non_camel_case_types)]
struct sig_hash_set_t {
    rsa: MdTypeT,
    ecdsa: MdTypeT,
}

#[allow(non_camel_case_types)]
#[allow(dead_code)]
struct hs_buffer {
    is_valid: u32,
    is_fragmented: u32,
    is_complete: u32,
    data: String,
    data_len: usize,
}

impl Default for hs_buffer {
    fn default() -> hs_buffer {
        hs_buffer {
            is_valid: 1,
            is_fragmented: 1,
            is_complete: 1,
            data: String::new(),
            data_len: 0,
        }

    }
}

#[allow(non_camel_case_types)]
#[allow(dead_code)]
struct future_record {
    data: String,
    len: usize,
    epoch: u32,
}
#[allow(non_camel_case_types)]
#[allow(dead_code)]
struct buffering {
    total_bytes_buffered: usize,
    seen_css: u8,
    hs: [hs_buffer; MBEDTLS_SSL_MAX_BUFFERED_HS],
    future_record: future_record,
}


// This structure contains the params only needed during handshake
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub struct handshake_params {
    /*
     * Handshake specific crypto variables
     */
    //optional if MBEDTLS_SSL_PROTO_TLS1_2 and MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED
    hash_algs: sig_hash_set_t,  // set of suitable sig-hash pairs

    // optional if MBEDTLS_DHM_C defined
    // dhm_ctx:                    // TODO implement mbedtls_dhm_context struct in dhm.h for DHM key exchange

    // optional declaration for MBEDTLS_ECDH_C OR MBEDTLS_ECDSA_C
             // optional declarations for MBEDTLS_USE_PSA_CRYPTO

    // optional declarations for MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
             // optional declarations for MBEDTLS_SSL_CLI_C


    // many other optional declarations


    buffering: buffering,
    mtu: u16,


    // some more optional declarations pertaining to checksum contexts


    update_checksum: fn(&ssl_tls::ssl::context, &str, usize),

}
