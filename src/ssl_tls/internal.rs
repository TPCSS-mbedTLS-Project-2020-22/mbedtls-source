// file ssl_internal.h

use mbed::hashing::md_type_t;

struct sig_hash_set_t {
    rsa: md_type_t,
    ecdsa: md_type_t,
}


struct hs_buffer {
    is_valid: u32,

}

struct buffering {
    total_bytes_buffered: usize,
    seen_css: u8,

}
// This structure contains the params only needed during handshake
struct handshake_params {
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


    buffering: struct {
        total_bytes_buffered: usize,
    },


}
