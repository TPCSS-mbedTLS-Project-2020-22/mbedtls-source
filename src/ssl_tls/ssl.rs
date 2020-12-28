// From ssl.h


/*
 * This structure is used for storing current session data.
 *
 * Note: when changing this definition, we need to check and update:
 *  - in tests/suites/test_suite_ssl.function:
 *      ssl_populate_session() and ssl_serialize_session_save_load()
 *  - in library/ssl_tls.c:
 *      mbedtls_ssl_session_init() and mbedtls_ssl_session_free()
 *      mbedtls_ssl_session_save() and ssl_session_load()
 *      ssl_session_copy()
 */
struct session {
    // TODO define optional mbedtls_time_t start
    ciphersuite: i32,           // choosen ciphersuite
    compression: i32,           // chosen compression
    id_len: usize,              // session if length
    id: [char; 32],             // session identifier
    master: [char; 48],         // the master secret

    // TODO optional bunch of declarations in case MBEDTLS_C509_CRT_PARSE_C is defined
    // peer_cert_digest: std::vec::Vec, // the digest of the peer's end-CRT

    verify_result: u32,         // verification result

    // optional declarations if MBEDTLS_SSL_SESSION_TICKETS and MBEDTLS_SSL_CLI_C defined
    ticket: std::vec::Vec,      // RFC 5077 session ticket
    ticket_len: usize,          // session ticket length
    ticket_lifetime: u32,

    // optional if MBEDTLS_SSL_MAX_FRAGMENT_LENGTH defined
    mfl_code: std::vec::Vec,    // MaxFragmentLength negotiated by user

    // optional if MBEDTLS_SSL_TRUNCATED_HMAC defined
    trunc_hmac: i32,

    // optional if MBED_TLS_SSL_TRUNCATED_HMAC defined
    encrypt_then_mac: i32,
}

struct context {
    // TODO define *conf of type mbedtls_ssl_config

    state: i32,
    major_ver: i32,
    minor_ver: i32,
    // TODO optional function pointers f_verfy and p_verify verify X.509  certificate verification

    f_send: fn(),               // callback type: send data on the network
    f_recv: fn(),               // callback type: for network receive
    f_recv_timeout,             // callback fro network receive with timeout

    p_bio: std::ffi::c_void,    // Context for I/O operation

    // Session layer 
    session_in: session,
    session_out: session,
    session: session,
    session_negotiate: session,
}
