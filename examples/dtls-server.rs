extern crate mbed;

// You may run this program with the command ~ cargo run --example dtls-server

/*
 * This is the example tls server file. I am commenting out all the function calls needed in the
 * sequence they are called in the original demo program.
 * NOTE: Most of the functions are very simple like the init functions. All the seemingly
 * complicated functions are preceeded with an asterix(*) eg. *mbed::ssl::cookie_setup().
 * I suggest that we implement the functions as they appear in this program rather than
 * implementing all the functions within a file taken up by a team.
 *
 * Also, the functionality in the dtls-client is almost similar, so we can start with that once
 * all the methods for the server is implemented
 */

/*
 * The benefit of this approach is that we will have a working demo of a tls client and server at
 * the end of this task.
 */

fn main() {
    // Just a test function
    mbed::ssl_tls::foo();

    // TODO Declare Variable
    println!("TODO: Declare variables");
    let mut cookie_ctx: mbed::ssl_tls::cookie::cookie_ctx;
    // TODO declare entropy and ctr_drbg context contact Hiren Kumar Saha and Mahesh Kumar

    let mut ssl: mbed::ssl_tls::ssl::context;
    let mut conf: mbed::ssl_tls::ssl::config;
    
    // TODO following init functions
    // mbed::net::init() -> net_socket.c
    // mbed::ssl::init() ->  ssl_tls.c
    // mbed::ssl::config_init() -> ssl_tls.c
    // mbed::ssl::cookie::init() -> ssl_cookie.c
    // mbed::x509::crt_init()  -> x509_crt.c
    // mbed::pk::init()  -> pk.c
    // mbed::entropy::init() -> entropy.c
    // mbed::ctr::drbg::init() -> ctr_drbg.c

    /*
     * TODO 1. Load the certificates and private RSA key
     */
    println!("TODO: 1. Load the certificates and private RSA key");
    // mbed::x509::crt_parse()  -> x509_crt.c
    // mbed::pk::parse_key()  -> pkparse.c


    /*
     * TODO 2. Setup the "listening" UDP socket
     */
    println!("TODO: 2. Setup the listening UDPP socket");
    // mbed::net::bind()  -> net_sockets.c
    // mbed::ctr::drbg::seed() -> ctr_drbg.c  // seeding the random generator
    // mbed::ssl::config_defaults()  -> ssl_tls.c  // setting up dtls data
    // mbed::ssl::conf_rng( callback mbed::ctr::drbg::random)  -> ssl_tls.c & ctr_drbg.c
    // mbed::ssl::conf_dbg() -> ssl_tls.c
    // mbed::ssl::conf_ca_chain() -> ssl_tls.c
    // mbed::ssl::conf_own_cert() -> ssl_tls.c

    // NOTE: this function is seemingly complex so is preceeded by an asterix
    // *mbed::ssl::cookie_setup(callback mbed::ctr::drbg::random) -> ssl_cookie.c 

    // mbed::ssl::conf_dtls_cookies() -> ssl_serv.c // NOTE: even though function pointers passed as parameters they are only assigned to the fields not called
    // mbed::ssl::setup()
    // *mbed::ssl::set_timer_cb() -> ssl_tls.c
    // mbed::net::free() -> net_sockets.c

    // *mbed::ssl::session_reset() -> ssl_tls.c calls a seemingly complicated function,
    // mbedtls_ssl_session_reset_int in the same file that reset an initialized and used SSL context
    // for reuse while retaining all application-set variables

    // TODO: 3. Wait for remote connection ...
    println!("TODO: 3. Wait for remote connection ... ");
    // *mbed:net::accept() -> net_sockets.c   // NOTE: mostly calls socket library files

    // TODO: 4. Hello verify request cookie
    // mbed::ssl::set_client_transport_id() -> ssl_srv.c
    // mbed::ssl::set_bio()

    // TODO: 5. Handshake: Heavy lifting starts here
    println!("TODO: 5. Handshake: Heavy lifting starts here");
    // *mbed::ssl::handshake()   -> ssl_tls.c
    // NOTE: this function calls mbed_ssl_hanshake_step  which in turn calls either
    // mbedtls_ssl_handshake_client_step in ssl_cli.c for the client or
    // mbed_ssl_handshake_server_step in ssl_srv.c for the server(only this function needed for server)

    // NOTE: Extreme heavy lifting : mbed_ssl_handshake_server_step calls all these functions
    // ssl_flight_transmit -> ssl_msg.c
    // ssl_parse_client_hello -> ssl_msg.c
    // ssl_write_server_hello -> ssl_srv.c
    // mbedtls_ssl_write_certificate -> ssl_srv.c
    // ssl_write_server_key_exchange( ssl );
    // ssl_write_certificate_request( ssl );
    // ssl_write_server_hello_done( ssl );
    // mbedtls_ssl_parse_certificate( ssl );
    // ssl_parse_client_key_exchange( ssl );
    // ssl_parse_certificate_verify( ssl );
    // mbedtls_ssl_parse_change_cipher_spec( ssl );
    // mbedtls_ssl_parse_finished( ssl );
    // mbedtls_ssl_write_change_cipher_spec( ssl );
    // mbedtls_ssl_write_finished( ssl );
    // mbedtls_ssl_handshake_wrapup( ssl );


    // TODO: 6. Read the echo request
    println!("TODO: 6. Read the echo request");
    // mbed:ssl::read() -> ssl_msg.c

    // TODO: 7. Write the 200 response
    println!("TODO: 7. Write the 200 response");
    // mbed::ssl::write() -> ssl_msg.c

    // TODO: 8. Done, Cleanly close the connection
    println!("TODO: 8. Done, Cleanly close the connection");
    // NOTE: Small functions called the free the memory and close connections, these tasks may be
    // skipped for the end.

}


