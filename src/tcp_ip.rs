/*
* Network sockets abstraction layer to integrate Mbed TLS into a
* BSD-style sockets API
*/

/* 
* Author : Shashank Singh 
*/


// Notes :
// 1. To check the function call parameters : I am not sure what datatypes to use for ports, ips, protocols

// Listing macros/constants

const MBEDTLS_ERR_NET_SOCKET_FAILED         : i16 = -0x0042 ; // Failed to open a socket. 
const MBEDTLS_ERR_NET_CONNECT_FAILED        : i16 = -0x0044 ; // The connection to the given server / port failed. 
const MBEDTLS_ERR_NET_BIND_FAILED           : i16 = -0x0046 ; // Binding of the socket failed. 
const MBEDTLS_ERR_NET_LISTEN_FAILED         : i16 = -0x0048 ; // Could not listen on the socket. 
const MBEDTLS_ERR_NET_ACCEPT_FAILED         : i16 = -0x004A ; // Could not accept the incoming connection. 
const MBEDTLS_ERR_NET_RECV_FAILED           : i16 = -0x004C ; // Reading information from the socket failed. 
const MBEDTLS_ERR_NET_SEND_FAILED           : i16 = -0x004E ; // Sending information through the socket failed. 
const MBEDTLS_ERR_NET_CONN_RESET            : i16 = -0x0050 ; // Connection was reset by peer. 
const MBEDTLS_ERR_NET_UNKNOWN_HOST          : i16 = -0x0052 ; // Failed to get an IP address for the given hostname. 
const MBEDTLS_ERR_NET_BUFFER_TOO_SMALL      : i16 = -0x0043 ; // Buffer is too small to hold the data. 
const MBEDTLS_ERR_NET_INVALID_CONTEXT       : i16 = -0x0045 ; // The context is invalid, eg because it was free()ed. 
const MBEDTLS_ERR_NET_POLL_FAILED           : i16 = -0x0047 ; // Polling the net context failed. 
const MBEDTLS_ERR_NET_BAD_INPUT_DATA        : i16 = -0x0049 ; // Input invalid. 


const MBEDTLS_NET_LISTEN_BACKLOG            : i16 =  10     ; // The backlog that listen() should use. 
const MBEDTLS_NET_PROTO_TCP                 : i16 =  0      ; // The TCP transport protocol 
const MBEDTLS_NET_PROTO_UDP                 : i16 =  1      ; // The UDP transport protocol 
const MBEDTLS_NET_POLL_READ                 : i16 =  1      ; // Used in mbedtls_net_poll to check for pending data  
const MBEDTLS_NET_POLL_WRITE                : i16 =  2      ; // Used in mbedtls_net_poll to check if write possible 



/// Wrapper type for sockets.
/// Currently backed by just a file descriptor, but might be more in the future
/// (eg two file descriptors for combined IPv4 + IPv6 support, or additional
/// structures for hand-made UDP demultiplexing). 
struct mbedtls_net_context {
    fd: i32
}


/// Initialize a context
/// Just makes the context ready to be used or freed safely.
fn mbedtls_net_init() {

}


/// Initiate a connection with host:port in the given protocol
fn mbedtls_net_connect(ctx: mbedtls_net_context, host:String, port:String, proto:i32 ) -> i32 {
    1
}


/// Create a receiving socket on bind_ip:port in the chosen
/// protocol. If bind_ip == NULL, all interfaces are bound.
fn mbedtls_net_bind(ctx: mbedtls_net_context, host:String, port:String, proto:i32) -> i32 {
    1
}