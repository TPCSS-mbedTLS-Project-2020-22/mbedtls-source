/*
* Network sockets abstraction layer to integrate Mbed TLS into a
* BSD-style sockets API
*/

/*
* Author : Shashank Singh
*/

// Notes :
// 1. To check the function call parameters : I am not sure what datatypes to use for ports, ips, protocols

use std::io::{self, BufRead, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket, Shutdown};
use std::str::FromStr;

// Listing any Global macros needed
// SS: These will have to be moved to a single common global errors file
// const MBEDTLS_ERR_ERROR_GENERIC_ERROR: i16 = -0x0001; // Denotes a generic error
const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED: i16 = -0x006E; // Denotes a bug in library
pub const MBEDTLS_NET_OPER_SUCCESS: i16 = 0; // Denotes a successful operation

// Listing macros/constants

// const MBEDTLS_ERR_NET_SOCKET_FAILED: i16 = -0x0042; // Failed to open a socket.
// const MBEDTLS_ERR_NET_CONNECT_FAILED: i16 = -0x0044; // The connection to the given server / port failed.
// const MBEDTLS_ERR_NET_BIND_FAILED: i16 = -0x0046; // Binding of the socket failed.
// const MBEDTLS_ERR_NET_LISTEN_FAILED: i16 = -0x0048; // Could not listen on the socket.
// const MBEDTLS_ERR_NET_ACCEPT_FAILED: i16 = -0x004A; // Could not accept the incoming connection.
// const MBEDTLS_ERR_NET_RECV_FAILED: i16 = -0x004C; // Reading information from the socket failed.
// const MBEDTLS_ERR_NET_SEND_FAILED: i16 = -0x004E; // Sending information through the socket failed.
// const MBEDTLS_ERR_NET_CONN_RESET: i16 = -0x0050; // Connection was reset by peer.
// const MBEDTLS_ERR_NET_UNKNOWN_HOST: i16 = -0x0052; // Failed to get an IP address for the given hostname.
// const MBEDTLS_ERR_NET_BUFFER_TOO_SMALL: i16 = -0x0043; // Buffer is too small to hold the data.
// const MBEDTLS_ERR_NET_INVALID_CONTEXT: i16 = -0x0045; // The context is invalid, eg because it was free()ed.
// const MBEDTLS_ERR_NET_POLL_FAILED: i16 = -0x0047; // Polling the net context failed.
// const MBEDTLS_ERR_NET_BAD_INPUT_DATA: i16 = -0x0049; // Input invalid.
// const MBEDTLS_NET_LISTEN_BACKLOG: i16 = 10; // The backlog that listen() should use.
// const MBEDTLS_NET_PROTO_TCP: i16 = 0; // The TCP transport protocol
// const MBEDTLS_NET_PROTO_UDP: i16 = 1; // The UDP transport protocol
// const MBEDTLS_NET_POLL_READ: i16 = 1; // Used in mbedtls_net_poll to check for pending data
// const MBEDTLS_NET_POLL_WRITE: i16 = 2; // Used in mbedtls_net_poll to check if write possible



/// Internal Wrapper type for underlying transport layer protocol in the context
#[derive(Debug, Copy, Clone)] //rustc --explain E0382
pub enum TLProtocol {
    TCP,
    UDP,
}

/// Wrapper type for sockets
/// Currently backed by just a file descriptor, but might be more in the future
/// (eg two file descriptors for combined IPv4 + IPv6 support, or additional
/// structures for hand-made UDP demultiplexing)
/// Rust : SS : Replaced fd by a tcpListener object in context
pub struct MbedtlsNetContext {
    pub protocol: Option<TLProtocol>, 
    tcp_listener: Option<TcpListener>,
    pub tcp_stream: Option<TcpStream>,
    tcp_stream_remote_addr: Option<SocketAddr>,
    udp_socket: Option<UdpSocket>,
    udp_socket_remote_addr: Option<SocketAddr>,
}

impl MbedtlsNetContext {
    pub fn new(proto: TLProtocol) -> Self {
        MbedtlsNetContext {
            protocol: Some(proto),
            tcp_listener: None,
            tcp_stream: None,
            tcp_stream_remote_addr: None,
            udp_socket: None,
            udp_socket_remote_addr: None,
        }
    }
}

// Initialize a context
// Just makes the context ready to be used or freed safely.
// No need of this in Rust
// fn mbedtls_net_init(ctx : &mut mbedtls_net_context) {
//     ctx.tcpListener = NULL;
// }

/// Initiate a connection with host:port in the given protocol
/// SS : host might need DNS resolution
/// SS : get an address list after resolution, and try to connect to all addresses in the list
pub fn mbedtls_net_connect(
    ctx: &mut MbedtlsNetContext,
    host: &str,
    port: &str,
    proto: &TLProtocol,
) -> i16 {
    let mut ret_value = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    // SS : Assuming host and port to be valid numerics
    let ip_addr = IpAddr::from_str(host).unwrap();
    let port: u16 = port.parse().unwrap();
    let sock_addr = SocketAddr::new(ip_addr, port);

    match proto {
        TLProtocol::TCP => {
            ctx.tcp_stream = match TcpStream::connect(sock_addr) {
                Ok(tcp_stream) => {
                    println!("Connected to server at {}", sock_addr);
                    ret_value = MBEDTLS_NET_OPER_SUCCESS;
                    Some(tcp_stream)
                }
                Err(e) => panic!(e),
            };
        },
        TLProtocol::UDP => {

            //Find free local port for client
            let mut found: bool = false;
            for p in 1025..65535 {
                ctx.udp_socket = match UdpSocket::bind(("127.0.0.1", p)) {
                    Ok(udp_socket) => {
                        found = true;
                        Some(udp_socket)
                    },
                    _ => None,
                };

                if found == true {
                    println!("UDP Client bound to 127.0.0.1:{}", p);                    
                    break;
                }
            }

            //Connect to sever
            let udp_socket = ctx.udp_socket.as_ref().unwrap();
            match udp_socket.connect(sock_addr) {
                Ok(()) => {
                    println!("Connected to server at {}", sock_addr);
                    ctx.udp_socket_remote_addr = Some(sock_addr);
                    ret_value = MBEDTLS_NET_OPER_SUCCESS
                },
                Err(e) => panic!(e),
            };
        }
    };

    ret_value
}

/// Create a receiving socket on bind_ip:port in the chosen
/// protocol. If bind_ip == NULL, all interfaces are bound.
pub fn mbedtls_net_bind(
    ctx: &mut MbedtlsNetContext,
    host: &str,
    port: &str,
    proto: &TLProtocol,
) -> i16 {
    //Defaul error code
    let mut ret_value = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    //Create socket address
    let ip_addr = IpAddr::from_str(host).unwrap(); // SS : Assuming host and port to be valid numerics
    let port: u16 = port.parse().unwrap();
    let sock_addr = SocketAddr::new(ip_addr, port);

    //Bind socket address and return a Server socket
    match proto {
        TLProtocol::TCP => {
            ctx.tcp_listener = match TcpListener::bind(sock_addr) {
                Ok(tcp_listener) => {
                    println!("TCP Server listening at {}", sock_addr);
                    ret_value = MBEDTLS_NET_OPER_SUCCESS;
                    Some(tcp_listener)
                }
                Err(e) => panic!(e),
            };
        }
        TLProtocol::UDP => {
            ctx.udp_socket = match UdpSocket::bind(sock_addr) {
                Ok(udp_socket) => {
                    println!("UDP Server listening at {}", sock_addr);
                    ret_value = MBEDTLS_NET_OPER_SUCCESS;
                    Some(udp_socket)
                }
                Err(e) => panic!("{:?}",e),
            }
        }
    };

    ret_value
}

pub fn mbedtls_net_accept(
    listener_ctx: &mut MbedtlsNetContext,
    client_ctx: &mut MbedtlsNetContext,
) -> i16 {
    //Defaul error code
    let mut ret_value = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    match listener_ctx.protocol.as_ref().unwrap() {
        TLProtocol::TCP => {
            println!("Waiting for a remote TCP client to connect ");

            match &listener_ctx.tcp_listener {                       //Why & ?
                Some(tcp_listener) => {
                    match tcp_listener.accept() {
                        Ok((stream, addr)) => {
                            println!("Remote host connected {}", addr);

                            client_ctx.tcp_stream = Some(stream);
                            client_ctx.tcp_stream_remote_addr = Some(addr);

                            ret_value = MBEDTLS_NET_OPER_SUCCESS;
                        }
                        Err(e) => panic!("Couldn't get client: {:?}", e),
                    }
                },
                None => panic!("Accept called on null listener!"),
            }
        },
        TLProtocol::UDP => {
            println!("Waiting for a UDP remote host to connect ");

            match &listener_ctx.udp_socket {
                Some(udp_socket) => {
                    let mut buf: [u8; 1] = [0; 1];

                    match udp_socket.peek_from(&mut buf) {
                        Ok((_bytes, addr)) => {
                            println!("Remote host connected {}", addr);

                            //Clone listen socket
                            let listen_socket = listener_ctx.udp_socket.as_ref().unwrap();
                            client_ctx.udp_socket = Some(listen_socket.try_clone().unwrap());
                            client_ctx.udp_socket_remote_addr = Some(addr);

                            ret_value = MBEDTLS_NET_OPER_SUCCESS;
                        },
                        Err(e) => panic!("couldn't get client: {:?}", e),
                    }
                },
                None => panic!("Accept called on null listener!"),
            }
        }
    };

    ret_value
}

pub fn mbedtls_net_send(ctx: &MbedtlsNetContext, msg: &[u8]) -> i16 {
    let mut ret_value = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    match ctx.protocol.as_ref().unwrap() {
        TLProtocol::TCP => {
            let mut tcp_stream = ctx.tcp_stream.as_ref().unwrap();

            let _bytes_sent = match tcp_stream.write_all(msg) {
                Ok(_bytes) => _bytes,
                Err(e) => {}, //panic!(e),
            };

            tcp_stream.flush();
            ret_value = MBEDTLS_NET_OPER_SUCCESS;
        },
        TLProtocol::UDP => {
            let udp_socket = ctx.udp_socket.as_ref().unwrap();


            let _bytes_sent = match udp_socket.send_to( msg,
                                                        ctx.udp_socket_remote_addr.unwrap()) {
                Ok(_bytes) => _bytes,
                Err(e) => panic!(e),
            };

            ret_value = MBEDTLS_NET_OPER_SUCCESS;
        }
    };

    ret_value
}


pub fn mbedtls_net_recv(
    ctx: &MbedtlsNetContext,
    recv_buf: &mut [u8],
    max_read_bytes_len: u32,
) -> i16 {
    let mut ret_value = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    match ctx.protocol.as_ref().unwrap()  {
        TLProtocol::TCP => {
            let mut tcp_stream = ctx.tcp_stream.as_ref().unwrap();


            // Read current current data in the TcpStream
            let mut reader = io::BufReader::new(&mut tcp_stream);
            let received_bytes_buffer: &[u8] = reader.fill_buf().unwrap();

            if(received_bytes_buffer.len() > 0){

                // Read at most 'read_bytes_len' bytes from the buffer
                let mut bytes_to_consume = max_read_bytes_len;
                if received_bytes_buffer.len() < max_read_bytes_len as usize {
                    bytes_to_consume = received_bytes_buffer.len() as u32;
                }
                for i in 0..bytes_to_consume {
                    recv_buf[i as usize] = received_bytes_buffer[i as usize];
                }

                // Mark the bytes read as consumed so the buffer will not return them in a subsequent read
                reader.consume(bytes_to_consume as usize);
                
                ret_value = MBEDTLS_NET_OPER_SUCCESS;
            }
        }
        TLProtocol::UDP => {
            let udp_socket = ctx.udp_socket.as_ref().unwrap();

            //TODO: check remote address as well, before receiving.
            udp_socket.recv(recv_buf).expect("Failed to write to server");

            ret_value = MBEDTLS_NET_OPER_SUCCESS;
        }
    };

    ret_value
}


/// Gracefully close the connection i.e. stop read or write or both operations. 
/// Rust doesn't implement close.
/// Don't know the use of this function, implemented just to maintain interface compatibility
pub fn mbedtls_net_free(
    ctx: &mut MbedtlsNetContext
) -> i16{
    let mut ret_value = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    match ctx.protocol.as_ref().unwrap()  {
        TLProtocol::TCP => {
            if !ctx.tcp_stream.is_none() {
                let tcp_stream = ctx.tcp_stream.as_ref().unwrap();
                tcp_stream.shutdown(Shutdown::Both).expect("shutdown call failed");
                ret_value = MBEDTLS_NET_OPER_SUCCESS;
            }
        }

        TLProtocol::UDP => {
            // there is nothing to close in UDP
            ret_value = MBEDTLS_NET_OPER_SUCCESS;
        }
    }

ret_value
}

/// Don't know the use of this function, implemented just to maintain interface compatibility
/// Simply calls the mbedtls_net_free function
pub fn mbedtls_net_close(
    ctx: &mut MbedtlsNetContext
)-> i16{
mbedtls_net_free(ctx)
}

pub fn print() {
    println!("Hey, inside tcp_ip library..!");
}

//sudo lsof -i -P -n | grep UDP
