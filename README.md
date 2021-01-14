README
## TCP/IP (net_sockets) Module Specific Documentation

### Contributors
* Aman Choudhary - amanc@iisc.ac.in
* Shashank Singh - shashanksing@iisc.ac.in

### Module Intro
This module provides Network Sockets Abstraction Layer to integrate Mbed TLS into a BSD-style sockets API. Provides a context based interface for quickly setting up underlying Transport Layer protocol (TCP or UDP) for application layer use. To be consumed by SSL/TLS module.


### Trying it out
The main.rs file contains an implementation of a test server and a test client that can be used to check the sanity of the underlying library (tcp_ip.rs).

* To run the test server - cargo run [TCP/UDP] SERVER <MESSAGE TO BE SENT IN RESPONSE WHEN A CLIENT CONNECTS TO SERVER> 
  Example - cargo run TCP SERVER WELCOME
  The server will run and wait for new connections. It will print the messages received from client and then send a response message to them.
  
* To run an instance of a test client - cargo run [TCP/UDP] CLIENT <MESSAGE TO BE SENT AS A GREETING TO SERVER> 
  Example - cargo run TCP CLIENT HELLO
  The client will send a HELLO message, wait for a response from server - prints the response and exits.


### List of macros and datatypes defined
* MbedtlsNetContext - Wrapper type for sockets. Abstraction to remember the context the user is referring to while doing Transport Layer operations.
* TLProtocol - An enum type specifying the protocols allowed for the users.
* Error Types 
  * MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED - Generic error in library implementation
  * MBEDTLS_NET_OPER_SUCCESS - Operation Succeeded

  
### List of library methods implemented
* mbedtls_net_connect - Initiate a connection with host:port in the specified protocol
* mbedtls_net_bind - Create a receiving socket on bind_ip:port in the specified protocol
* mbedtls_net_accept - Accept a connection on a listening socket (TCP) or wait for a message on the socket (UDP)
* mbedtls_net_send - Send a message in the stream (TCP) or the socket (UDP)
* mbedtls_net_recv - Read/Receive a message from the stream (TCP) or call recv on UDP socket
* mbedtls_net_free - Gracefully give up read/write in the context (TCP) or do nothing (UDP)
* mbedtls_net_close - Simply calls mbedtls_net_free within itself
