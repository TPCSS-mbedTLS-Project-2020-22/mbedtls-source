use mbed::tcp_ip;
use std::{env, thread};

fn main() {
    //Extract protocol
    let args: Vec<String> = env::args().collect();
    let proto_str = (&args[1]).to_uppercase(); // TCP/UDP
    let proto = match &proto_str[..] {
        "TCP" => tcp_ip::TLProtocol::TCP,
        "UDP" => tcp_ip::TLProtocol::UDP,
        _ => panic!("Undefined Protocol"),
    };

    println!("\nStarting {} SERVER...\n", proto_str);

    //Initialize context
    let mut context = tcp_ip::MbedtlsNetContext::new(proto);

    println!("Trying to open a {} socket...", proto_str);
    let ret = tcp_ip::mbedtls_net_bind(&mut context, "127.0.0.1", "4442", &proto);
    if ret != tcp_ip::MBEDTLS_NET_OPER_SUCCESS {
        println!("Failed to create socket.");
    } else {
        match &proto_str[..] {
            "TCP" => 
            loop {
                let mut context_client = tcp_ip::MbedtlsNetContext::new(proto);
                tcp_ip::mbedtls_net_accept(&mut context, &mut context_client);

                thread::spawn(move || loop {
                    let mut buf: [u8; 512] = [0; 512];

                    let ret = tcp_ip::mbedtls_net_recv(&mut context_client, &mut buf, 512);
                    if ret != tcp_ip::MBEDTLS_NET_OPER_SUCCESS {
                        println!("Connection terminated with client.");
                        break;
                    }
                    println!("Message received: {}", String::from_utf8_lossy(&buf));

                    let ret = tcp_ip::mbedtls_net_send(&mut context_client, &buf);
                    if ret != tcp_ip::MBEDTLS_NET_OPER_SUCCESS {
                        println!("Failed to echo message.");
                        break;
                    }
                });
            } ,
            "UDP" => loop {
                let mut context_client = tcp_ip::MbedtlsNetContext::new(proto);
                tcp_ip::mbedtls_net_accept(&mut context, &mut context_client);

                let mut buf: [u8; 512] = [0; 512];

                let ret = tcp_ip::mbedtls_net_recv(&mut context_client, &mut buf, 512);
                if ret != tcp_ip::MBEDTLS_NET_OPER_SUCCESS {
                    println!("Connection terminated with client.");
                    break;
                }
                println!("Message received: {}", String::from_utf8_lossy(&buf));

                let ret = tcp_ip::mbedtls_net_send(&mut context_client, &buf);
                if ret != tcp_ip::MBEDTLS_NET_OPER_SUCCESS {
                    println!("Failed to echo message.");
                    break;
                }
            },
            _ => {}
        };
    }

    println!("Server exiting...\n");
}
