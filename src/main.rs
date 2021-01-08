use mbed::net_sockets;
use std::env;

fn main() {

    //Extract 'protocol' and 'mode' of operation
    let args: Vec<String> = env::args().collect();
    let proto_str = (&args[1]).to_uppercase();        // tcp/udp
    let mode = (&args[2]).to_uppercase();             // server/client
    let msg = (&args[3])[..].as_bytes();

    let proto = match &proto_str[..] {
        "TCP" => net_sockets::TLProtocol::TCP,
        "UDP" => net_sockets::TLProtocol::UDP,
        _ => panic!("Undefined Protocol"),
    };


    println!("\nStarting {} {}...\n", proto_str, mode);

    //Initialize context
    let mut context = net_sockets::MbedtlsNetContext::new(proto);
    // match context.protocol.unwrap() {
    //     net_sockets::TLProtocol::TCP => println!("TCP"),
    //     net_sockets::TLProtocol::UDP => println!("UDP")
    // }


    if mode.eq_ignore_ascii_case("SERVER") {

        println!("Trying to open a {} socket", proto_str);
        net_sockets::mbedtls_net_bind(&mut context, "127.0.0.1", "4442", &proto);

        loop{
            let mut context_client = net_sockets::MbedtlsNetContext::new(proto);
            net_sockets::mbedtls_net_accept(&mut context, &mut context_client);
            
            let mut buf: [u8; 512] = [0; 512];

            net_sockets::mbedtls_net_recv(&mut context_client, &mut buf, 6); 
            println!("Received message : {}", String::from_utf8_lossy(&buf));

            net_sockets::mbedtls_net_send(&mut context_client, msg); 
            println!("Sent response message to client : {:}", String::from_utf8_lossy(&msg));
        }
    } 
    else if mode.eq_ignore_ascii_case("CLIENT") {
        println!("Trying to connect to the open socket");
        net_sockets::mbedtls_net_connect(&mut context, "127.0.0.1", "4442", &proto);

        let mut buf: [u8; 512] = [0; 512];

        println!("Sending message to server : {}", String::from_utf8_lossy(&msg));
        net_sockets::mbedtls_net_send(&mut context, msg);

        net_sockets::mbedtls_net_recv(&mut context, &mut buf, 7); 
        println!("Received response from server : {}", String::from_utf8_lossy(&buf));
    }
    

    // println!("Press enter to end the program : ");
    // let mut line = String::new();
    // let b1 = std::io::stdin().read_line(&mut line).unwrap();
}
