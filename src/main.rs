//Added by Aman: Test library use

use std::env;
use mbed::tcp_ip;

fn main(){
    tcp_ip::print();

    let args: Vec<String> = env::args().collect();

    let operation = &args[1];

    println!("You have asked for operation : {}", operation);

    if(operation.eq_ignore_ascii_case("bind")) {
        println!("Trying to open a TCP socket");
        let mut context = tcp_ip::MbedtlsNetContext::new();
        tcp_ip::mbedtls_net_bind(&mut context, "127.0.0.1", "4442", &2);
    }
    
    else if(operation.eq_ignore_ascii_case("connect")){
        println!("Trying to connect to the open socket");
        let mut context = tcp_ip::MbedtlsNetContext::new();

        
    }


    println!("Press enter to end the program : ");
    let mut line=String::new();
    let b1 = std::io::stdin().read_line(&mut line).unwrap();   
}