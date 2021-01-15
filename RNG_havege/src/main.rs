//HAVEGE: HArdware Volatile Entropy Gathering and Expansion
// This module generate random data into a file (data.txt in this case)
mod havege;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::mem;

fn main() {
    let len:usize = havege::MBEDTLS_HAVEGE_COLLECT_SIZE;
    let mut hs = havege::mbedtls_havege_state::new(0,0,[0;2],[0;1024],[0;8192]);
    
    let path = Path::new("data.txt");
    let display = path.display();
    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => file,
    };
    havege::initialise(&mut hs);
    for i in 1..768{
        let mut buff = String::from("hello");
        havege::havege_random(&mut hs,&mut buff,len);
        
        match file.write_all(buff.as_bytes()) {
            Err(why) => panic!("couldn't write to {}: {}", display, why),
            Ok(_) => println!("successfully wrote to {}", display),
        }
    }
    mem::forget(hs);
}