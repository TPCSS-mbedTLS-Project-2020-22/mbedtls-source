//just to do a sanity check 
mod cipher;
use crate::cipher::blowfishc::mbedtls_blowfish_crypt_ctr;
use crate::cipher::blowfishc::mbedtls_blowfish_crypt_cfb64;
use crate::cipher::blowfish_header::MBEDTLS_BLOWFISH_BLOCKSIZE;
use crate::cipher::blowfishc::mbedtls_blowfish_crypt_cbc;
use crate::cipher::blowfish_header::MBEDTLS_BLOWFISH_ENCRYPT;
use crate::cipher::blowfish_header::MBEDTLS_BLOWFISH_DECRYPT;
use crate::cipher::blowfish_header::mbedtls_blowfish_context;
use cipher::blowfishc::get_uint32_be;
use cipher::blowfishc::put_uint32_be;

fn main() {
    let mut n:u32=0;
    let mut b:[u8;8]=[1,2,3,4,5,6,7,8];
    let i:usize=0;
    get_uint32_be(&mut n,&mut b,i);
    println!("{:b}",n);
    b=[0,0,0,0,0,0,0,0];
    put_uint32_be(n,&mut b,i);
    println!("{:?}",b);
    println!("{:?}",cipher::blowfishc::P);
    let mut ctx:&mut mbedtls_blowfish_context=& mut mbedtls_blowfish_context{
        P:cipher::blowfishc::P,
        S:cipher::blowfishc::S,
    };
    let mut xl:u32=0x3AC372E6;
    let mut xr:u32=0xCE77E25B;
    cipher::blowfishc::blowfish_enc(&mut ctx,&mut xl,&mut xr);
    println!("{:x} {:x}",xl,xr);
    cipher::blowfishc::blowfish_dec(&mut ctx,&mut xl,&mut xr);
    println!("{:x} {:x}",xl,xr);
    //println!("{}",F(&mut ctx,n));
    cipher::blowfishc::mbedtls_blowfish_init(&mut ctx);
    println!("{:?}",ctx.P);
    cipher::blowfishc::mbedtls_blowfish_setkey(&mut ctx,"10010110001110101001011000111010",32);
    println!("{:?}",ctx.P);
    b=[49, 50, 51, 52, 53, 54, 55, 56];
    let mut c:[u8;8]=[0,0,0,0,0,0,0,0];
    println!("{:?}",b);
    cipher::blowfishc::mbedtls_blowfish_crypt_ecb(&mut ctx,MBEDTLS_BLOWFISH_ENCRYPT, b,&mut c);
    println!("{:?}",c);
    let mut d:[u8;8]=[0,0,0,0,0,0,0,0];
    cipher::blowfishc::mbedtls_blowfish_crypt_ecb(&mut ctx,MBEDTLS_BLOWFISH_DECRYPT, c,&mut d);
    println!("{:?}",d);
    crate::cipher::blowfish_header::run();
    let mut iv:  [char;MBEDTLS_BLOWFISH_BLOCKSIZE]=['1','2','3','4','5','6','7','8'];
    let mut k= String::from("ijklmnopijklmnop");
    //out="hmm";

    mbedtls_blowfish_crypt_cbc(&mut ctx,MBEDTLS_BLOWFISH_ENCRYPT,16,&mut iv,String::from("abcdefgh[]||tuvw"),&mut k);
    println!("{:?}",k);
    let mut k1= String::from("ijklmnopijklmnop");
    iv=['1','2','3','4','5','6','7','8'];
    mbedtls_blowfish_crypt_cbc(&mut ctx,MBEDTLS_BLOWFISH_DECRYPT,16,&mut iv,k,&mut k1);
    println!("{:?}",k1);
    let mut ivoff:usize=0;
    iv=['1','2','3','4','5','6','7','8'];
    mbedtls_blowfish_crypt_cfb64(&mut ctx,MBEDTLS_BLOWFISH_ENCRYPT,16,&mut iv,&mut ivoff,String::from("abc\ne,%7pqrstuvw"),&mut k1);
    println!("{:?} {:?}",k1,iv);
    let mut k2= String::from("ijklmnopijklmnop");
    iv=['1','2','3','4','5','6','7','8'];
    mbedtls_blowfish_crypt_cfb64(&mut ctx,MBEDTLS_BLOWFISH_DECRYPT,16,&mut iv,&mut ivoff,k1,&mut k2);
    println!("{:?} {:?}",k2,iv);
    let mut nonc:  [char;MBEDTLS_BLOWFISH_BLOCKSIZE]=['0','2','3','8','5','6','7','8'];
    iv=['1','2','3','4','5','6','7','8'];
    let mut k3= String::from("ijklmnopijklmnopabcdefgh[]||tuvw");
    let mut noff:usize=0;
    mbedtls_blowfish_crypt_ctr(&mut ctx,32,&mut noff,&mut nonc,&mut iv,String::from("abcdefg@*&rstuvwabcdefgh[]||tuvw"),&mut k3);
    println!("{:?} {:?}",k3,nonc);
    let mut k4= String::from("ijklmnopijklmnopabcdefgh[]||tuvw");
    noff=0;
    nonc=['0','2','3','8','5','6','7','8'];
    mbedtls_blowfish_crypt_ctr(&mut ctx,32,&mut noff,&mut nonc,&mut iv,k3,&mut k4);
    println!("{:?} {:?}",k4,nonc);
    cipher::chacha20::run();
}
