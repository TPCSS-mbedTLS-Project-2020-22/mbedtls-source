mod blowfishc;
use blowfishc::blowfish;
use crate::blowfishc::blowfish::MBEDTLS_BLOWFISH_ENCRYPT;
use crate::blowfishc::blowfish::MBEDTLS_BLOWFISH_DECRYPT;
use blowfish::mbedtls_blowfish_context;
use blowfishc::get_uint32_be;
use blowfishc::put_uint32_be;

fn main() {
    let mut n:u32=0;
    let mut b:[u8;8]=[1,2,3,4,5,6,7,8];
    let i:usize=0;
    get_uint32_be(&mut n,&mut b,i);
    println!("{:b}",n);
    b=[0,0,0,0,0,0,0,0];
    put_uint32_be(n,&mut b,i);
    println!("{:?}",b);
    println!("{:?}",blowfishc::P);
    let mut ctx:&mut mbedtls_blowfish_context=& mut mbedtls_blowfish_context{
        P:blowfishc::P,
        S:blowfishc::S,
    };
    let mut xl:u32=0x3AC372E6;
    let mut xr:u32=0xCE77E25B;
    blowfishc::blowfish_enc(&mut ctx,&mut xl,&mut xr);
    println!("{:x} {:x}",xl,xr);
    blowfishc::blowfish_dec(&mut ctx,&mut xl,&mut xr);
    println!("{:x} {:x}",xl,xr);
    //println!("{}",F(&mut ctx,n));
    blowfishc::mbedtls_blowfish_init(&mut ctx);
    println!("{:?}",ctx.P);
    blowfishc::mbedtls_blowfish_setkey(&mut ctx,"10010110001110101001011000111010",32);
    println!("{:?}",ctx.P);
    let mut c:[u8;8]=[0,0,0,0,0,0,0,0];
    println!("{:?}",b);
    blowfishc::mbedtls_blowfish_crypt_ecb(&mut ctx,MBEDTLS_BLOWFISH_ENCRYPT, b,&mut c);
    println!("{:?}",c);
    let mut d:[u8;8]=[0,0,0,0,0,0,0,0];
    blowfishc::mbedtls_blowfish_crypt_ecb(&mut ctx,MBEDTLS_BLOWFISH_DECRYPT, c,&mut d);
    println!("{:?}",d);
    blowfish::run();
}
