use mbed::cipher::des::*;
fn main() {
    let mut cipher = mbedtls_des_context::init();
    println!(
        "Cipher Initialized round keys:{} ",cipher.sk[0]
    );
   
   //Test1
   let mut n:u32=0;
   let mut b:[u8;8]=[1,2,3,4,5,6,7,8];
    let i:usize=0;
    get_uint32_be(&mut n,&mut b,i);
    println!("{:b}",n);
    b=[0,0,0,0,0,0,0,0];
    put_uint32_be(n,&mut b,i);
    println!("{:?}",b);

   //Test2
   
    let mut xl:u32=0x3AC372E6;
    let mut xr:u32=0xCE77E25B;
    println!("Before DES initial Permutation working{:x} {:x}",xl,xr);
    DES_IP(&mut xl,&mut xr);
    println!("DES initial Permutation working{:x} {:x}",xl,xr);
    DES_FP(&mut xl,&mut xr);
    println!("DES Final Permutation working{:x} {:x}",xl,xr);


    //Test3 For Setting Keys for Decryption
    const  des3_test_keys: [u8; 8] =
    [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    ];
    mbedtls_des_setkey_enc( &mut cipher, des3_test_keys );
    println!("{:?}",cipher.sk);
    //Encryption
    b=[49, 50, 51, 52, 53, 54, 55, 56];
    let mut c:[u8;8]=[0,0,0,0,0,0,0,0];
    println!("{:?}",b);
    mbedtls_des_crypt_ecb(&mut cipher,b,&mut c);
    println!("{:?}",c);

    //Decryption
    mbedtls_des_setkey_dec( &mut cipher, des3_test_keys );
    println!("{:?}",cipher.sk);
    let mut d:[u8;8]=[0,0,0,0,0,0,0,0];
    println!("Before Decryption{:?}",d);
    println!("{:?}",c);
    mbedtls_des_crypt_ecb(&mut cipher,c,&mut d);
    println!("{:?}",d);


   
   
    

    
}