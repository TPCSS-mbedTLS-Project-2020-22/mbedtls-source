use mbed::cipher::des::*;
fn main() {
    let mut cipher = mbedtls_des_context::init();
    println!(
        "Cipher Initialized round keys:{} ",cipher.sk[0]
    );
   
   //Test-1-ECB Encryption and Decryption 
   let mut n:u32=0;
   let mut input:[u8;8]=[1,2,3,4,5,6,7,8];    
   const  des3_test_keys: [u8; 8] =
    [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    ];
    mbedtls_des_setkey_enc( &mut cipher, des3_test_keys );
    println!("Now Presenting ECB Encryption and Decryption");
    //Encryption
    input=[49, 50, 51, 52, 53, 54, 55, 56];
    let mut c:[u8;8]=[0,0,0,0,0,0,0,0];
    println!("Before Encrption : Input Value is  {:?}",input);
    mbedtls_des_crypt_ecb(&mut cipher,input,&mut c);
    println!("After Encryption , Now Encryptedd Value :{:?}",c);

    //Decryption
    mbedtls_des_setkey_dec( &mut cipher, des3_test_keys );
   let mut output:[u8;8]=[0,0,0,0,0,0,0,0];
    println!("Before Decryption , Encrypted value is : {:?}",c);
    mbedtls_des_crypt_ecb(&mut cipher,c,&mut output);
    println!("After Decryption , Original Value  :{:?}",output);
   
    const  des3_test_iv: [u8; 8]  =
[
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
];
let mut cipher = mbedtls_des_context::init();
    println!(
        "Cipher Initialized round keys:{} ",cipher.sk[0]
    );
let mut iv:  [char;8]=['1','2','3','4','5','6','7','8'];
let mut k= String::from("ijklmnopijklmnop");
mbedtls_des_crypt_cbc(&mut cipher,1,8,&mut iv,String::from("hellopri"),&mut k);  
println!("{:?}",k);
    let mut k1= String::from("ijklmnopijklmnop");
    iv=['1','2','3','4','5','6','7','8'];
    mbedtls_des_crypt_cbc(&mut cipher,0,8,&mut iv,k,&mut k1);
    println!("{:?}",k1);
    
}