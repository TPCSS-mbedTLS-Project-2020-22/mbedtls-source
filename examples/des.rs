use mbedtls::cipher::des::*;
fn main() {
    let mut cipher = mbedtls_des_context::init();
    println!("Cipher Initialized round keys:{} ", cipher.sk[0]);
    const DES3_TEST_KEYS: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    const DES3_TEST_IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
    const DES3_TEST_KEYS_16: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01,
    ];

    const DES3_TEST_KEYS_24: [u8; 24] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
    ];

    //Test-1-DES ECB Encryption and Decryption (56 Bit)
    let  n: u32 = 0;
    let mut input: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    mbedtls_des_setkey_enc(&mut cipher, DES3_TEST_KEYS);
    println!("-------Now Presenting DES ECB Encryption and Decryption------");
    //Encryption
    input = [49, 50, 51, 52, 53, 54, 55, 56];
    let mut c: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    println!("Before Encrption : Input Value is  {:?}", input);
    mbedtls_des_crypt_ecb(&mut cipher, input, &mut c);
    println!("After Encryption , Now Encryptedd Value :{:?}", c);

    //Decryption
    mbedtls_des_setkey_dec(&mut cipher, DES3_TEST_KEYS);
    let mut output: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    println!("Before Decryption , Encrypted value is : {:?}", c);
    mbedtls_des_crypt_ecb(&mut cipher, c, &mut output);
    println!("After Decryption , Original Value  :{:?}", output);

    println!("-------Now Presenting DES CBC Encryption and Decryption------");
    // Test 2--- DES CBC Enryption and Decryption  (56 Bit)

    let mut cipher = mbedtls_des_context::init();
    println!("Cipher Initialized round keys:{} ", cipher.sk[0]);

    let mut iv: [char; 8] = ['1', '2', '3', '4', '5', '6', '7', '8'];
    let mut k = String::from("qwertyuio");
    mbedtls_des_crypt_cbc(&mut cipher, 1, 8, &mut iv, String::from("hellopri"), &mut k);
    println!("Enrypted Input Value :  {:?}", k);
    let mut k1 = String::from("qwertyuio");
    iv = ['1', '2', '3', '4', '5', '6', '7', '8'];
    mbedtls_des_crypt_cbc(&mut cipher, 0, 8, &mut iv, k, &mut k1);
    println!("Decrypted Value , Originally passed as Input is : {:?}", k1);

    println!("-------Now Presenting 3-DES CBC Encryption and Decryption using 112 key Bits ------");
    //Test 3--3DES

    let mut cipher3 = mbedtls_des3_context::init();
    println!("Cipher Initialized round keys:{} ", cipher3.sk[0]);
    mbedtls_des3_set2key_enc(&mut cipher3, DES3_TEST_KEYS_16);
    //Encryption
    input = [49, 50, 51, 52, 53, 54, 55, 56];
    let mut c: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    println!("Before Encrption : Input Value is  {:?}", input);
    mbedtls_des3_crypt_ecb(&mut cipher3, input, &mut c);
    println!("After Encryption , Now Encryptedd Value :{:?}", c);

    //Decryption
    mbedtls_des3_set2key_enc(&mut cipher3, DES3_TEST_KEYS_16);
    let mut output: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    println!("Before Decryption , Encrypted value is : {:?}", c);
    mbedtls_des3_crypt_ecb(&mut cipher3, c, &mut output);
    println!("After Decryption , Original Value  :{:?}", output);
}
