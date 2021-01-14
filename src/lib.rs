#![allow(unused_imports)]

mod ssl_tls;
pub mod aes;

use std::convert::TryInto;

#[test]
fn test_01()
{
    let mut ctx = crate::aes::mbedtls_aes_context::new();
    println!("{:?}", ctx);
    crate::aes::mbedtls_aes_setkey_enc(&mut ctx, &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4], 128);
    // assert_eq!(ctx.nr, 10);
    assert_eq!(ctx.key, [1, 2, 3, 4]);
}

#[test]
fn test_02()
{
    let mut n: u32 = 0;
    let mut b: [u8; 4] = [0, 0, 0, 1];
    crate::aes::GET_UINT32_LE(&mut n, &mut b, 0);
    assert_eq!(n, 1);
}

#[test]
fn test_03()
{
    let n: u32 = 1;
    let mut b: [u8; 4] = [0; 4];
    crate::aes::PUT_UINT32_LE(n, &mut b, 0);
    assert_eq!(b, [0, 0, 0, 1]);
}

#[test]
fn test_mbedtls_setkey_dec()
{
    let mut ctx: aes::mbedtls_aes_context = aes::mbedtls_aes_context::new();
    let key: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let return_value = aes::mbedtls_aes_setkey_dec(&mut ctx, &key, 128);
    println!("{:X?}", ctx);
    assert_eq!(return_value, 0);
}

#[test]
fn test_aes_01() {
    let mut ctx = crate::aes::mbedtls_aes_context::new();
    let original_msg: [u8; 16] = [0x41u8; 16];
    let key: [u8; 16] = [0; 16];
    let mut encrypted_msg: [u8; 16] = [0; 16]; 
    crate::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::aes::mbedtls_internal_aes_encrypt(&ctx, &original_msg, &mut encrypted_msg);
    let expected_answer: [u8; 16] = [
        0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b,
        0x63, 0xe3,
    ];
    assert_eq!(encrypted_msg, expected_answer);
}

#[test]
fn test_aes_02() {
    let mut ctx = crate::aes::mbedtls_aes_context::new();
    let original_msg: [u8; 16] = [0x00u8; 16];
    let key: [u8; 16] = [0; 16];
    let mut encrypted_msg: [u8; 16] = [0; 16];
    crate::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::aes::mbedtls_internal_aes_encrypt(&ctx, &original_msg, &mut encrypted_msg);
    let expected_answer: [u8; 16] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
        0x2b, 0x2e,
    ];
    assert_eq!(encrypted_msg, expected_answer);
}

#[test]
fn test_aes_dec_01()
{
    let mut ctx = crate::aes::mbedtls_aes_context::new();
    let original_msg: [u8; 16] = "abcdefghijklmnop".as_bytes().try_into().expect("Error");
    let mut encrypted_msg: [u8; 16] = [0; 16];
    let key: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 , 16];
    crate::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::aes::mbedtls_internal_aes_encrypt(&ctx, &original_msg, &mut encrypted_msg);

    let mut decrypted_msg: [u8; 16] = [0; 16];
    crate::aes::mbedtls_internal_aes_decrypt(&ctx, &encrypted_msg, &mut decrypted_msg);
    assert_eq!(original_msg, decrypted_msg);
}

// #[test]
// fn test_aes_enc_01()
// {
//     let mut ctx = crate::aes::mbedtls_aes_context::new();
//     let plaintext: [u8; 16] = "6a84867cd77e12ad07ea1be895c53fa3".as_bytes().try_into().expect("Error");
//     let key: [u8; 16] = [0; 16];
//     let mut ciphertext: [u8; 16] = [0; 16];

//     crate::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
//     crate::aes::mbedtls_inter
// }