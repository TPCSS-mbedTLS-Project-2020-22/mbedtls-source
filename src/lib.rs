#![allow(unused_imports)]

pub mod cipher;
mod ssl_tls;

use std::convert::TryInto;

#[test]
fn test_01() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    println!("{:?}", ctx);
    crate::cipher::aes::mbedtls_aes_setkey_enc(
        &mut ctx,
        &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4],
        128,
    );
    // assert_eq!(ctx.nr, 10);
    assert_eq!(ctx.key, [1, 2, 3, 4]);
}

#[test]
fn test_02() {
    let mut n: u32 = 0;
    let mut b: [u8; 4] = [0, 0, 0, 1];
    crate::cipher::aes::GET_UINT32_LE(&mut n, &mut b, 0);
    assert_eq!(n, 1);
}

#[test]
fn test_03() {
    let n: u32 = 1;
    let mut b: [u8; 4] = [0; 4];
    crate::cipher::aes::PUT_UINT32_LE(n, &mut b, 0);
    assert_eq!(b, [0, 0, 0, 1]);
}

#[test]
fn test_mbedtls_setkey_dec() {
    let mut ctx: cipher::aes::mbedtls_aes_context = cipher::aes::mbedtls_aes_context::new();
    let key: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let return_value = cipher::aes::mbedtls_aes_setkey_dec(&mut ctx, &key, 128);
    println!("{:X?}", ctx);
    assert_eq!(return_value, 0);
}

#[test]
fn test_aes_01() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    let original_msg: [u8; 16] = [0x41u8; 16];
    let key: [u8; 16] = [0; 16];
    let mut encrypted_msg: [u8; 16] = [0; 16];
    crate::cipher::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::cipher::aes::mbedtls_internal_aes_encrypt(&ctx, &original_msg, &mut encrypted_msg);
    let expected_answer: [u8; 16] = [
        0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b, 0x63,
        0xe3,
    ];
    assert_eq!(encrypted_msg, expected_answer);
}

#[test]
fn test_aes_02() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    let original_msg: [u8; 16] = [0x00u8; 16];
    let key: [u8; 16] = [0; 16];
    let mut encrypted_msg: [u8; 16] = [0; 16];
    crate::cipher::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::cipher::aes::mbedtls_internal_aes_encrypt(&ctx, &original_msg, &mut encrypted_msg);
    let expected_answer: [u8; 16] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];
    assert_eq!(encrypted_msg, expected_answer);
}

#[test]
fn test_aes_dec_01() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    let original_msg: [u8; 16] = "abcdefghijklmnop".as_bytes().try_into().expect("Error");
    let mut encrypted_msg: [u8; 16] = [0; 16];
    let key: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    crate::cipher::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::cipher::aes::mbedtls_internal_aes_encrypt(&ctx, &original_msg, &mut encrypted_msg);

    let mut decrypted_msg: [u8; 16] = [0; 16];
    crate::cipher::aes::mbedtls_internal_aes_decrypt(&ctx, &encrypted_msg, &mut decrypted_msg);
    assert_eq!(original_msg, decrypted_msg);
}

#[test]
fn test_aes_enc_01() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    let plaintext: [u8; 32] = "6a84867cd77e12ad07ea1be895c53fa3"
        .as_bytes()
        .try_into()
        .expect("Error");
    // let plaintext: [u8; 16] = "6a84867cd77e12ad".as_bytes().try_into().expect("Error");
    let key: [u8; 16] = [0; 16];
    let mut ciphertext: [u8; 32] = [0; 32];
    // let answer: [u8; 32] = "732281c0a0aab8f7a54a0c67a0c45ecf".as_bytes().try_into().expect("Error");
    let answer: [u8; 32] = [
        0x0c, 0x98, 0xa8, 0xce, 0x44, 0x0c, 0xcd, 0x37, 0x05, 0x65, 0xfc, 0x21, 0xa0, 0xf6, 0x54,
        0xa8, 0xe3, 0x4e, 0x5e, 0x1d, 0x9d, 0x2f, 0xf6, 0xae, 0x6c, 0xde, 0x38, 0x08, 0x1b, 0xc9,
        0x15, 0x09,
    ];

    crate::cipher::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::cipher::aes::mbedtls_aes_crypt_ecb(
        &ctx,
        crate::cipher::aes::MBEDTLS_AES_ENCRYPT,
        &plaintext,
        &mut ciphertext,
    );
    // println!("{}", std::str::from_utf8(&ciphertext).unwrap());
    println!("{:02X?}", ciphertext);
    assert_eq!(answer, ciphertext);
}

#[test]
fn test_aes_enc_02() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    let plaintext: [u8; 64] = "3c888bbbb1a8eb9f3e9b87acaad986c466e2f7071c83083b8a557971918850e5"
        .as_bytes()
        .try_into()
        .expect("Error");
    // let plaintext: [u8; 16] = "6a84867cd77e12ad".as_bytes().try_into().expect("Error");
    let key: [u8; 16] = [0; 16];
    let mut ciphertext: [u8; 64] = [0; 64];
    // let answer: [u8; 32] = "732281c0a0aab8f7a54a0c67a0c45ecf".as_bytes().try_into().expect("Error");
    let answer: [u8; 64] = [
        0xd8, 0xe6, 0xf8, 0x72, 0xee, 0x71, 0x88, 0xe8, 0x31, 0xaa, 0x97, 0x4c, 0xd2, 0xe3, 0xf4,
        0x62, 0xe4, 0x71, 0x7d, 0xbd, 0xe8, 0xd3, 0xef, 0xb2, 0x2c, 0x31, 0x8c, 0xaf, 0xad, 0x08,
        0x40, 0xaa, 0x6d, 0xb3, 0x3e, 0x0c, 0xe5, 0x98, 0xb2, 0x42, 0xb8, 0xa8, 0xf0, 0x76, 0xfd,
        0xaf, 0xaf, 0xdc, 0x1d, 0x05, 0x54, 0x81, 0xd9, 0xb8, 0x7d, 0xea, 0x06, 0x37, 0xc9, 0xc0,
        0x2e, 0x9e, 0x22, 0x73,
    ];

    crate::cipher::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::cipher::aes::mbedtls_aes_crypt_ecb(
        &ctx,
        crate::cipher::aes::MBEDTLS_AES_ENCRYPT,
        &plaintext,
        &mut ciphertext,
    );
    // println!("{}", std::str::from_utf8(&ciphertext).unwrap());
    println!("{:02X?}", ciphertext);
    assert_eq!(answer, ciphertext);
}

#[test]
fn test_aes_enc_cbc_01() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    let plaintext: [u8; 64] = "3c888bbbb1a8eb9f3e9b87acaad986c466e2f7071c83083b8a557971918850e5"
        .as_bytes()
        .try_into()
        .expect("Error");
    let key: [u8; 16] = [0; 16];
    let mut ciphertext: [u8; 64] = [0; 64];
    let iv: [u8; 16] = [
        0xd8, 0x96, 0x07, 0xb4, 0x7d, 0xc8, 0x19, 0xd1, 0x93, 0xfb, 0xa1, 0x4a, 0x30, 0x49, 0x67,
        0x22,
    ];
    let enc_answer: [u8; 64] = [
        0x54, 0xda, 0xf1, 0x5a, 0xec, 0x2d, 0x01, 0xe5, 0x08, 0x66, 0x78, 0x89, 0x88, 0xb4, 0xf3,
        0x65, 0x51, 0x02, 0x7e, 0x31, 0x27, 0x57, 0xa4, 0xac, 0xa1, 0x99, 0xa7, 0xcb, 0xe9, 0x49,
        0x93, 0xd8, 0x74, 0x46, 0x51, 0xd1, 0x9e, 0x82, 0xe9, 0xe3, 0x78, 0x30, 0x1d, 0xc5, 0x53,
        0x87, 0x74, 0x65, 0x2f, 0xb3, 0xf4, 0xee, 0x37, 0x52, 0x03, 0x37, 0xb1, 0x53, 0xbf, 0x3a,
        0x93, 0x8a, 0x95, 0x0d,
    ];

    let mut decrypted_msg: [u8; 64] = [0; 64];

    crate::cipher::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::cipher::aes::mbedtls_aes_crypt_cbc(
        &ctx,
        crate::cipher::aes::MBEDTLS_AES_ENCRYPT,
        64,
        &iv,
        &plaintext,
        &mut ciphertext,
    );
    crate::cipher::aes::mbedtls_aes_crypt_cbc(
        &ctx,
        crate::cipher::aes::MBEDTLS_AES_DECRYPT,
        64,
        &iv,
        &ciphertext,
        &mut decrypted_msg,
    );

    // println!("===========================================\n\nanswer = {:02X?}\n\n===========================================\n\n", enc_answer);
    // println!("===========================================\n\nciphertext = {:02X?}\n\n===========================================\n\n", ciphertext);

    assert_eq!(ciphertext, enc_answer);
    assert_eq!(plaintext, decrypted_msg);
}

#[test]
fn test_aes_enc_ofb_01() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    let plaintext: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF,
        0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A,
        0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B,
        0xE6, 0x6C, 0x37, 0x10,
    ];
    let key: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];
    let mut ciphertext: [u8; 64] = [0; 64];
    let mut iv_enc: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let mut iv_dec: [u8; 16] = iv_enc.clone();
    let mut iv_off: usize = 0;
    let enc_answer: [u8; 64] = [
        0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB,
        0x4A, 0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03, 0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e,
        0xd8, 0x25, 0x97, 0x40, 0x05, 0x1e, 0x9c, 0x5f, 0xec, 0xf6, 0x43, 0x44, 0xf7, 0xa8, 0x22,
        0x60, 0xed, 0xcc, 0x30, 0x4c, 0x65, 0x28, 0xf6, 0x59, 0xc7, 0x78, 0x66, 0xa5, 0x10, 0xd9,
        0xc1, 0xd6, 0xae, 0x5e,
    ];

    let mut decrypted_msg: [u8; 64] = [0; 64];

    crate::cipher::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    crate::cipher::aes::mbedtls_aes_crypt_ofb(
        &ctx,
        64,
        &mut iv_off,
        &mut iv_enc,
        &plaintext,
        &mut ciphertext,
    );
    crate::cipher::aes::mbedtls_aes_crypt_ofb(
        &ctx,
        64,
        &mut iv_off,
        &mut iv_dec,
        &ciphertext,
        &mut decrypted_msg,
    );

    // println!("===========================================\n\nanswer = {:02X?}\n\n===========================================\n\n", enc_answer);
    // println!("===========================================\n\nciphertext = {:02X?}\n\n===========================================\n\n", ciphertext);

    assert_eq!(ciphertext, enc_answer);
    assert_eq!(plaintext, decrypted_msg);
}

#[test]
fn mbedtls_aes_test_ctr_01() {
    let mut ctx = crate::cipher::aes::mbedtls_aes_context::new();
    let key: [u8; 16] = [
        0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC, 0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3,
        0x9E,
    ];
    crate::cipher::aes::mbedtls_aes_setkey_enc(&mut ctx, &key, 128);
    let ctx_option = Some(&ctx);
    let plaintext: [u8; 16] = [
        0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73,
        0x67,
    ];
    
    let mut ciphertext: [u8; 16] = [0; 16];
    let mut nonce_counter: [u8; 16] = [
        0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    let enc_answer: [u8; 16] = [
        0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79, 0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11,
        0xB8,
    ];
    let ctr_len = 16;
    let mut decrypted_msg: [u8; 16] = [0; 16];
    let mut offset = 0;
    let mut stream_block: [u8; 16] = [0; 16];

    crate::cipher::aes::mbedtls_aes_crypt_ctr(
        ctx_option,
        ctr_len,
        &mut offset,
        &mut nonce_counter,
        &mut stream_block,
        &plaintext,
        &mut ciphertext,
    );
    offset = 0;
    nonce_counter = [
        0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    crate::cipher::aes::mbedtls_aes_crypt_ctr(
        ctx_option,
        ctr_len,
        &mut offset,
        &mut nonce_counter,
        &mut stream_block,
        &ciphertext,
        &mut decrypted_msg
    );

    assert_eq!(enc_answer, ciphertext);
    assert_eq!(decrypted_msg, plaintext);
}
