use std::convert::TryFrom;
use std::convert::TryInto;
use std::ptr;
use std::ptr::write_bytes;
pub const MBEDTLS_ERR_CCM_BAD_INPUT: i32 = -0x000D;
pub const MBEDTLS_ERR_CCM_AUTH_FAILED: i32 = -0x000F;
pub const MBEDTLS_ERR_CCM_HW_ACCEL_FAILED: i32 = -0x0011;
pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED: i32 = 1234;
pub const NB_TESTS: usize = 3;
pub const CCM_SELFTEST_PT_MAX_LEN: usize = 24;
pub const CCM_SELFTEST_CT_MAX_LEN: usize = 32;
pub const CCM_ENCRYPT: u32 = 0;
pub const CCM_DECRYPT: u32 = 1;
pub const MBEDTLS_CIPHER_ID_AES: i32 = 0;
pub const MBEDTLS_MODE_ECB: i32 = 1;
pub struct mbedtls_ccm_context {
    //pub cipher_ctx:mbedtls_cipher_context_t ;
    //pub pub cipher_info:&pub mbedtls_cipher_info_t;
    pub operation: i32,
    pub unprocessed_data: [u8; 16],
    pub unprocessed_len: usize,
    pub iv: [u8; 16],
    pub iv_size: usize,
    //pub cipher_ctx:&pub,
    //pub  MBEDTLS_USE_PSA_CRYPTO:u8=psa_enabled,
    pub key_bitlen: u32,
    pub name: String,
    pub flags: i32,
    pub block_size: u32,
}

pub fn mbedtls_ccm_init(mut ctx: &mut mbedtls_ccm_context) {
    unsafe {
        ptr::write_bytes(ctx, 0, 1);
    }
}

pub fn mbedtls_ccm_setkey(
    mut ctx: &mut mbedtls_ccm_context,
    mut cipher: i32,
    mut key: [u8; 16],
    mut keybits: u32,
) -> i32 {
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    //**let mut cipher_info: &mut mbedtls_cipher_info_t;

    //**cipher_info = mbedtls_cipher_info_from_values(cipher, keybits, MBEDTLS_MODE_ECB);

    /*if (*cipher_info.block_size != 16) {
        return (MBEDTLS_ERR_CCM_BAD_INPUT);
    }*/
    //**mbedtls_cipher_free(&ctx.cipher_ctx);

    /*if ((ret = mbedtls_cipher_setup(&ctx.cipher_ctx, cipher_info)) != 0) {
        return (ret).try_into().unwrap();
    }*/

    /*if ((ret = mbedtls_cipher_setkey(&ctx.cipher_ctx, key, keybits, 1)) != 0) {
        return (ret).try_into().unwrap();
    }*/

    return (0);
}

/*//pub fn mbedtls_ccm_free(mut ctx: &mut mbedtls_ccm_context) {
    unsafe {
        ptr::write_bytes(ctx, 0, 1);
    }
}*/

pub fn ccm_auth_crypt(
    mut ctx: &mut mbedtls_ccm_context,
    mut mode: u32,
    mut length: usize,
    mut iv: [u8; 12],
    mut iv_len: usize,
    mut add: [u8; 20],
    mut add_len: usize,
    mut input: &mut [u8],
    mut output: &mut [u8],
    mut tag: &mut [u8],
    mut tag_len: usize,
) -> i32 {
    let mut ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut i: u8;
    let mut q: u8;
    let mut len_left: usize;
    let mut olen: usize;
    let mut b: [u8; 16];
    let mut y: [u8; 16];
    let mut ctr: [u8; 16];
    let mut src: &mut [u8];
    let mut dst: &mut [u8];

    if (tag_len == 2 || tag_len > 16 || tag_len % 2 != 0) {
        return (MBEDTLS_ERR_CCM_BAD_INPUT);
    }
    if (iv_len < 7 || iv_len > 13) {
        return (MBEDTLS_ERR_CCM_BAD_INPUT);
    }

    if (add_len > 0xFF00) {
        return (MBEDTLS_ERR_CCM_BAD_INPUT);
    }

    q = (15 - iv_len) as u8;
    b[0] = 0;
    if (add_len > 0) {
        b[0] |= (add_len << 6) as u8;
    }
    b[0] |= (((tag_len - 2) / 2) << 3) as u8;
    b[0] |= q - 1;
    for i in 1..iv_len {
        b[i] = iv[i];
    }
    len_left = length;
    for i in (0..q) {
        b[15 - i as usize] = (len_left & 0xFF) as u8;
        len_left >>= 8
    }
    if (len_left > 0) {
        return (MBEDTLS_ERR_CCM_BAD_INPUT);
    }
    for i in 0..16 {
        y[i] = 0;
    }
    //UPDATE_CBC_MAC;
    for i in 0..16 {
        y[i] = y[i] ^ b[i];
    }
    /*(comment out ) ret = mbedtls_cipher_update((&ctx).cipher_ctx, y, 16, y, &olen);
    if (ret != 0) {
        return (ret);
    }*/

    if (add_len > 0) {
        let mut use_len: usize;
        len_left = add_len;
        for j in 0..(add.len()) {
            src[j] = add[j];
        }
        for i in 0..16 {
            b[i] = 0;
        }
        b[0] = ((add_len >> 8) & 0xFF) as u8;
        b[1] = ((add_len) & 0xFF) as u8;
        if (len_left < 16 - 2) {
            use_len = len_left;
        } else {
            use_len = 16 - 2;
        }
        for i in 2..use_len {
            b[i] = src[i];
        }
        len_left = len_left - use_len;

        let mut k: usize = 0;
        for j in use_len..(src.len()) {
            src[k] = src[j];
            k = k + 1;
        }

        //UPDATE_CBC_MAC;
        for i in 0..16 {
            y[i] = y[i] ^ b[i];
        }
        /*ret = mbedtls_cipher_update((&ctx).cipher_ctx, y, 16, y, &olen);
        if (ret != 0) {
            return (ret);
        }*/

        while (len_left > 0) {
            if (len_left > 16) {
                use_len = 16;
            } else {
                use_len = len_left;
            }
            for i in 0..16 {
                b[i] = 0;
            }
            for i in 0..use_len {
                b[i] = src[i];
            }
            //UPDATE_CBC_MAC;
            for i in 0..16 {
                y[i] = y[i] ^ b[i];
            }
            /*(comment out ) ret = mbedtls_cipher_update((&ctx).cipher_ctx, y, 16, y, &olen);
            if (ret != 0) {
                return (ret);
            }*/
            len_left = len_left - use_len;
            let mut k: usize = 0;
            for j in use_len..(src.len()) {
                src[k] = src[j];
                k = k + 1;
            }
        }
    }
    ctr[0] = q - 1;
    for i in 0..iv_len {
        ctr[i + 1] = iv[i];
    }
    for i in (1 + iv_len)..q as usize {
        ctr[i] = 0;
    }

    ctr[15] = 1;

    len_left = length;
    for j in 0..input.len() {
        src[j] = input[j];
    }
    for j in 0..output.len() {
        dst[j] = output[j];
    }

    while (len_left > 0) {
        let mut use_len: usize;
        if (len_left > 16) {
            use_len = 16;
        } else {
            use_len = len_left;
        }
        if (mode == CCM_ENCRYPT) {
            for i in 0..16 {
                b[i] = 0;
            }
            for i in 0..use_len {
                b[i] = src[i];
            }
            for i in 0..16 {
                y[i] = y[i] ^ b[i];
            }
            /*(comment out ) ret = mbedtls_cipher_update((&ctx).cipher_ctx, y, 16, y, &olen);
            if (ret != 0) {
                return (ret);
            }*/
        }

        //CTR_CRYPT(dst, src, use_len); start here

        /*(comment out) if ((ret = mbedtls_cipher_update((&ctx).cipher_ctx, ctr, 16, b, &olen)) != 0) {
            return (ret);
        }*/

        for i in 0..use_len {
            dst[i] = src[i] ^ b[i];
        }
        //CTR_CRYPT(dst, src, use_len); end here
        if (mode == CCM_DECRYPT) {
            for i in 0..16 {
                b[i] = 0;
            }
            for i in 0..use_len {
                b[i] = dst[i];
            }
            //UPDATE_CBC_MAC;
            for i in 0..16 {
                y[i] = y[i] ^ b[i];
            }
            /*(comment) ret = mbedtls_cipher_update((&ctx).cipher_ctx, y, 16, y, &olen);
            if (ret != 0) {
                return (ret);
            }*/
        }
        let mut k: usize = 0;
        for j in use_len..(dst.len()) {
            dst[k] = dst[j];
            k = k + 1;
        }
        k = 0;
        for j in use_len..(src.len()) {
            src[k] = src[j];
            k = k + 1;
        }
        len_left = len_left - use_len;
        for i in 0..q {
            if ((1 + ctr[15 - i as usize]) != 0) {
                break;
            }
        }
    }

    for i in 0..q {
        ctr[(15 - i as usize)] = 0;
    }
    //CTR_CRYPT(y, y, 16); start here
    /* (comment out ) if ((ret = mbedtls_cipher_update((&ctx).cipher_ctx, ctr, 16, b, &olen)) != 0) {
        return (ret);
    }*/

    for i in 0..16 {
        y[i] = y[i] ^ b[i];
    }
    //CTR_CRYPT(y, y, 16); end here
    for i in 0..tag_len {
        tag[i] = y[i];
    }
    return (0);
}

pub fn mbedtls_ccm_star_encrypt_and_tag(
    mut ctx: &mut mbedtls_ccm_context,
    mut length: usize,
    mut iv: [u8; 12],
    mut iv_len: usize,
    mut add: [u8; 20],
    mut add_len: usize,
    mut input: &mut [u8],
    mut output: &mut [u8],
    mut tag: &mut [u8],
    mut tag_len: usize,
) -> i32 {
    return (ccm_auth_crypt(
        ctx,
        CCM_ENCRYPT,
        length,
        iv,
        iv_len,
        add,
        add_len,
        &mut input,
        &mut output,
        &mut tag,
        tag_len,
    ));
}

pub fn mbedtls_ccm_encrypt_and_tag(
    mut ctx: &mut mbedtls_ccm_context,
    mut length: usize,
    mut iv: [u8; 12],
    mut iv_len: usize,
    mut add: [u8; 20],
    mut add_len: usize,
    mut input: &mut [u8],
    mut output: &mut [u8],
    mut tag: &mut [u8],
    mut tag_len: usize,
) -> i32 {
    if (tag_len == 0) {
        return (MBEDTLS_ERR_CCM_BAD_INPUT);
    }

    return (mbedtls_ccm_star_encrypt_and_tag(
        ctx,
        length,
        iv,
        iv_len,
        add,
        add_len,
        &mut input,
        &mut output,
        &mut tag,
        tag_len,
    ));
}

pub fn mbedtls_ccm_star_auth_decrypt(
    mut ctx: &mut mbedtls_ccm_context,
    mut length: usize,
    mut iv: [u8; 12],
    mut iv_len: usize,
    mut add: [u8; 20],
    mut add_len: usize,
    mut input: &mut [u8],
    mut output: &mut [u8],
    mut tag: &mut [u8],
    mut tag_len: usize,
) -> i32 {
    let mut ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut check_tag: &mut [u8];
    let mut i: u8;
    let mut diff: i32;
    ret = ccm_auth_crypt(
        ctx,
        CCM_DECRYPT,
        length,
        iv,
        iv_len,
        add,
        add_len,
        &mut input,
        &mut output,
        &mut check_tag,
        tag_len,
    );
    if (ret != 0) {
        return (ret);
    }

    let mut diff = 0;
    for i in 0..tag_len {
        diff |= tag[i] ^ check_tag[i];
    }

    if (diff != 0) {
        for i in 0..length {
            output[i] = 0;
        }
        return (MBEDTLS_ERR_CCM_AUTH_FAILED);
    }

    return (0);
}

pub fn mbedtls_ccm_auth_decrypt(
    mut ctx: &mut mbedtls_ccm_context,
    mut length: usize,
    mut iv: [u8; 12],
    mut iv_len: usize,
    mut add: [u8; 20],
    mut add_len: usize,
    mut input: &mut [u8],
    mut output: &mut [u8],
    mut tag: &mut [u8],
    mut tag_len: usize,
) -> i32 {
    return (mbedtls_ccm_star_auth_decrypt(
        ctx,
        length,
        iv,
        iv_len,
        add,
        add_len,
        &mut input,
        &mut output,
        &mut tag,
        tag_len,
    ));
}
pub const key_test_data: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];

pub const iv_test_data: [u8; 12] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
];

pub const ad_test_data: [u8; 20] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
];

pub const msg_test_data: [u8; CCM_SELFTEST_PT_MAX_LEN] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
];

pub const iv_len_test_data: [usize; NB_TESTS] = [7, 8, 12];
pub const add_len_test_data: [usize; NB_TESTS] = [8, 16, 20];
pub const msg_len_test_data: [usize; NB_TESTS] = [4, 16, 24];
pub const tag_len_test_data: [usize; NB_TESTS] = [4, 6, 8];

pub const res_test_data: [[u8; CCM_SELFTEST_CT_MAX_LEN]; 3] = [
    [
        0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d, 0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7,
        0x0b, 0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5, 0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0,
        0x99, 0x51,
    ],
    [
        0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62, 0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59,
        0x3d, 0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd, 0x8a, 0xa5, 0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0,
        0x99, 0x51,
    ],
    [
        0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a, 0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7,
        0x0b, 0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5, 0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0,
        0x99, 0x51,
    ],
];
pub fn mbedtls_ccm_self_test(mut verbose: i32) -> i32 {
    let mut ctx: mbedtls_ccm_context;
    //let mut plaintext: &mut [u8; CCM_SELFTEST_PT_MAX_LEN] = [0; CCM_SELFTEST_PT_MAX_LEN];
    let mut plaintext: &mut [u8];
    //let mut ciphertext: [u8; CCM_SELFTEST_CT_MAX_LEN];
    //let mut ciphertext: &mut [u8; CCM_SELFTEST_CT_MAX_LEN] = [0; CCM_SELFTEST_CT_MAX_LEN];
    let mut ciphertext: &mut [u8];
    let mut i: usize;
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_ccm_init(&mut ctx);
    let mut a: i32 = mbedtls_ccm_setkey(&mut ctx, MBEDTLS_CIPHER_ID_AES, key_test_data, 128);

    if (a != 0) {
        if (verbose != 0) {
            println!("  CCM: setup failed");
        }

        return (1);
    }
    for i in 0..NB_TESTS {
        if (verbose != 0) {
            println!("  CCM-AES {}: ", (i + 1) as u32);
        }
        for j in 0..CCM_SELFTEST_PT_MAX_LEN {
            plaintext[j] = 0;
        }
        for j in 0..CCM_SELFTEST_PT_MAX_LEN {
            ciphertext[j] = 0;
        }
        for j in 0..msg_len_test_data[i] {
            plaintext[j] = msg_test_data[j];
        }
        let mut a: usize = ciphertext.len();
        let mut s: &mut [u8];
        let mut k: usize = 0;
        for j in msg_len_test_data[i]..a {
            s[k] = ciphertext[j];
            k = k + 1;
        }

        ret = mbedtls_ccm_encrypt_and_tag(
            &mut ctx,
            msg_len_test_data[i],
            iv_test_data,
            iv_len_test_data[i],
            ad_test_data,
            add_len_test_data[i],
            &mut plaintext,
            &mut ciphertext,
            &mut s,
            tag_len_test_data[i],
        );
        let mut flagc = 0;
        for j in 0..(msg_len_test_data[i] + tag_len_test_data[i]) {
            if (ciphertext[j] != res_test_data[i][j]) {
                flagc = 1;
                break;
            }
        }
        if (ret != 0 || flagc != 0) {
            if (verbose != 0) {
                println!("failed\n");
            }

            return (1);
        }
        for i in 0..CCM_SELFTEST_PT_MAX_LEN {
            plaintext[i] = 0;
        }
        ret = mbedtls_ccm_auth_decrypt(
            &mut ctx,
            msg_len_test_data[i],
            iv_test_data,
            iv_len_test_data[i],
            ad_test_data,
            add_len_test_data[i],
            &mut ciphertext,
            &mut plaintext,
            &mut s,
            tag_len_test_data[i],
        );
        let mut flagp = 0;
        for j in 0..(msg_len_test_data[i]) {
            if (plaintext[j] != msg_test_data[j]) {
                flagp = 1;
                break;
            }
        }
        if (ret != 0 || flagp != 0) {
            if (verbose != 0) {
                println!("failed\n");
            }

            return (1);
        }

        if (verbose != 0) {
            println!("passed\n");
        }
    }

    //**mbedtls_ccm_free(&ctx);

    if (verbose != 0) {
        println!("\n");
    }

    return (0);
}
pub fn run() {
    mbedtls_ccm_self_test(123456);
    println!("run printed");
}
