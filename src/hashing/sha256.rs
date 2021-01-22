/*
Conversion of sha256.c
*/
struct MdContextSHA256 {
    /// number of bytes processed
    total: Vec<u32>,
    /// intermediate digest state
    state: Vec<u32>,
    /// data block being processed
    buffer: Vec<u8>,
    /// amount of data in buffer
    is224: i32,
}

fn main() {
    unimplemented!();
}

fn mbedtls_sha256_init(ctx: &mut MdContextSHA256) {
    // SHA256_VALIDATE( ctx != NULL ); is not chnaged bcoz it is do { } while( 0 )

    ctx.total = vec![0u32; 2];
    ctx.state = vec![0u32; 8];
    ctx.buffer = vec![0u8; 64];

    ctx.is224 = 0u32 as i32;
}

fn mbedtls_sha256_free(ctx: &mut MdContextSHA256) {
    for i in &mut ctx.total.iter_mut() {
        *i = 0u32;
    }
    ctx.total.resize(0, 0);

    for i in &mut ctx.state.iter_mut() {
        *i = 0u32;
    }
    ctx.state.resize(0, 0);

    for i in &mut ctx.buffer.iter_mut() {
        *i = 0u8;
    }
    ctx.buffer.resize(0, 0);

    ctx.is224 = 0u32 as i32;
}

// fn mbedtls_sha256_clone(dst: &mut MdContextSHA256, src: &MdContextSHA256) {
//     dst.buffer[..].clone_from_slice(&src.buffer[..]);
//     dst.state[..].clone_from_slice(&src.state[..]);
//     dst.total[..].clone_from_slice(&src.total[..]);
//     dst.is224 = src.is224;
// }

fn mbedtls_sha256_starts_ret(ctx: &mut MdContextSHA256, is224: i32) -> i32 {
    ctx.total[0] = 0;
    ctx.total[1] = 0;

    if is224 == 0 {
        /* SHA-256 */
        ctx.state[0] = 0x6A09E667;
        ctx.state[1] = 0xBB67AE85;
        ctx.state[2] = 0x3C6EF372;
        ctx.state[3] = 0xA54FF53A;
        ctx.state[4] = 0x510E527F;
        ctx.state[5] = 0x9B05688C;
        ctx.state[6] = 0x1F83D9AB;
        ctx.state[7] = 0x5BE0CD19;
    } else {
        /* SHA-224 */
        println!("\n SHA-224\n");

        ctx.state[0] = 0xC1059ED8;
        ctx.state[1] = 0x367CD507;
        ctx.state[2] = 0x3070DD17;
        ctx.state[3] = 0xF70E5939;
        ctx.state[4] = 0xFFC00B31;
        ctx.state[5] = 0x68581511;
        ctx.state[6] = 0x64F98FA7;
        ctx.state[7] = 0xBEFA4FA4;
    }

    ctx.is224 = is224;
    // println!("\n ctx.is224- {:?}\n", ctx.is224);
    return 0;
}

fn mbedtls_sha256_starts(ctx: &mut MdContextSHA256, is224: i32) {
    mbedtls_sha256_starts_ret(ctx, is224);
}

//do while loop implemented as single inst bcoz while condition is 0
fn GET_UINT32_BE(b: &[u8; 4]) -> u32 {
    return (u32::from(b[0]) << 24)
        | (u32::from(b[1]) << 16)
        | (u32::from(b[2]) << 8)
        | (u32::from(b[3]));
}

//do while loop implemented as single inst bcoz while condition is 0
fn PUT_UINT32_BE(n: u32, b: &mut [u8]) {
    use std::convert::TryFrom;
    b[0] = (n >> 24) as u8;
    b[1] = (n >> 16) as u8;
    b[2] = (n >> 8) as u8;
    b[3] = (n) as u8;
}

fn mbedtls_internal_sha256_process(ctx: &mut MdContextSHA256, data: &[u8]) -> i32 {
    let mut W: Vec<u32> = vec![0; 64];
    let mut A: Vec<u32> = vec![0; 8];
    let (mut temp1, mut temp2): (u32, u32) = (0, 0);
    let mut i: u32;

    let SHR = |x: u32, n: u32| (((x) & 0xFFFFFFFF) >> (n));

    let ROTR = |x: u32, n: u32| (SHR(x, n) | ((x) << (32 - (n))));

    let S0 = |x: u32| (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3));
    let S1 = |x: u32| (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10));

    let S2 = |x: u32| (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22));
    let S3 = |x: u32| (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25));

    let F0 = |x: u32, y: u32, z: u32| (((x) & (y)) | ((z) & ((x) | (y))));
    let F1 = |x: u32, y: u32, z: u32| ((z) ^ ((x) & ((y) ^ (z))));

    let P = |a: u32,
             b: u32,
             c: u32,
             d: &mut u32,
             e: u32,
             f: u32,
             g: u32,
             h: &mut u32,
             x: u32,
             T: u32| {
        // (d) += (h) + S3(e) + F1((e),(f),(g)) + (K) + (x);
        *d = (*d).wrapping_add(*h);
        *d = (*d).wrapping_add(S3(e));
        *d = (*d).wrapping_add(F1(e, f, g));
        *d = (*d).wrapping_add(T);
        *d = (*d).wrapping_add(x);

        // (h) = (h) + S3(e) + F1((e),(f),(g)) + (K) + (x) + S2(a) + F0((a),(b),(c));
        *h = (*h).wrapping_add(S3(e));
        *h = (*h).wrapping_add(F1(e, f, g));
        *h = (*h).wrapping_add(T);
        *h = (*h).wrapping_add(x);
        *h = (*h).wrapping_add(S2(a));
        *h = (*h).wrapping_add(F0(a, b, c));
    };

    const K: [u32; 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
        0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE,
        0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
        0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
        0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
        0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116,
        0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
        0xC67178F2,
    ];

    for i in 0..8 {
        A[i] = ctx.state[i];
    }

    // #if defined(MBEDTLS_SHA256_SMALLER) this need to be converted
    // for i in 0..64 {
    //     if i < 16 {
    //         W[i] = GET_UINT32_BE(&[
    //             data[i * 4],
    //             data[i * 4 + 1],
    //             data[i * 4 + 2],
    //             data[i * 4 + 3],
    //         ]);
    //     } else {
    //         let mut R1 = |t: u32| -> u32 {
    //             W[t as usize] = S1(W[(t as usize) - 2])
    //                 .wrapping_add(W[(t as usize) - 7])
    //                 .wrapping_add(S0(W[(t as usize) - 15]))
    //                 .wrapping_add(W[(t as usize) - 16]);
    //             return W[t as usize];
    //         };

    //         R1(i as u32);
    //     }

    //     P(
    //         A[0],
    //         A[1],
    //         A[2],
    //         &mut ctx.state[3],
    //         A[4],
    //         A[5],
    //         A[6],
    //         &mut A[7],
    //         W[i],
    //         K[i],
    //     );
    //     temp1 = A[7];
    //     A[7] = A[6];
    //     A[6] = A[5];
    //     A[5] = A[4];
    //     A[4] = A[3];
    //     A[3] = A[2];
    //     A[2] = A[1];
    //     A[1] = A[0];
    //     A[0] = temp1;
    // }

    // Conversion for #else /* MBEDTLS_SHA256_SMALLER */ yet to chnage #else
    for i in 0..16 {
        W[i] = GET_UINT32_BE(&[
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
    }

    for i in (0..16).step_by(8) {
        let mut temp1 = A[3];
        P(
            A[0],
            A[1],
            A[2],
            &mut temp1, // &mut ctx.state[3],
            A[4],
            A[5],
            A[6],
            &mut A[7],
            W[i + 0],
            K[i + 0],
        );
        A[3] = temp1;

        temp1 = A[2];
        P(
            A[7],
            A[0],
            A[1],
            &mut temp1, // &mut ctx.state[2],
            A[3],
            A[4],
            A[5],
            &mut A[6],
            W[i + 1],
            K[i + 1],
        );
        A[2] = temp1;

        temp1 = A[1];
        P(
            A[6],
            A[7],
            A[0],
            &mut temp1, // &mut ctx.state[1],
            A[2],
            A[3],
            A[4],
            &mut A[5],
            W[i + 2],
            K[i + 2],
        );
        A[1] = temp1;

        temp1 = A[0];
        P(
            A[5],
            A[6],
            A[7],
            &mut temp1, // &mut ctx.state[0],
            A[1],
            A[2],
            A[3],
            &mut A[4],
            W[i + 3],
            K[i + 3],
        );
        A[0] = temp1;

        temp1 = A[7];
        P(
            A[4],
            A[5],
            A[6],
            &mut temp1, // &mut ctx.state[7],
            A[0],
            A[1],
            A[2],
            &mut A[3],
            W[i + 4],
            K[i + 4],
        );
        A[7] = temp1;

        temp1 = A[6];
        P(
            A[3],
            A[4],
            A[5],
            &mut temp1, // &mut ctx.state[6],
            A[7],
            A[0],
            A[1],
            &mut A[2],
            W[i + 5],
            K[i + 5],
        );
        A[6] = temp1;

        temp1 = A[5];
        P(
            A[2],
            A[3],
            A[4],
            &mut temp1, // &mut ctx.state[5],
            A[6],
            A[7],
            A[0],
            &mut A[1],
            W[i + 6],
            K[i + 6],
        );
        A[5] = temp1;

        temp1 = A[4];
        P(
            A[1],
            A[2],
            A[3],
            &mut temp1, // &mut ctx.state[4],
            A[5],
            A[6],
            A[7],
            &mut A[0],
            W[i + 7],
            K[i + 7],
        );
        A[4] = temp1;
    }

    // for i in (16..64).step_by(8) {
    //     P( A[0], A[1], A[2],&mut ctx.state[3], A[4], A[5], A[6],&mut A[7], R(i+0), K[i+0] );
    //     P( A[7], A[0], A[1],&mut ctx.state[2], A[3], A[4], A[5],&mut A[6], R(i+1), K[i+1] );
    //     P( A[6], A[7], A[0],&mut ctx.state[1], A[2], A[3], A[4],&mut A[5], R(i+2), K[i+2] );
    //     P( A[5], A[6], A[7],&mut ctx.state[0], A[1], A[2], A[3],&mut A[4], R(i+3), K[i+3] );
    //     P( A[4], A[5], A[6],&mut ctx.state[7], A[0], A[1], A[2],&mut A[3], R(i+4), K[i+4] );
    //     P( A[3], A[4], A[5],&mut ctx.state[6], A[7], A[0], A[1],&mut A[2], R(i+5), K[i+5] );
    //     P( A[2], A[3], A[4],&mut ctx.state[5], A[6], A[7], A[0],&mut A[1], R(i+6), K[i+6] );
    //     P( A[1], A[2], A[3],&mut ctx.state[4], A[5], A[6], A[7],&mut A[0], R(i+7), K[i+7] );
    // }

    let mut R = |t: u32| -> u32 {
        W[t as usize] = S1(W[(t as usize) - 2])
            .wrapping_add(W[(t as usize) - 7])
            .wrapping_add(S0(W[(t as usize) - 15]))
            .wrapping_add(W[(t as usize) - 16]);
        return W[t as usize];
    };

    for i in (16..64).step_by(8) {
        let mut temp1 = A[3];
        P(
            A[0],
            A[1],
            A[2],
            &mut temp1, // &mut ctx.state[3],
            A[4],
            A[5],
            A[6],
            &mut A[7],
            R(i + 0),
            K[i as usize + 0],
        );
        A[3] = temp1;

        temp1 = A[2];
        P(
            A[7],
            A[0],
            A[1],
            &mut temp1, // &mut ctx.state[2],
            A[3],
            A[4],
            A[5],
            &mut A[6],
            R(i + 1),
            K[i as usize + 1],
        );
        A[2] = temp1;

        temp1 = A[1];
        P(
            A[6],
            A[7],
            A[0],
            &mut temp1, // &mut ctx.state[1],
            A[2],
            A[3],
            A[4],
            &mut A[5],
            R(i + 2),
            K[i as usize + 2],
        );
        A[1] = temp1;

        temp1 = A[0];
        P(
            A[5],
            A[6],
            A[7],
            &mut temp1, // &mut ctx.state[0],
            A[1],
            A[2],
            A[3],
            &mut A[4],
            R(i + 3),
            K[i as usize + 3],
        );
        A[0] = temp1;

        temp1 = A[7];
        P(
            A[4],
            A[5],
            A[6],
            &mut temp1, // &mut ctx.state[7],
            A[0],
            A[1],
            A[2],
            &mut A[3],
            R(i + 4),
            K[i as usize + 4],
        );
        A[7] = temp1;

        temp1 = A[6];
        P(
            A[3],
            A[4],
            A[5],
            &mut temp1, // &mut ctx.state[6],
            A[7],
            A[0],
            A[1],
            &mut A[2],
            R(i + 5),
            K[i as usize + 5],
        );
        A[6] = temp1;

        temp1 = A[5];
        P(
            A[2],
            A[3],
            A[4],
            &mut temp1, // &mut ctx.state[5],
            A[6],
            A[7],
            A[0],
            &mut A[1],
            R(i + 6),
            K[i as usize + 6],
        );
        A[5] = temp1;

        temp1 = A[4];
        P(
            A[1],
            A[2],
            A[3],
            &mut temp1, // &mut ctx.state[4],
            A[5],
            A[6],
            A[7],
            &mut A[0],
            R(i + 7),
            K[i as usize + 7],
        );
        A[4] = temp1;
    }
    // #endif /* MBEDTLS_SHA256_SMALLER */ if ended here

    for i in 0..8 {
        ctx.state[i] = ctx.state[i].wrapping_add(A[i]);
    }

    return 0;
}

fn mbedtls_sha256_update_ret(ctx: &mut MdContextSHA256, input: &Vec<u8>, mut ilen: usize) -> i32 {
    use std::convert::TryFrom;

    let mut ret: i32 = -0x006E;
    let mut fill: usize = 0;
    let mut left: u32 = 0;
    let mut iptr: usize = 0;

    if ilen == 0 {
        return 0;
    }

    left = ctx.total[0] & 0x3Fu32;
    fill = (64u32 - left) as usize;

    ctx.total[0] = ctx.total[0].wrapping_add(ilen as u32);
    ctx.total[0] = ctx.total[0] & 0xFFFFFFFFu32;
    if ctx.total[0] < ilen as u32 {
        ctx.total[1] = ctx.total[1].wrapping_add(1);
    }

    if left != 0 && ilen >= fill {
        ctx.buffer[left as usize..(left as usize) + fill].clone_from_slice(&input[..fill]);

        ret = mbedtls_internal_sha256_process(ctx, &(ctx.buffer.clone()));
        if ret != 0 {
            return ret;
        }

        iptr += fill;
        ilen -= fill;
        left = 0;
    }

    while ilen >= 64 {
        ret = mbedtls_internal_sha256_process(ctx, &input[iptr..]);
        if ret != 0 {
            return ret;
        }

        iptr += 64;
        ilen -= 64;
    }

    if ilen > 0 {
        ctx.buffer[left as usize..(left as usize) + ilen]
            .clone_from_slice(&input[iptr..iptr + ilen]);
    }

    return 0;
}

// unsigned char output[32] need to define size as 32
fn mbedtls_sha256_finish_ret(ctx: &mut MdContextSHA256, output: &mut Vec<u8>) -> i32 {
    let mut ret: i32 = -0x006E;

    let (mut used, mut high, mut low): (u32, u32, u32) = (0, 0, 0);

    used = ctx.total[0] & 0x3Fu32;
    ctx.buffer[used as usize] = 0x80;
    used = used.wrapping_add(1);

    if used <= 56 {
        let mut i: usize;
        for i in used..(56) {
            ctx.buffer[i as usize] = 0;
        }
    } else {
        let mut i: usize;
        for i in used..(64) {
            ctx.buffer[i as usize] = 0;
        }

        ret = mbedtls_internal_sha256_process(ctx, &(ctx.buffer.clone()));

        if ret != 0 {
            return ret;
        }

        // memset( ctx->buffer, 0, 56 ); - check if correct.
        for i in 0..56 {
            ctx.buffer[i as usize] = 0;
        }
    }

    high = (ctx.total[0] >> 29) | (ctx.total[1] << 3);
    low = ctx.total[0] << 3;

    PUT_UINT32_BE(high, &mut ctx.buffer[56..60]);
    PUT_UINT32_BE(low, &mut ctx.buffer[60..64]);

    ret = mbedtls_internal_sha256_process(ctx, &(ctx.buffer.clone()));

    if ret != 0 {
        return ret;
    }

    PUT_UINT32_BE(ctx.state[0], &mut output[0..4]);
    PUT_UINT32_BE(ctx.state[1], &mut output[4..8]);
    PUT_UINT32_BE(ctx.state[2], &mut output[8..12]);
    PUT_UINT32_BE(ctx.state[3], &mut output[12..16]);
    PUT_UINT32_BE(ctx.state[4], &mut output[16..20]);
    PUT_UINT32_BE(ctx.state[5], &mut output[20..24]);
    PUT_UINT32_BE(ctx.state[6], &mut output[24..28]);

    if ctx.is224 == 0 {
        PUT_UINT32_BE(ctx.state[7], &mut output[28..32]);
    }
    return 0;
}

fn mbedtls_sha256_ret(input: &Vec<u8>, ilen: usize, output: &mut Vec<u8>, is224: i32) -> i32 {
    let mut ret: i32 = -0x006E;
    let mut ctx: MdContextSHA256 = MdContextSHA256 {
        total: Vec::new(),
        state: Vec::new(),
        buffer: Vec::new(),
        is224: 0,
    };

    mbedtls_sha256_init(&mut ctx);
    ret = mbedtls_sha256_starts_ret(&mut ctx, is224);
    if ret != 0 {
        mbedtls_sha256_free(&mut ctx);
        return ret;
    }

    ret = mbedtls_sha256_update_ret(&mut ctx, input, ilen);
    if ret != 0 {
        mbedtls_sha256_free(&mut ctx);
        return ret;
    }

    ret = mbedtls_sha256_finish_ret(&mut ctx, output);
    if ret != 0 {
        mbedtls_sha256_free(&mut ctx);
        return ret;
    }

    mbedtls_sha256_free(&mut ctx);
    return ret;
}

/*
 * FIPS-180-2 test vectors
 */
#[cfg(test)]
pub mod test {
    #[test]

    fn self_test() {
        use super::mbedtls_sha256_finish_ret;
        use super::mbedtls_sha256_free;
        use super::mbedtls_sha256_init;
        use super::mbedtls_sha256_starts_ret;
        use super::mbedtls_sha256_update_ret;

        const sha256_test_buf: [&str; 3] = [
            "abc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "",
        ];

        const sha256_test_buflen: [usize; 3] = [3, 56, 1000];

        const sha256_test_sum: [[u8; 32]; 6] = [
            /*
             * SHA-224 test vectors
             */
            // padding added to convert 28 to 32
            [
                0x23, 0x09, 0x7D, 0x22, 0x34, 0x05, 0xD8, 0x22, 0x86, 0x42, 0xA4, 0x77, 0xBD, 0xA2,
                0x55, 0xB3, 0x2A, 0xAD, 0xBC, 0xE4, 0xBD, 0xA0, 0xB3, 0xF7, 0xE3, 0x6C, 0x9D, 0xA7,
                0x00, 0x00, 0x00, 0x00,
            ],
            [
                0x75, 0x38, 0x8B, 0x16, 0x51, 0x27, 0x76, 0xCC, 0x5D, 0xBA, 0x5D, 0xA1, 0xFD, 0x89,
                0x01, 0x50, 0xB0, 0xC6, 0x45, 0x5C, 0xB4, 0xF5, 0x8B, 0x19, 0x52, 0x52, 0x25, 0x25,
                0x00, 0x00, 0x00, 0x00,
            ],
            [
                0x20, 0x79, 0x46, 0x55, 0x98, 0x0C, 0x91, 0xD8, 0xBB, 0xB4, 0xC1, 0xEA, 0x97, 0x61,
                0x8A, 0x4B, 0xF0, 0x3F, 0x42, 0x58, 0x19, 0x48, 0xB2, 0xEE, 0x4E, 0xE7, 0xAD, 0x67,
                0x00, 0x00, 0x00, 0x00,
            ],
            /*
             * SHA-256 test vectors
             */
            [
                0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
                0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
                0xF2, 0x00, 0x15, 0xAD,
            ],
            [
                0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E,
                0x60, 0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4,
                0x19, 0xDB, 0x06, 0xC1,
            ],
            [
                0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92, 0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7,
                0x3E, 0x67, 0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E, 0x04, 0x6D, 0x39, 0xCC,
                0xC7, 0x11, 0x2C, 0xD0,
            ],
        ];

        let mut i: i32;
        let mut j: i32;
        let mut k: i32;
        let mut buflen: i32;
        let mut ret: i32 = 0;

        let mut buf: Vec<u8> = vec![0; 1024];
        let mut sha256sum: Vec<u8> = vec![0; 32];

        use super::MdContextSHA256;
        let mut ctx: MdContextSHA256 = MdContextSHA256 {
            total: Vec::new(),
            state: Vec::new(),
            buffer: Vec::new(),
            is224: 0,
        };

        mbedtls_sha256_init(&mut ctx);

        for i in 0..6 {
            j = i % 3;

            // k = i < 3;
            if i < 3 {
                k = 1;
            } else {
                k = 0;
            }

            println!(
                "Running SHA-256 test Number {0} with value of k as {1}",
                i + 1,
                k
            );
            println!("SHA-256 Sum before: {:?}", sha256sum);
            println!("Test Sum before: {:?}", sha256_test_sum[i as usize]);

            assert_eq!(0, mbedtls_sha256_starts_ret(&mut ctx, k));

            if j == 2 {
                //memset(buf, 'a', buflen = 1000);
                for i in 0..1000 {
                    let x = 'a';
                    buf[i] = x as u8;
                }

                for j in 0..1000 {
                    assert_eq!(0, mbedtls_sha256_update_ret(&mut ctx, &buf, 1000));
                }
            } else {
                assert_eq!(
                    0,
                    mbedtls_sha256_update_ret(
                        &mut ctx,
                        &sha256_test_buf[j as usize].as_bytes().to_vec(),
                        sha256_test_buflen[j as usize]
                    )
                );
            }

            assert_eq!(0, mbedtls_sha256_finish_ret(&mut ctx, &mut sha256sum));

            println!("\n before compare\n");

            use std::cmp;
            fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
                a.iter()
                    .zip(b)
                    .map(|(x, y)| x.cmp(y))
                    .find(|&ord| ord != cmp::Ordering::Equal)
                    .unwrap_or(a.len().cmp(&b.len()))
            }
            println!("SHA256 Sum after Hashing : {:?}", sha256sum);
            println!("Test Sum after Hashing: {:?}", sha256_test_sum[i as usize]);

            assert_eq!(
                cmp::Ordering::Equal,
                compare(sha256sum.as_ref(), &sha256_test_sum[i as usize])
            );

            println!("********* Test Case {} is Passed*********** \n", i + 1);
        }
        println!(" ");

        mbedtls_sha256_free(&mut ctx);
    }
}
