/*
Conversion of sha512.c
*/
struct MdContextSHA512 {
    total: Vec<u64>,
    state: Vec<u64>,
    buffer: Vec<u8>,
    is384: i64,
}

fn main() {
    unimplemented!();
}

fn mbedtls_sha512_init(ctx: &mut MdContextSHA512) {
    ctx.total = vec![0u64; 2];
    ctx.state = vec![0u64; 8];
    ctx.buffer = vec![0u8; 128];

    ctx.is384 = 0u64 as i64;
}

fn mbedtls_sha512_free(ctx: &mut MdContextSHA512) {
    for i in &mut ctx.total.iter_mut() {
        *i = 0u64;
    }
    ctx.total.resize(0, 0);
    for i in &mut ctx.state.iter_mut() {
        *i = 0u64;
    }
    ctx.state.resize(0, 0);
    for i in &mut ctx.buffer.iter_mut() {
        *i = 0u8;
    }
    ctx.buffer.resize(0, 0);

    // to be checked once
    ctx.is384 = 0u64 as i64;
}

fn mbedtls_sha512_clone(dst: &mut MdContextSHA512, src: &MdContextSHA512) {
    dst.buffer[..].clone_from_slice(&src.buffer[..]);
    dst.state[..].clone_from_slice(&src.state[..]);
    dst.total[..].clone_from_slice(&src.total[..]);
    dst.is384 = src.is384;
}

fn mbedtls_sha512_starts_ret(ctx: &mut MdContextSHA512, is384: i64) -> i64 {
    //Not converted #if defined and all
    //Not converted  )
    println!(" Inside start ret\n");

    ctx.total[0] = 0;
    ctx.total[1] = 0;

    if is384 == 0 {
        /* SHA-512 */
        ctx.state[0] = 0x6A09E667F3BCC908;
        ctx.state[1] = 0xBB67AE8584CAA73B;
        ctx.state[2] = 0x3C6EF372FE94F82B;
        ctx.state[3] = 0xA54FF53A5F1D36F1;
        ctx.state[4] = 0x510E527FADE682D1;
        ctx.state[5] = 0x9B05688C2B3E6C1F;
        ctx.state[6] = 0x1F83D9ABFB41BD6B;
        ctx.state[7] = 0x5BE0CD19137E2179;
    } else {
        /* SHA-384 */
        //println!("\n SHA-384\n");
        // #if defined(MBEDTLS_SHA512_NO_SHA384)
        //         return( MBEDTLS_ERR_SHA512_BAD_INPUT_DATA );
        // #else
        // yet to check this
        ctx.state[0] = 0xCBBB9D5DC1059ED8;
        ctx.state[1] = 0x629A292A367CD507;
        ctx.state[2] = 0x9159015A3070DD17;
        ctx.state[3] = 0x152FECD8F70E5939;
        ctx.state[4] = 0x67332667FFC00B31;
        ctx.state[5] = 0x8EB44A8768581511;
        ctx.state[6] = 0xDB0C2E0D64F98FA7;
        ctx.state[7] = 0x47B5481DBEFA4FA4;
    }

    ctx.is384 = is384;
    // println!("\n ctx.is384- {:?}\n", ctx.is384);
    return 0;
}

fn GET_UINT64_BE(b: &[u8; 8]) -> u64 {
    return (u64::from(b[0]) << 56)
        | (u64::from(b[1]) << 48)
        | (u64::from(b[2]) << 40)
        | (u64::from(b[3]) << 32)
        | (u64::from(b[4]) << 24)
        | (u64::from(b[5]) << 16)
        | (u64::from(b[6]) << 8)
        | (u64::from(b[7]));
}

fn PUT_UINT64_BE(n: u64, b: &mut [u8]) {
    use std::convert::TryFrom;
    b[0] = (n >> 56) as u8;
    b[1] = (n >> 48) as u8;
    b[2] = (n >> 40) as u8;
    b[3] = (n >> 32) as u8;
    b[4] = (n >> 24) as u8;
    b[5] = (n >> 16) as u8;
    b[6] = (n >> 8) as u8;
    b[7] = (n) as u8;
}

fn mbedtls_internal_sha512_process(ctx: &mut MdContextSHA512, data: &[u8]) -> i64 {
    println!(" Inside process\n");
    let mut W: Vec<u64> = vec![0; 80];
    let mut A: Vec<u64> = vec![0; 8];
    let (mut temp1, mut temp2): (u64, u64) = (0, 0);
    let mut i: u64;

    let SHR = |x: u64, n: u64| ((x) >> (n));

    let ROTR = |x: u64, n: u64| (SHR(x, n) | ((x) << (64 - (n))));

    let S0 = |x: u64| (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7));
    let S1 = |x: u64| (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6));

    let S2 = |x: u64| (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39));
    let S3 = |x: u64| (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41));

    let F0 = |x: u64, y: u64, z: u64| (((x) & (y)) | ((z) & ((x) | (y))));
    let F1 = |x: u64, y: u64, z: u64| ((z) ^ ((x) & ((y) ^ (z))));

    let P = |a: u64,
             b: u64,
             c: u64,
             d: &mut u64,
             e: u64,
             f: u64,
             g: u64,
             h: &mut u64,
             x: u64,
             T: u64| {
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

    const K: [u64; 80] = [
        0x428A2F98D728AE22,
        0x7137449123EF65CD,
        0xB5C0FBCFEC4D3B2F,
        0xE9B5DBA58189DBBC,
        0x3956C25BF348B538,
        0x59F111F1B605D019,
        0x923F82A4AF194F9B,
        0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242,
        0x12835B0145706FBE,
        0x243185BE4EE4B28C,
        0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F,
        0x80DEB1FE3B1696B1,
        0x9BDC06A725C71235,
        0xC19BF174CF692694,
        0xE49B69C19EF14AD2,
        0xEFBE4786384F25E3,
        0x0FC19DC68B8CD5B5,
        0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275,
        0x4A7484AA6EA6E483,
        0x5CB0A9DCBD41FBD4,
        0x76F988DA831153B5,
        0x983E5152EE66DFAB,
        0xA831C66D2DB43210,
        0xB00327C898FB213F,
        0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2,
        0xD5A79147930AA725,
        0x06CA6351E003826F,
        0x142929670A0E6E70,
        0x27B70A8546D22FFC,
        0x2E1B21385C26C926,
        0x4D2C6DFC5AC42AED,
        0x53380D139D95B3DF,
        0x650A73548BAF63DE,
        0x766A0ABB3C77B2A8,
        0x81C2C92E47EDAEE6,
        0x92722C851482353B,
        0xA2BFE8A14CF10364,
        0xA81A664BBC423001,
        0xC24B8B70D0F89791,
        0xC76C51A30654BE30,
        0xD192E819D6EF5218,
        0xD69906245565A910,
        0xF40E35855771202A,
        0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8,
        0x1E376C085141AB53,
        0x2748774CDF8EEB99,
        0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63,
        0x4ED8AA4AE3418ACB,
        0x5B9CCA4F7763E373,
        0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC,
        0x78A5636F43172F60,
        0x84C87814A1F0AB72,
        0x8CC702081A6439EC,
        0x90BEFFFA23631E28,
        0xA4506CEBDE82BDE9,
        0xBEF9A3F7B2C67915,
        0xC67178F2E372532B,
        0xCA273ECEEA26619C,
        0xD186B8C721C0C207,
        0xEADA7DD6CDE0EB1E,
        0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA,
        0x0A637DC5A2C898A6,
        0x113F9804BEF90DAE,
        0x1B710B35131C471B,
        0x28DB77F523047D84,
        0x32CAAB7B40C72493,
        0x3C9EBE0A15C9BEBC,
        0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6,
        0x597F299CFC657E2A,
        0x5FCB6FAB3AD6FAEC,
        0x6C44198C4A475817,
    ];

    for i in 0..8 {
        A[i] = ctx.state[i];
    }

    // #if defined(MBEDTLS_SHA256_SMALLER) this need to be converted
    // for i in 0..80 {
    //     if i < 16 {
    //         // yet to check how to call GET_UINT64_BE with 8 parameter
    //         W[i] = GET_UINT64_BE(&[
    //             data[i << 3],
    //             data[i << 3 + 1],
    //             data[i << 3 + 2],
    //             data[i << 3 + 3],
    //             data[i << 3 + 4],
    //             data[i << 3 + 5],
    //             data[i << 3 + 6],
    //             data[i << 3 + 7],
    //         ]);
    //     } else {
    //         // W[i] = S1(W[i - 2]) + W[i - 7] + S0(W[i - 15]) + W[i - 16];
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
    for i in 0..80 {
        if i < 16 {
            // yet to check how to call GET_UINT64_BE with 8 parameter
            W[i] = GET_UINT64_BE(&[
                data[(i << 3)],
                data[(i << 3) + 1],
                data[(i << 3) + 2],
                data[(i << 3) + 3],
                data[(i << 3) + 4],
                data[(i << 3) + 5],
                data[(i << 3) + 6],
                data[(i << 3) + 7],
            ]);
        } else {
            W[i] = S1(W[i - 2]);
            W[i] = W[i].wrapping_add(W[i - 7]);
            W[i] = W[i].wrapping_add(S0(W[i - 15]));
            W[i] = W[i].wrapping_add(W[i - 16]);
        }
    }
    i = 0;

    // do while loop implemented as loop and break
    // loop
    // {
    //     P( A[0], A[1], A[2],&mut A[3], A[4], A[5], A[6], A[7], W[i as usize], K[i as usize] ); i=i+1;
    //     P( A[7], A[0], A[1],&mut A[2], A[3], A[4], A[5], A[6], W[i as usize], K[i as usize] ); i=i+1;
    //     P( A[6], A[7], A[0],&mut A[1], A[2], A[3], A[4], A[5], W[i as usize], K[i as usize] ); i=i+1;
    //     P( A[5], A[6], A[7],&mut A[0], A[1], A[2], A[3], A[4], W[i as usize], K[i as usize] ); i=i+1;
    //     P( A[4], A[5], A[6],&mut A[7], A[0], A[1], A[2], A[3], W[i as usize], K[i as usize] ); i=i+1;
    //     P( A[3], A[4], A[5],&mut A[6], A[7], A[0], A[1], A[2], W[i as usize], K[i as usize] ); i=i+1;
    //     P( A[2], A[3], A[4],&mut A[5], A[6], A[7], A[0], A[1], W[i as usize], K[i as usize] ); i=i+1;
    //     P( A[1], A[2], A[3],&mut A[4], A[5], A[6], A[7], A[0], W[i as usize], K[i as usize] ); i=i+1;

    //     // while( i < 80 ); is executed
    //     if i>=80 {
    //      break;
    //   }
    // }
    loop {
        let mut temp1 = A[3];
        P(
            A[0],
            A[1],
            A[2],
            &mut temp1,
            A[4],
            A[5],
            A[6],
            &mut A[7],
            W[i as usize],
            K[i as usize],
        );
        A[3] = temp1;
        i = i + 1;

        temp1 = A[2];
        P(
            A[7],
            A[0],
            A[1],
            &mut temp1, // &mut A[2],
            A[3],
            A[4],
            A[5],
            &mut A[6],
            W[i as usize],
            K[i as usize],
        );
        i = i + 1;
        A[2] = temp1;

        temp1 = A[1];
        P(
            A[6],
            A[7],
            A[0],
            &mut temp1,
            A[2],
            A[3],
            A[4],
            &mut A[5],
            W[i as usize],
            K[i as usize],
        );
        i = i + 1;
        A[1] = temp1;

        temp1 = A[0];
        P(
            A[5],
            A[6],
            A[7],
            &mut temp1,
            A[1],
            A[2],
            A[3],
            &mut A[4],
            W[i as usize],
            K[i as usize],
        );
        i = i + 1;
        A[0] = temp1;

        temp1 = A[7];
        P(
            A[4],
            A[5],
            A[6],
            &mut temp1,
            A[0],
            A[1],
            A[2],
            &mut A[3],
            W[i as usize],
            K[i as usize],
        );
        i = i + 1;
        A[7] = temp1;

        temp1 = A[6];
        P(
            A[3],
            A[4],
            A[5],
            &mut temp1,
            A[7],
            A[0],
            A[1],
            &mut A[2],
            W[i as usize],
            K[i as usize],
        );
        i = i + 1;
        A[6] = temp1;

        temp1 = A[5];
        P(
            A[2],
            A[3],
            A[4],
            &mut temp1,
            A[6],
            A[7],
            A[0],
            &mut A[1],
            W[i as usize],
            K[i as usize],
        );
        i = i + 1;
        A[5] = temp1;

        temp1 = A[4];
        P(
            A[1],
            A[2],
            A[3],
            &mut temp1,
            A[5],
            A[6],
            A[7],
            &mut A[0],
            W[i as usize],
            K[i as usize],
        );
        i = i + 1;
        A[4] = temp1;

        // while( i < 80 ); is executed
        if i >= 80 {
            break;
        }
    }
    // #endif /* MBEDTLS_SHA256_SMALLER */ if ended here

    for i in 0..8 {
        ctx.state[i] = ctx.state[i].wrapping_add(A[i]);
    }

    return 0;
}

fn mbedtls_sha512_update_ret(ctx: &mut MdContextSHA512, input: &Vec<u8>, mut ilen: usize) -> i64 {
    println!(" Inside update ret\n");
    use std::convert::TryFrom;

    let mut ret: i64 = -0x006E;
    let mut fill: usize = 0;
    let mut left: u64 = 0;
    let mut iptr: usize = 0;

    if ilen == 0 {
        return 0;
    }

    left = ctx.total[0] & 0x7F;
    fill = (128u64 - left) as usize;

    ctx.total[0] = ctx.total[0].wrapping_add(ilen as u64);
    if ctx.total[0] < ilen as u64 {
        ctx.total[1] = ctx.total[1].wrapping_add(1);
    }

    if left != 0 && ilen >= fill {
        ctx.buffer[left as usize..(left as usize) + fill].clone_from_slice(&input[..fill]);

        ret = mbedtls_internal_sha512_process(ctx, &(ctx.buffer.clone()));
        if ret != 0 {
            return ret;
        }

        iptr += fill;
        ilen -= fill;
        left = 0;
    }

    while ilen >= 128 {
        ret = mbedtls_internal_sha512_process(ctx, &input[iptr..]);
        if ret != 0 {
            return ret;
        }

        iptr += 128;
        ilen -= 128;
    }

    if ilen > 0 {
        ctx.buffer[left as usize..(left as usize) + ilen]
            .clone_from_slice(&input[iptr..iptr + ilen]);
    }

    return 0;
}

// unsigned char output[32] need to define size as 32
fn mbedtls_sha512_finish_ret(ctx: &mut MdContextSHA512, output: &mut Vec<u8>) -> i64 {
    println!(" Inside finish ret\n");
    let mut ret: i64 = -0x006E;

    let (mut used, mut high, mut low): (u64, u64, u64) = (0, 0, 0);

    used = ctx.total[0] & 0x7F;
    ctx.buffer[used as usize] = 0x80;
    used = used.wrapping_add(1);
    println!("used value is: {:?}", used);

    if used <= 112 {
        let mut i: usize;
        for i in used..(112) {
            ctx.buffer[i as usize] = 0;
        }
    } else {
        let mut i: usize;
        for i in used..(128) {
            ctx.buffer[i as usize] = 0;
        }

        ret = mbedtls_internal_sha512_process(ctx, &(ctx.buffer.clone()));

        if ret != 0 {
            return ret;
        }

        // memset( ctx->buffer, 0, 56 ); - check if correct.
        for i in 0..112 {
            ctx.buffer[i as usize] = 0;
        }
    }

    high = (ctx.total[0] >> 61) | (ctx.total[1] << 3);
    low = ctx.total[0] << 3;

    PUT_UINT64_BE(high, &mut ctx.buffer[112..120]);
    PUT_UINT64_BE(low, &mut ctx.buffer[120..128]);

    ret = mbedtls_internal_sha512_process(ctx, &(ctx.buffer.clone()));

    if ret != 0 {
        return ret;
    }

    PUT_UINT64_BE(ctx.state[0], &mut output[0..8]);
    PUT_UINT64_BE(ctx.state[1], &mut output[8..16]);
    PUT_UINT64_BE(ctx.state[2], &mut output[16..24]);
    PUT_UINT64_BE(ctx.state[3], &mut output[24..32]);
    PUT_UINT64_BE(ctx.state[4], &mut output[32..40]);
    PUT_UINT64_BE(ctx.state[5], &mut output[40..48]);

    if ctx.is384 == 0 {
        PUT_UINT64_BE(ctx.state[6], &mut output[48..56]);
        PUT_UINT64_BE(ctx.state[7], &mut output[56..64]);
    }
    return 0;
}

fn mbedtls_sha512_ret(input: &Vec<u8>, ilen: usize, output: &mut Vec<u8>, is384: i64) -> i64 {
    println!(" Inside ret\n");
    let mut ret: i64 = -0x006E;
    let mut ctx: MdContextSHA512 = MdContextSHA512 {
        total: Vec::new(),
        state: Vec::new(),
        buffer: Vec::new(),
        is384: 0 as i64,
    };

    mbedtls_sha512_init(&mut ctx);
    ret = mbedtls_sha512_starts_ret(&mut ctx, is384);
    if ret != 0 {
        mbedtls_sha512_free(&mut ctx);
        return ret;
    }

    ret = mbedtls_sha512_update_ret(&mut ctx, input, ilen);
    if ret != 0 {
        mbedtls_sha512_free(&mut ctx);
        return ret;
    }

    ret = mbedtls_sha512_finish_ret(&mut ctx, output);
    if ret != 0 {
        mbedtls_sha512_free(&mut ctx);
        return ret;
    }

    mbedtls_sha512_free(&mut ctx);
    return ret;
}

/*
 * FIPS-180-2 test vectors
 */
#[cfg(test)]
pub mod test {
    #[test]

    fn self_test() {
        use super::mbedtls_sha512_finish_ret;
        use super::mbedtls_sha512_free;
        use super::mbedtls_sha512_init;
        use super::mbedtls_sha512_starts_ret;
        use super::mbedtls_sha512_update_ret;

        const sha512_test_buf: [&str; 3] = [
            "abc",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "",
        ];

        const sha512_test_buflen: [usize; 3] = [3, 112, 1000];

        const sha512_test_sum: [[u8; 64]; 6] = [
            /*
             * SHA-384 test vectors
             */
            // padding added
            [
                0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6,
                0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A,
                0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA,
                0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            [
                0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD,
                0x1B, 0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2, 0x2F, 0xA0, 0x80, 0x86,
                0xE3, 0xB0, 0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3,
                0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            [
                0x9D, 0x0E, 0x18, 0x09, 0x71, 0x64, 0x74, 0xCB, 0x08, 0x6E, 0x83, 0x4E, 0x31, 0x0A,
                0x4A, 0x1C, 0xED, 0x14, 0x9E, 0x9C, 0x00, 0xF2, 0x48, 0x52, 0x79, 0x72, 0xCE, 0xC5,
                0x70, 0x4C, 0x2A, 0x5B, 0x07, 0xB8, 0xB3, 0xDC, 0x38, 0xEC, 0xC4, 0xEB, 0xAE, 0x97,
                0xDD, 0xD8, 0x7F, 0x3D, 0x89, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            /*
             * SHA-512 test vectors
             */
            [
                0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20,
                0x41, 0x31, 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6,
                0x4B, 0x55, 0xD3, 0x9A, 0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA,
                0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD, 0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
                0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
            ],
            [
                0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA, 0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC,
                0x14, 0x3F, 0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1, 0x72, 0x99, 0xAE, 0xAD,
                0xB6, 0x88, 0x90, 0x18, 0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4, 0x33, 0x1B,
                0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A, 0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
                0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09,
            ],
            [
                0xE7, 0x18, 0x48, 0x3D, 0x0C, 0xE7, 0x69, 0x64, 0x4E, 0x2E, 0x42, 0xC7, 0xBC, 0x15,
                0xB4, 0x63, 0x8E, 0x1F, 0x98, 0xB1, 0x3B, 0x20, 0x44, 0x28, 0x56, 0x32, 0xA8, 0x03,
                0xAF, 0xA9, 0x73, 0xEB, 0xDE, 0x0F, 0xF2, 0x44, 0x87, 0x7E, 0xA6, 0x0A, 0x4C, 0xB0,
                0x43, 0x2C, 0xE5, 0x77, 0xC3, 0x1B, 0xEB, 0x00, 0x9C, 0x5C, 0x2C, 0x49, 0xAA, 0x2E,
                0x4E, 0xAD, 0xB2, 0x17, 0xAD, 0x8C, 0xC0, 0x9B,
            ],
        ];

        let mut i: i64;
        let mut j: i64;
        let mut k: i64;
        let mut buflen: i64;
        let mut ret: i64 = 0;

        let mut buf: Vec<u8> = vec![0; 1024];
        let mut sha512sum: Vec<u8> = vec![0; 64];

        use super::MdContextSHA512;
        let mut ctx: MdContextSHA512 = MdContextSHA512 {
            total: Vec::new(),
            state: Vec::new(),
            buffer: Vec::new(),
            is384: 0,
        };

        mbedtls_sha512_init(&mut ctx);

        for i in 0..6 {
            j = i % 3;

            // k = i < 3;
            if i < 3 {
                k = 1;
            } else {
                k = 0;
            }
            // k = 0;

            println!(
                "Running SHA-512 test Number {0} with value of k as {1}",
                i + 1,
                k
            );
            println!("SHA-512 Sum before: {:?}", sha512sum);
            let mut temp_vec = vec![0; 64];
            temp_vec.copy_from_slice(&sha512_test_sum[i as usize]);
            println!("Test Sum before: {:?}", temp_vec);

            assert_eq!(0, mbedtls_sha512_starts_ret(&mut ctx, k));

            if j == 2 {
                //memset(buf, 'a', buflen = 1000);
                for i in 0..1000 {
                    let x = 'a';
                    buf[i] = x as u8;
                }

                for j in 0..1000 {
                    assert_eq!(0, mbedtls_sha512_update_ret(&mut ctx, &buf, 1000));
                }
            } else {
                assert_eq!(
                    0,
                    mbedtls_sha512_update_ret(
                        &mut ctx,
                        &sha512_test_buf[j as usize].as_bytes().to_vec(),
                        sha512_test_buflen[j as usize]
                    )
                );
            }

            assert_eq!(0, mbedtls_sha512_finish_ret(&mut ctx, &mut sha512sum));

            println!("\n before compare\n");

            use std::cmp;
            fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
                a.iter()
                    .zip(b)
                    .map(|(x, y)| x.cmp(y))
                    .find(|&ord| ord != cmp::Ordering::Equal)
                    .unwrap_or(a.len().cmp(&b.len()))
            }
            println!("SHA512 Sum after Hashing : {:?}", sha512sum);
            temp_vec.copy_from_slice(&sha512_test_sum[i as usize]);
            println!("Test Sum after Hashing: {:?}", temp_vec);

            assert_eq!(
                cmp::Ordering::Equal,
                compare(sha512sum.as_ref(), &sha512_test_sum[i as usize])
            );

            println!("********* Test Case {} is Passed*********** \n", i + 1);
        }
        println!(" ");

        mbedtls_sha512_free(&mut ctx);
    }
}
