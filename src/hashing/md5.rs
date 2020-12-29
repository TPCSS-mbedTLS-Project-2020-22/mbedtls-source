use crate::error;

fn get_uint32_le(b: &[u8; 4]) -> u32{    
    return  u32::from(b[0])
        |   u32::from(b[1]) << 8
        |   u32::from(b[2]) << 16
        |   u32::from(b[3]) << 24;
}

fn put_uint32_le(n: u32, b: &mut[u8]){
    use std::convert::TryFrom;
    b[0] = u8::try_from(n & 0xFF).unwrap();
    b[1] = u8::try_from((n>>8) & 0xFF).unwrap();
    b[2] = u8::try_from((n>>16) & 0xFF).unwrap();
    b[3] = u8::try_from((n>>24) & 0xFF).unwrap();
}

fn zeroize_u8(a: &mut Vec<u8>){
    for i in &mut a.iter_mut(){
        *i = 0u8;
    }
}

fn zeroize_u32(a: &mut Vec<u32>){
    for i in &mut a.iter_mut(){
        *i = 0u32;
    }
}

pub(super) fn init(ctx: &mut super::MdContext){
    ctx.total = vec![0u32; 2];
    ctx.state = vec![0u32; 4];
    ctx.buffer = vec![0u8; 64];
}

pub(super) fn free(ctx: &mut super::MdContext){
    zeroize_u32(&mut ctx.total);
    ctx.total.resize(0, 0);
    zeroize_u32(&mut ctx.state);
    ctx.state.resize(0, 0);
    zeroize_u8(&mut ctx.buffer);
    ctx.buffer.resize(0, 0);
}

pub(super) fn clone(dst: &mut super::MdContext, src: &super::MdContext){
    dst.buffer[..].clone_from_slice(&src.buffer[..]);
    dst.state[..].clone_from_slice(&src.state[..]);
    dst.total[..].clone_from_slice(&src.total[..]);
}

pub(super) fn starts_ret(ctx: &mut super::MdContext) -> i32{
    ctx.total[0] = 0;
    ctx.total[1] = 0;

    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xEFCDAB89;
    ctx.state[2] = 0x98BADCFE;
    ctx.state[3] = 0x10325476;

    return 0;
}

fn shift_left(x: u32, n: u32)->u32{
    if n>31{
        return 0;
    }
    return (x << n);
}

// Done.

pub(super) fn internal_process(ctx: &mut super::MdContext, data: &[u8]) -> i32{
    // use std::convert::TryInto;

    let mut X: Vec<u32> = vec![0; 16];
    let (mut A, mut B, mut C, mut D): (u32, u32, u32, u32) = (0, 0, 0, 0);

    for i in 0..16{
        X[i] = get_uint32_le(&[data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]]);
    }

    
    let S = |mut x: u32, n: u32|
                (   shift_left(x, n) | 
                    ((x & 0xFFFFFFFF) >> (32 - (n)))
                );

    A = ctx.state[0];
    B = ctx.state[1];
    C = ctx.state[2];
    D = ctx.state[3];

    let F = |x: u32, y: u32, z: u32| ((z) ^ ((x) & ((y) ^ (z))));

    let P = |a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32 | {
    		*a = (*a).wrapping_add(F(b,c,d));
    		*a = (*a).wrapping_add(X[k as usize]);
    		*a = (*a).wrapping_add(t);
            *a = S(*a,s);
            *a = (*a).wrapping_add(b); 
    };

    P(&mut A, B, C, D,  0,  7, 0xD76AA478 );
    P(&mut D, A, B, C,  1, 12, 0xE8C7B756 );
    P(&mut C, D, A, B,  2, 17, 0x242070DB );
    P(&mut B, C, D, A,  3, 22, 0xC1BDCEEE );
    P(&mut A, B, C, D,  4,  7, 0xF57C0FAF );
    P(&mut D, A, B, C,  5, 12, 0x4787C62A );
    P(&mut C, D, A, B,  6, 17, 0xA8304613 );
    P(&mut B, C, D, A,  7, 22, 0xFD469501 );
    P(&mut A, B, C, D,  8,  7, 0x698098D8 );
    P(&mut D, A, B, C,  9, 12, 0x8B44F7AF );
    P(&mut C, D, A, B, 10, 17, 0xFFFF5BB1 );
    P(&mut B, C, D, A, 11, 22, 0x895CD7BE );
    P(&mut A, B, C, D, 12,  7, 0x6B901122 );
    P(&mut D, A, B, C, 13, 12, 0xFD987193 );
    P(&mut C, D, A, B, 14, 17, 0xA679438E );
    P(&mut B, C, D, A, 15, 22, 0x49B40821 );
        
    let F = |x: u32, y: u32, z: u32| ((y) ^ ((z) & ((x) ^ (y))));

    let P = |a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32 | {
    		*a = (*a).wrapping_add(F(b,c,d));
    		*a = (*a).wrapping_add(X[k as usize]);
    		*a = (*a).wrapping_add(t);
            *a = S(*a,s);
            *a = (*a).wrapping_add(b); 
    };

    P(&mut A, B, C, D,  1,  5, 0xF61E2562 );
    P(&mut D, A, B, C,  6,  9, 0xC040B340 );
    P(&mut C, D, A, B, 11, 14, 0x265E5A51 );
    P(&mut B, C, D, A,  0, 20, 0xE9B6C7AA );
    P(&mut A, B, C, D,  5,  5, 0xD62F105D );
    P(&mut D, A, B, C, 10,  9, 0x02441453 );
    P(&mut C, D, A, B, 15, 14, 0xD8A1E681 );
    P(&mut B, C, D, A,  4, 20, 0xE7D3FBC8 );
    P(&mut A, B, C, D,  9,  5, 0x21E1CDE6 );
    P(&mut D, A, B, C, 14,  9, 0xC33707D6 );
    P(&mut C, D, A, B,  3, 14, 0xF4D50D87 );
    P(&mut B, C, D, A,  8, 20, 0x455A14ED );
    P(&mut A, B, C, D, 13,  5, 0xA9E3E905 );
    P(&mut D, A, B, C,  2,  9, 0xFCEFA3F8 );
    P(&mut C, D, A, B,  7, 14, 0x676F02D9 );
    P(&mut B, C, D, A, 12, 20, 0x8D2A4C8A );

    
    let F = |x: u32, y: u32, z: u32| (x ^ y ^ z);

    let P = |a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32 | {
    		*a = (*a).wrapping_add(F(b,c,d));
    		*a = (*a).wrapping_add(X[k as usize]);
    		*a = (*a).wrapping_add(t);
            *a = S(*a,s);
            *a = (*a).wrapping_add(b); 
    };
    
    P(&mut A, B, C, D,  5,  4, 0xFFFA3942 );
    P(&mut D, A, B, C,  8, 11, 0x8771F681 );
    P(&mut C, D, A, B, 11, 16, 0x6D9D6122 );
    P(&mut B, C, D, A, 14, 23, 0xFDE5380C );
    P(&mut A, B, C, D,  1,  4, 0xA4BEEA44 );
    P(&mut D, A, B, C,  4, 11, 0x4BDECFA9 );
    P(&mut C, D, A, B,  7, 16, 0xF6BB4B60 );
    P(&mut B, C, D, A, 10, 23, 0xBEBFBC70 );
    P(&mut A, B, C, D, 13,  4, 0x289B7EC6 );
    P(&mut D, A, B, C,  0, 11, 0xEAA127FA );
    P(&mut C, D, A, B,  3, 16, 0xD4EF3085 );
    P(&mut B, C, D, A,  6, 23, 0x04881D05 );
    P(&mut A, B, C, D,  9,  4, 0xD9D4D039 );
    P(&mut D, A, B, C, 12, 11, 0xE6DB99E5 );
    P(&mut C, D, A, B, 15, 16, 0x1FA27CF8 );
    P(&mut B, C, D, A,  2, 23, 0xC4AC5665 );

    let F = |x: u32, y: u32, z: u32| ((y) ^ ((x) | !(z)));

    let P = |a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32 | {
    		*a = (*a).wrapping_add(F(b,c,d));
    		*a = (*a).wrapping_add(X[k as usize]);
    		*a = (*a).wrapping_add(t);
            *a = S(*a,s);
            *a = (*a).wrapping_add(b);  
    };

    P(&mut A, B, C, D,  0,  6, 0xF4292244 );
    P(&mut D, A, B, C,  7, 10, 0x432AFF97 );
    P(&mut C, D, A, B, 14, 15, 0xAB9423A7 );
    P(&mut B, C, D, A,  5, 21, 0xFC93A039 );
    P(&mut A, B, C, D, 12,  6, 0x655B59C3 );
    P(&mut D, A, B, C,  3, 10, 0x8F0CCC92 );
    P(&mut C, D, A, B, 10, 15, 0xFFEFF47D );
    P(&mut B, C, D, A,  1, 21, 0x85845DD1 );
    P(&mut A, B, C, D,  8,  6, 0x6FA87E4F );
    P(&mut D, A, B, C, 15, 10, 0xFE2CE6E0 );
    P(&mut C, D, A, B,  6, 15, 0xA3014314 );
    P(&mut B, C, D, A, 13, 21, 0x4E0811A1 );
    P(&mut A, B, C, D,  4,  6, 0xF7537E82 );
    P(&mut D, A, B, C, 11, 10, 0xBD3AF235 );
    P(&mut C, D, A, B,  2, 15, 0x2AD7D2BB );
    P(&mut B, C, D, A,  9, 21, 0xEB86D391 );

    
    ctx.state[0] = ctx.state[0].wrapping_add(A);
    ctx.state[1] = ctx.state[1].wrapping_add(B);
    ctx.state[2] = ctx.state[2].wrapping_add(C);
    ctx.state[3] = ctx.state[3].wrapping_add(D);
    
    return 0;
}

// Done.

pub(super) fn update_ret(ctx: &mut super::MdContext, input: &Vec<u8>, mut ilen: usize) -> i32{
    use std::convert::TryFrom;

    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut fill: usize = 0;
    let mut left: u32 = 0;
    let mut iptr: usize = 0;

    if ilen == 0{
        return 0;
    }

    left = ctx.total[0] & 0x3Fu32;
    fill = (64u32 - left) as usize;

    ctx.total[0] = ctx.total[0].wrapping_add(ilen as u32);
    ctx.total[0] = ctx.total[0]&0xFFFFFFFFu32;

    if ctx.total[0]< ilen as u32{
        ctx.total[1] = ctx.total[1].wrapping_add(1);
    }

    if left!=0 && ilen >= fill{
        ctx.buffer[left as usize..(left as usize)+fill].clone_from_slice(&input[..fill]);

        ret = internal_process(ctx, &(ctx.buffer.clone())); // because Rust doesn't allow two references to the same object.
        if ret!=0{
            return ret;
        }

        iptr += fill;
        ilen -= fill;
        
        left = 0;
    }

    while ilen >= 64{
        ret = internal_process(ctx, &input[iptr..]);
        if ret!=0{
            return ret;
        }

        iptr += 64;
        ilen -= 64;
    }

    if ilen>0{
        ctx.buffer[left as usize .. (left as usize)+ilen].clone_from_slice(&input[iptr..iptr+ilen]);
    }

    return 0;
}

// Done.

pub(super) fn finish_ret(ctx: &mut super::MdContext, output: &mut Vec<u8>) -> i32{
    let mut ret = error::ERR_ERROR_CORRUPTION_DETECTED;

    let (mut used, mut high, mut low): (u32, u32, u32) = (0, 0, 0);

    used = ctx.total[0] & 0x3Fu32; 
    ctx.buffer[used as usize] = 0x80;
    used = used.wrapping_add(1);

    if used <= 56 {

        // memset( ctx->buffer + used, 0, 56 - used );
        let mut i: usize;
        for i in used..(56-used){
            ctx.buffer[i as usize] = 0;
        }
    }
    else{
        // memset( ctx->buffer + used, 0, 64 - used );
        let mut u: usize;
        for i in used..(64-used){
            ctx.buffer[i as usize] = 0;
        }

        ret = internal_process(ctx, &(ctx.buffer.clone()));

        if ret != 0{
            return ret;
        }

        // memset( ctx->buffer, 0, 56 ); 
        for i in 0..56{
            ctx.buffer[i as usize] = 0;
        }

    }

    high = (ctx.total[0] >> 29) | (ctx.total[1] << 3 );
    low  = ctx.total[0] << 3;

    put_uint32_le(low, &mut ctx.buffer[56..60]);
    put_uint32_le(high , &mut ctx.buffer[60..64]);

    ret = internal_process(ctx, &(ctx.buffer.clone()));

    if ret!= 0{
        return ret;
    }

    put_uint32_le(ctx.state[0], &mut output[0..4]);
    put_uint32_le(ctx.state[1], &mut output[4..8]);
    put_uint32_le(ctx.state[2], &mut output[8..12]);
    put_uint32_le(ctx.state[3], &mut output[12..16]);

    return 0;

}

// Done.

pub(super) fn ret(input: &Vec<u8>, ilen: usize, output: &mut Vec<u8>) -> i32{
    let mut ret: i32 = -error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut ctx: super::MdContext = super::MdContext{
        total: Vec::new(),
        state: Vec::new(),
        buffer: Vec::new(),
    };

    init(&mut ctx);
    
    ret = starts_ret(&mut ctx);
    if ret!=0{
        free(&mut ctx);
        return ret;
    }

    ret = update_ret(&mut ctx, input, ilen);
    if ret!=0{
        free(&mut ctx);
        return ret;
    }

    ret = finish_ret(&mut ctx, output);
    if ret!=0{
        free(&mut ctx);
        return ret;
    }

    free(&mut ctx);
    return ret;
}

#[cfg(test)]
pub mod test{

    const test_str: [&str; 7] = 
        [ "",
            "a",
            "abc",
            "message digest",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        ];

    const test_strlen: [usize; 7] = 
        [0, 1, 3, 14, 26, 62, 80];

     const test_sum: [[u8; 16]; 7] = [
		     [ 0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
		      0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E ],
		     [ 0x0C, 0xC1, 0x75, 0xB9, 0xC0, 0xF1, 0xB6, 0xA8,
		      0x31, 0xC3, 0x99, 0xE2, 0x69, 0x77, 0x26, 0x61 ],
		     [ 0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0,
		      0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72 ],
		     [ 0xF9, 0x6B, 0x69, 0x7D, 0x7C, 0xB7, 0x93, 0x8D,
		      0x52, 0x5A, 0x2F, 0x31, 0xAA, 0xF1, 0x61, 0xD0 ],
		     [ 0xC3, 0xFC, 0xD3, 0xD7, 0x61, 0x92, 0xE4, 0x00,
		      0x7D, 0xFB, 0x49, 0x6C, 0xCA, 0x67, 0xE1, 0x3B ],
		     [ 0xD1, 0x74, 0xAB, 0x98, 0xD2, 0x77, 0xD9, 0xF5,
		      0xA5, 0x61, 0x1C, 0x2C, 0x9F, 0x41, 0x9D, 0x9F ],
		     [ 0x57, 0xED, 0xF4, 0xA2, 0x2B, 0xE3, 0xC9, 0x55,
		      0xAC, 0x49, 0xDA, 0x2E, 0x21, 0x07, 0xB6, 0x7A ]
     ];
    
    use std::cmp;
    fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
        a.iter()
            .zip(b)
            .map(|(x, y)| x.cmp(y))
            .find(|&ord| ord != cmp::Ordering::Equal)
            .unwrap_or(a.len().cmp(&b.len()))
    }

    #[test]
    pub(super) fn self_test(){
        let mut md5sum: Vec<u8> = vec![0; 16];
        for i in 0..7{
            assert_eq!(0, super::ret(&test_str[i].as_bytes().to_vec(), test_strlen[i], &mut md5sum));
            /*
            print!("MD5({}) = ", test_str[i]);
            for i in md5sum.iter(){
                print!("{:02x}", i);
            }
            println!();
            */

            assert_eq!(cmp::Ordering::Equal, compare(md5sum.as_ref(), &test_sum[i]));
        }
    }
}