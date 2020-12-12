use crate::error;

/// Constructs an u32 from a given slice of u8 
/// assuming little endian representation 
fn get_uint32_le(b: &[u8; 4]) -> u32{    
    return  u32::from(b[0])
        |   u32::from(b[1]) << 8
        |   u32::from(b[2]) << 16
        |   u32::from(b[3]) << 24;
}
/// Stores u32 to u8 slice of 4 elements
/// assuming little endian representation
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

///Classical c-like logical shift left
fn shift_left(x: u32, n: u32)->u32{
    if n>31{
        return 0;
    }
    return x<<n;
}

pub(super) fn internal_process(ctx: &mut super::MdContext, data: &[u8]) -> i32{
    // use std::convert::TryInto;

    let mut X: Vec<u32> = vec![0; 16];
    let (mut A, mut B, mut C, mut D): (u32, u32, u32, u32) = (0, 0, 0, 0);

    for i in 0..16{
        X[i] = get_uint32_le(&[data[i*4], 
                            data[i*4+1], 
                            data[i*4+2], 
                            data[i*4+3]]);
    }

    
    let S = |mut x: u32, n: u32|
                (   shift_left(x, n) | 
                    ((x & 0xFFFFFFFF) >> (32 - (n)))
                );

    A = ctx.state[0];
    B = ctx.state[1];
    C = ctx.state[2];
    D = ctx.state[3];

    let F = |x: u32, y: u32, z: u32| (x&y | !x&z);
    
    let P = |a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32| 
            {
                *a = (*a).wrapping_add(F(b, c, d));
                *a = (*a).wrapping_add(x);
                *a = S(*a, s);
            };

    P( &mut A, B, C, D, X[ 0],  3 );
    P( &mut D, A, B, C, X[ 1],  7 );
    P( &mut C, D, A, B, X[ 2], 11 );
    P( &mut B, C, D, A, X[ 3], 19 );
    P( &mut A, B, C, D, X[ 4],  3 );
    P( &mut D, A, B, C, X[ 5],  7 );
    P( &mut C, D, A, B, X[ 6], 11 );
    P( &mut B, C, D, A, X[ 7], 19 );
    P( &mut A, B, C, D, X[ 8],  3 );
    P( &mut D, A, B, C, X[ 9],  7 );
    P( &mut C, D, A, B, X[10], 11 );
    P( &mut B, C, D, A, X[11], 19 );
    P( &mut A, B, C, D, X[12],  3 );
    P( &mut D, A, B, C, X[13],  7 );
    P( &mut C, D, A, B, X[14], 11 );
    P( &mut B, C, D, A, X[15], 19 );
        
    let F = |x: u32, y: u32, z: u32| (x&y | x&z | y&z);
    let P = |a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32| 
            {
                *a = (*a).wrapping_add(F(b, c, d)).wrapping_add(x).wrapping_add(0x5A827999);
                *a = S(*a, s);
            };

    P( &mut A, B, C, D, X[ 0],  3 );
    P( &mut D, A, B, C, X[ 4],  5 );
    P( &mut C, D, A, B, X[ 8],  9 );
    P( &mut B, C, D, A, X[12], 13 );
    P( &mut A, B, C, D, X[ 1],  3 );
    P( &mut D, A, B, C, X[ 5],  5 );
    P( &mut C, D, A, B, X[ 9],  9 );
    P( &mut B, C, D, A, X[13], 13 );
    P( &mut A, B, C, D, X[ 2],  3 );
    P( &mut D, A, B, C, X[ 6],  5 );
    P( &mut C, D, A, B, X[10],  9 );
    P( &mut B, C, D, A, X[14], 13 );
    P( &mut A, B, C, D, X[ 3],  3 );
    P( &mut D, A, B, C, X[ 7],  5 );
    P( &mut C, D, A, B, X[11],  9 );
    P( &mut B, C, D, A, X[15], 13 ); 
    
    let F = |x: u32, y: u32, z: u32| (x ^ y ^ z);
    let P = |a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32| 
            {
                *a = (*a).wrapping_add(F(b, c, d));
                *a = (*a).wrapping_add(x);
                *a = (*a).wrapping_add(0x6ED9EBA1);
                *a = S(*a, s);
            };
    
    P( &mut A, B, C, D, X[ 0],  3 );
    P( &mut D, A, B, C, X[ 8],  9 );
    P( &mut C, D, A, B, X[ 4], 11 );
    P( &mut B, C, D, A, X[12], 15 );
    P( &mut A, B, C, D, X[ 2],  3 );
    P( &mut D, A, B, C, X[10],  9 );
    P( &mut C, D, A, B, X[ 6], 11 );
    P( &mut B, C, D, A, X[14], 15 );
    P( &mut A, B, C, D, X[ 1],  3 );
    P( &mut D, A, B, C, X[ 9],  9 );
    P( &mut C, D, A, B, X[ 5], 11 );
    P( &mut B, C, D, A, X[13], 15 );
    P( &mut A, B, C, D, X[ 3],  3 );
    P( &mut D, A, B, C, X[11],  9 );
    P( &mut C, D, A, B, X[ 7], 11 );
    P( &mut B, C, D, A, X[15], 15 );
    
    ctx.state[0] = ctx.state[0].wrapping_add(A);
    ctx.state[1] = ctx.state[1].wrapping_add(B);
    ctx.state[2] = ctx.state[2].wrapping_add(C);
    ctx.state[3] = ctx.state[3].wrapping_add(D);
    
    return 0;
}

pub(super) fn update_ret(ctx: &mut super::MdContext, input: &Vec<u8>, mut ilen: usize) -> i32{
    use std::convert::TryFrom;

    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut fill: usize = 0;
    let mut left: u32 = 0;
    let mut iptr: usize = 0;

    if ilen==0{
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

        ret = internal_process(ctx, &(ctx.buffer.clone()));
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

const padding: [u8; 64] = [
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

pub(super) fn finish_ret(ctx: &mut super::MdContext, output: &mut Vec<u8>) -> i32{
    let mut ret = error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut last: u32 = 0;
    let mut padn: u32 = 0;
    let mut high: u32 = 0;
    let mut low: u32 = 0;
    let mut msglen: [u8; 8] = [0u8; 8];

    high = (ctx.total[0] >> 29)
         | (ctx.total[1] << 3 );
    low  = ctx.total[0] << 3;

    put_uint32_le(low, &mut msglen[0..4]);
    put_uint32_le(high, &mut msglen[4..8]);

    last = ctx.total[0] & 0x3F;
    padn = if last<56{
                56-last
            }else{
                120-last
            };
    ret = update_ret(ctx, &padding.to_vec(), padn as usize);
    if ret!=0{
        return ret;
    }

    ret = update_ret(ctx, &msglen.to_vec(), 8);
    if ret!=0{
        return ret;
    }

    put_uint32_le(ctx.state[0], &mut output[0..4]);
    put_uint32_le(ctx.state[1], &mut output[4..8]);
    put_uint32_le(ctx.state[2], &mut output[8..12]);
    put_uint32_le(ctx.state[3], &mut output[12..16]);

    return 0;
}

pub(super) fn ret(input: &Vec<u8>, ilen: usize, output: &mut Vec<u8>) -> i32{
    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
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
mod test{

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

    const test_sum: [[u8; 16]; 7] = 
        [
              [ 0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31,
                0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0 ],
              [ 0xBD, 0xE5, 0x2C, 0xB3, 0x1D, 0xE3, 0x3E, 0x46,
                0x24, 0x5E, 0x05, 0xFB, 0xDB, 0xD6, 0xFB, 0x24 ],
              [ 0xA4, 0x48, 0x01, 0x7A, 0xAF, 0x21, 0xD8, 0x52,
                0x5F, 0xC1, 0x0A, 0xE8, 0x7A, 0xA6, 0x72, 0x9D ],
              [ 0xD9, 0x13, 0x0A, 0x81, 0x64, 0x54, 0x9F, 0xE8,
                0x18, 0x87, 0x48, 0x06, 0xE1, 0xC7, 0x01, 0x4B ],
              [ 0xD7, 0x9E, 0x1C, 0x30, 0x8A, 0xA5, 0xBB, 0xCD,
                0xEE, 0xA8, 0xED, 0x63, 0xDF, 0x41, 0x2D, 0xA9 ],
              [ 0x04, 0x3F, 0x85, 0x82, 0xF2, 0x41, 0xDB, 0x35,
                0x1C, 0xE6, 0x27, 0xE1, 0x53, 0xE7, 0xF0, 0xE4 ],
              [ 0xE3, 0x3B, 0x4D, 0xDC, 0x9C, 0x38, 0xF2, 0x19,
                0x9C, 0x3E, 0x7B, 0x16, 0x4F, 0xCC, 0x05, 0x36 ]
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
        let mut md4sum: Vec<u8> = vec![0; 16];
        for i in 0..7{
            assert_eq!(0, super::ret(&test_str[i].as_bytes().to_vec(), test_strlen[i], &mut md4sum));
            
            print!("MD4({}) = ", test_str[i]);
            for i in md4sum.iter(){
                print!("{:02x}", i);
            }
            println!();

            assert_eq!(cmp::Ordering::Equal, compare(md4sum.as_ref(), &test_sum[i]));
        }
    }
}