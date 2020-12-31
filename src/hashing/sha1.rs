use crate::error;

// Done
fn get_uint32_be(b: &[u8; 4]) -> u32{    
    return  (u32::from(b[0]) << 24)
        |   (u32::from(b[1]) << 16)
        |   (u32::from(b[2]) << 8)
        |   (u32::from(b[3])) ;
}

// Done

fn put_uint32_be(n: u32, b: &mut[u8]){
    use std::convert::TryFrom;
    
    b[0] = (n >> 24) as u8;
    b[1] = (n >> 16) as u8;
    b[2] = (n >> 8) as u8;
    b[3] = (n) as u8;
    
}

// Done 
fn zeroize_u8(a: &mut Vec<u8>){
    for i in &mut a.iter_mut(){
        *i = 0u8;
    }
}

// Done

fn zeroize_u32(a: &mut Vec<u32>){
    for i in &mut a.iter_mut(){
        *i = 0u32;
    }
}

// Done

pub(super) fn init(ctx: &mut super::MdContext){
    // check if these values are correct
    ctx.total = vec![0u32; 2];
    ctx.state = vec![0u32; 5];
    ctx.buffer = vec![0u8; 64];
}

// Done

pub(super) fn free(ctx: &mut super::MdContext){
    zeroize_u32(&mut ctx.total);
    ctx.total.resize(0, 0);
    zeroize_u32(&mut ctx.state);
    ctx.state.resize(0, 0);
    zeroize_u8(&mut ctx.buffer);
    ctx.buffer.resize(0, 0);
}

// Done

pub(super) fn clone(dst: &mut super::MdContext, src: &super::MdContext){
    dst.buffer[..].clone_from_slice(&src.buffer[..]);
    dst.state[..].clone_from_slice(&src.state[..]);
    dst.total[..].clone_from_slice(&src.total[..]);
}

// Done

pub(super) fn starts_ret(ctx: &mut super::MdContext) -> i32{
    ctx.total[0] = 0;
    ctx.total[1] = 0;

    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xEFCDAB89;
    ctx.state[2] = 0x98BADCFE;
    ctx.state[3] = 0x10325476;
    ctx.state[4] = 0xC3D2E1F0;

    return 0;
}

pub fn shift_left(x: u32, n: u32)->u32{
    if n>31{
        return 0;
    }
    return (x << n);
}

// Done.

pub(super) fn internal_process(ctx: &mut super::MdContext, data: &[u8]) -> i32{
    let mut W: Vec<u32> = vec![0; 16];
    let (mut A, mut B, mut C, mut D, mut E, mut temp): (u32, u32, u32, u32, u32 ,u32) = (0, 0, 0, 0, 0, 0);

    for i in 0..16{
        W[i] = get_uint32_be(&[data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]]);
    }

    
    let S = |mut x: u32, n: u32|
                {   shift_left(x, n) | 
                    ((x & 0xFFFFFFFF) >> (32 - (n)))
                };


    A = ctx.state[0];
    B = ctx.state[1];
    C = ctx.state[2];
    D = ctx.state[3];
    E = ctx.state[4];


    let F = |x: u32, y: u32, z: u32| ((z) ^ ((x) & ((y) ^ (z))));

    let P = |a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, x: u32|
            {
                *e = (*e).wrapping_add(S(a,5));
                *e = (*e).wrapping_add(F(*b,c,d));
                *e = (*e).wrapping_add(0x5A827999);
                *e = (*e).wrapping_add(x);
                *b = (S(*b,30));
            };

    P( A, &mut B, C, D, &mut E, W[0]  );
    P( E, &mut A, B, C, &mut D, W[1]  );
    P( D, &mut E, A, B, &mut C, W[2]  );
    P( C, &mut D, E, A, &mut B, W[3]  );
    P( B, &mut C, D, E, &mut A, W[4]  );
    P( A, &mut B, C, D, &mut E, W[5]  );
    P( E, &mut A, B, C, &mut D, W[6]  );
    P( D, &mut E, A, B, &mut C, W[7]  );
    P( C, &mut D, E, A, &mut B, W[8]  );
    P( B, &mut C, D, E, &mut A, W[9]  );
    P( A, &mut B, C, D, &mut E, W[10] );
    P( E, &mut A, B, C, &mut D, W[11] );
    P( D, &mut E, A, B, &mut C, W[12] );
    P( C, &mut D, E, A, &mut B, W[13] );
    P( B, &mut C, D, E, &mut A, W[14] );
    P( A, &mut B, C, D, &mut E, W[15] );

    let mut R = |t: i32 | -> u32 {
        temp = W[((t-3) & 0x0F) as usize]^W[((t-8) & 0x0F) as usize]^W[((t-14) & 0x0F) as usize] ^ W[(t & 0x0F) as usize];
        W[(t & 0x0F) as usize] = S(temp, 1);
        return W[(t & 0x0F) as usize];
    };

    P( E, &mut A, B, C, &mut D, R(16) );
    P( D, &mut E, A, B, &mut C, R(17) );
    P( C, &mut D, E, A, &mut B, R(18) );
    P( B, &mut C, D, E, &mut A, R(19) );
        
    let F = |x: u32, y: u32, z: u32| ((x) ^ (y) ^ (z));


    let P = |a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, x: u32|
        {
            *e = (*e).wrapping_add(S(a,5));
            *e = (*e).wrapping_add(F(*b,c,d));
            *e = (*e).wrapping_add(0x6ED9EBA1);
            *e = (*e).wrapping_add(x);
            *b = (S(*b,30));
        };

    P( A, &mut B, C, D, &mut E, R(20) );
    P( E, &mut A, B, C, &mut D, R(21) );
    P( D, &mut E, A, B, &mut C, R(22) );
    P( C, &mut D, E, A, &mut B, R(23) );
    P( B, &mut C, D, E, &mut A, R(24) );
    P( A, &mut B, C, D, &mut E, R(25) );
    P( E, &mut A, B, C, &mut D, R(26) );
    P( D, &mut E, A, B, &mut C, R(27) );
    P( C, &mut D, E, A, &mut B, R(28) );
    P( B, &mut C, D, E, &mut A, R(29) );
    P( A, &mut B, C, D, &mut E, R(30) );
    P( E, &mut A, B, C, &mut D, R(31) );
    P( D, &mut E, A, B, &mut C, R(32) );
    P( C, &mut D, E, A, &mut B, R(33) );
    P( B, &mut C, D, E, &mut A, R(34) );
    P( A, &mut B, C, D, &mut E, R(35) );
    P( E, &mut A, B, C, &mut D, R(36) );
    P( D, &mut E, A, B, &mut C, R(37) );
    P( C, &mut D, E, A, &mut B, R(38) );
    P( B, &mut C, D, E, &mut A, R(39) );

    
    let F = |x: u32, y: u32, z: u32| (((x) & (y)) | ((z) & ((x) | (y))));


    let P = |a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, x: u32|
    {
        *e = (*e).wrapping_add(S(a,5));
        *e = (*e).wrapping_add(F(*b,c,d));
        *e = (*e).wrapping_add(0x8F1BBCDC);
        *e = (*e).wrapping_add(x);
        *b = (S(*b,30));
    };

    P( A, &mut B, C, D, &mut E, R(40) );
    P( E, &mut A, B, C, &mut D, R(41) );
    P( D, &mut E, A, B, &mut C, R(42) );
    P( C, &mut D, E, A, &mut B, R(43) );
    P( B, &mut C, D, E, &mut A, R(44) );
    P( A, &mut B, C, D, &mut E, R(45) );
    P( E, &mut A, B, C, &mut D, R(46) );
    P( D, &mut E, A, B, &mut C, R(47) );
    P( C, &mut D, E, A, &mut B, R(48) );
    P( B, &mut C, D, E, &mut A, R(49) );
    P( A, &mut B, C, D, &mut E, R(50) );
    P( E, &mut A, B, C, &mut D, R(51) );
    P( D, &mut E, A, B, &mut C, R(52) );
    P( C, &mut D, E, A, &mut B, R(53) );
    P( B, &mut C, D, E, &mut A, R(54) );
    P( A, &mut B, C, D, &mut E, R(55) );
    P( E, &mut A, B, C, &mut D, R(56) );
    P( D, &mut E, A, B, &mut C, R(57) );
    P( C, &mut D, E, A, &mut B, R(58) );
    P( B, &mut C, D, E, &mut A, R(59) );

    let F = |x: u32, y: u32, z: u32| ((x) ^ (y) ^ (z));

    let P = |a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, x: u32|
    {
        *e = (*e).wrapping_add(S(a,5));
        *e = (*e).wrapping_add(F(*b,c,d));
        *e = (*e).wrapping_add(0xCA62C1D6);
        *e = (*e).wrapping_add(x);
        *b = (S(*b,30));
    };

    P( A, &mut B, C, D, &mut E, R(60) );
    P( E, &mut A, B, C, &mut D, R(61) );
    P( D, &mut E, A, B, &mut C, R(62) );
    P( C, &mut D, E, A, &mut B, R(63) );
    P( B, &mut C, D, E, &mut A, R(64) );
    P( A, &mut B, C, D, &mut E, R(65) );
    P( E, &mut A, B, C, &mut D, R(66) );
    P( D, &mut E, A, B, &mut C, R(67) );
    P( C, &mut D, E, A, &mut B, R(68) );
    P( B, &mut C, D, E, &mut A, R(69) );
    P( A, &mut B, C, D, &mut E, R(70) );
    P( E, &mut A, B, C, &mut D, R(71) );
    P( D, &mut E, A, B, &mut C, R(72) );
    P( C, &mut D, E, A, &mut B, R(73) );
    P( B, &mut C, D, E, &mut A, R(74) );
    P( A, &mut B, C, D, &mut E, R(75) );
    P( E, &mut A, B, C, &mut D, R(76) );
    P( D, &mut E, A, B, &mut C, R(77) );
    P( C, &mut D, E, A, &mut B, R(78) );
    P( B, &mut C, D, E, &mut A, R(79) );
  
    
    ctx.state[0] = ctx.state[0].wrapping_add(A);
    ctx.state[1] = ctx.state[1].wrapping_add(B);
    ctx.state[2] = ctx.state[2].wrapping_add(C);
    ctx.state[3] = ctx.state[3].wrapping_add(D);
    ctx.state[4] = ctx.state[4].wrapping_add(E);
    
    return 0;
}


pub(super) fn update_ret(ctx: &mut super::MdContext, input: &Vec<u8>, mut ilen: usize) -> i32{
    use std::convert::TryFrom;

    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;;
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


pub(super) fn finish_ret(ctx: &mut super::MdContext, output: &mut Vec<u8>) -> i32{
    let mut ret = error::ERR_ERROR_CORRUPTION_DETECTED;

    let (mut used, mut high, mut low): (u32, u32, u32) = (0, 0, 0);

    used = ctx.total[0] & 0x3Fu32; 
    ctx.buffer[used as usize] = 0x80;
    used = used.wrapping_add(1);

    if used <= 56 {
        let mut i: usize;
        for i in used..(56){
            ctx.buffer[i as usize] = 0;
        }
    }
    else{
        let mut i: usize;
        for i in used..(64){
            ctx.buffer[i as usize] = 0;
        }

        ret = internal_process(ctx, &(ctx.buffer.clone()));

        if ret != 0{
            return ret;
        }

        // memset( ctx->buffer, 0, 56 ); - check if correct.
        for i in 0..56{
            ctx.buffer[i as usize] = 0;
        }

    }

    high = (ctx.total[0] >> 29) | (ctx.total[1] << 3 );
    low  = ctx.total[0] << 3;

    put_uint32_be(high, &mut ctx.buffer[56..60]);
    put_uint32_be(low , &mut ctx.buffer[60..64]);

    ret = internal_process(ctx, &(ctx.buffer.clone()));

    if ret!= 0{
        return ret;
    }

    put_uint32_be(ctx.state[0], &mut output[0..4]);
    put_uint32_be(ctx.state[1], &mut output[4..8]);
    put_uint32_be(ctx.state[2], &mut output[8..12]);
    put_uint32_be(ctx.state[3], &mut output[12..16]);
    put_uint32_be(ctx.state[4], &mut output[16..20]);


    return 0;
}


pub(super) fn ret(input: &Vec<u8>, ilen: usize, output: &mut Vec<u8>) -> i32{
    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;;
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
    use crate::hashing::MdContext;

    #[test]
    pub(super) fn self_test(){



        use super::init;
        use super::free;
        use super::starts_ret;
        use super::update_ret;
        use super::finish_ret;

        const sha1_test_buf: [&str; 3] = ["abc", 
                                         "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                                         ""];                                  

        const sha1_test_buflen: [usize; 3] = [3, 56, 1000];


        const sha1_test_sum: [[u8; 20]; 3] = [
                                        [0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
                                              0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D],
                                              [0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
                                              0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1],
                                              [0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
                                              0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F]
                                        ];

        let mut i: i32;
        let mut j: i32;
        let mut buflen: i32;
        let mut ret: i32 = 0;

        let mut buf: Vec<u8> = vec![0; 1024];
        let mut sha1sum: Vec<u8> = vec![0; 20];

        let mut ctx: MdContext = MdContext{total: Vec::new(), state: Vec::new(), buffer: Vec::new()};

        init(&mut ctx);

        for i in 0..3 {

            println!("SHA-1 test #{}", i+1);
            println!("SHA1Sum before: {:?}", sha1sum);
            println!("TestSum before: {:?}", sha1_test_sum[i]);

            assert_eq!(0, starts_ret(&mut ctx));

            if i == 2 {
                //memset(buf, 'a', buflen = 1000);
                for i in 0..1000{
                    let x = 'a';
                    buf[i] = x as u8;
                }

                for j in 0..1000{
                    assert_eq!(0, update_ret(&mut ctx, &buf, 1000));

                }
            }
            else{
                // update_ret(ctx: &mut Context, input: &Vec<u8>, mut ilen: usize) -> i32
                assert_eq!(0,update_ret(&mut ctx, &sha1_test_buf[i].as_bytes().to_vec(), sha1_test_buflen[i]));

            }



            assert_eq!(0, finish_ret(&mut ctx, &mut sha1sum));

            println!("\n");

            use std::cmp;
            fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
                    a.iter()
                    .zip(b)
                    .map(|(x, y)| x.cmp(y))
                    .find(|&ord| ord != cmp::Ordering::Equal)
                    .unwrap_or(a.len().cmp(&b.len()))
            }



            println!("SHA1Sum After: {:?}", sha1sum);
            println!("TestSum After: {:?}", sha1_test_sum[i]);

            assert_eq!(cmp::Ordering::Equal, compare(sha1sum.as_ref(), &sha1_test_sum[i]));

            println!("Passed. \n");
  
        }

        println!(" ");

        free(&mut ctx);

    }

}

