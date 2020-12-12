/**
 * \brief          MD4 context structure
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
pub struct Context{
    /// number of bytes processed
    total: [u32; 2],
    /// intermediate digest state
    state: [u32; 4],
    /// data block being processed
    buffer: [u8; 64]
}

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
fn put_uint32_le(n: u32, b: &mut[u8; 4]){
    use std::convert::TryFrom;
    b[0] = u8::try_from(n & 0xFF).unwrap();
    b[1] = u8::try_from((n>>8) & 0xFF).unwrap();
    b[2] = u8::try_from((n>>16) & 0xFF).unwrap();
    b[3] = u8::try_from((n>>24) & 0xFF).unwrap();
}

fn init(ctx: &mut Context){
    ctx.buffer = [0; 64];
    ctx.state = [0; 4];
    ctx.total = [0; 2];
}

fn free(ctx: &mut Context){
    ctx.buffer = [0; 64];
    ctx.state = [0; 4];
    ctx.total = [0; 2];
}

fn clone(dst: &mut Context, src: &Context){
    dst.buffer[..].clone_from_slice(&src.buffer[..]);
    dst.state[..].clone_from_slice(&src.state[..]);
    dst.total[..].clone_from_slice(&src.total[..]);
}

fn starts_ret(ctx: &mut Context) -> i32{
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

fn internal_process(ctx: &mut Context, data: &[u8; 64]) -> i32{
    use std::convert::TryInto;

    let mut X: [u32; 16] = [0; 16];
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

#[cfg(test)]
mod test{
    #[test]
    fn test(){
        // assert_eq!(1,0);
    }
}