/** 
 * Note: This file does not implement deprecated functions.
 * 
*/
use crate::error;

const PI_SUBST: [u8; 256] = 
[    
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36,
    0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13, 0x62, 0xA7, 0x05, 0xF3,
    0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C,
    0x82, 0xCA, 0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16,
    0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12, 0xBE, 0x4E,
    0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E,
    0xBB, 0x2F, 0xEE, 0x7A, 0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2,
    0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E,
    0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03, 0xFF, 0x19, 0x30, 0xB3,
    0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56,
    0xAA, 0xC6, 0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6,
    0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1, 0x45, 0x9D,
    0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65,
    0xE6, 0x2D, 0xA8, 0x02, 0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0,
    0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C,
    0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26, 0x2C, 0x53, 0x0D, 0x6E,
    0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81,
    0x4D, 0x52, 0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA,
    0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A, 0x78, 0x88,
    0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE,
    0x3B, 0x00, 0x1D, 0x39, 0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58,
    0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99,
    0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14
];

fn zeroize(a: &mut Vec<u8>){
    for i in &mut a.iter_mut(){
        *i = 0;
    }
}

/**
 * \brief          Initialize MD2 context
 *
 * \param ctx      MD2 context to be initialized
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
pub(super) fn init(ctx: &mut super::MdContext_MD2){
    ctx.cksum = vec![0; 16];
    ctx.state = vec![0; 48];
    ctx.buffer = vec![0; 16];
    ctx.left = 0;
}

/**
 * \brief          Clear MD2 context
 *
 * \param ctx      MD2 context to be cleared
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
pub(super) fn free(ctx: &mut super::MdContext_MD2){
    // In perticular what is difference
    // between mbedtls_md2_free and mbedtls_md2_init
    zeroize(&mut ctx.cksum);
    ctx.cksum.resize(0, 0);
    zeroize(&mut ctx.state);
    ctx.state.resize(0, 0);
    zeroize(&mut ctx.buffer);
    ctx.buffer.resize(0, 0);
    ctx.left = 0;
}

/**
 * \brief          Clone (the state of) an MD2 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
pub(super) fn clone(dst: &mut super::MdContext_MD2, src: &super::MdContext_MD2){
    dst.buffer[..].clone_from_slice(&src.buffer[..]);
    dst.cksum[..].clone_from_slice(&src.cksum[..]);
    dst.state[..].clone_from_slice(&src.state[..]);
    dst.left = src.left;
}

/**
 * \brief          MD2 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
pub(super) fn starts_ret(ctx: &mut super::MdContext_MD2) -> i32{
    zeroize(&mut ctx.cksum);
    zeroize(&mut ctx.state);
    zeroize(&mut ctx.buffer);
    ctx.left = 0;
    return 0;
}

/**
 * \brief          MD2 process buffer
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
pub(super) fn update_ret(ctx: &mut super::MdContext_MD2, input: &Vec<u8>, _ilen: usize)->i32{
    let mut ret : i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut fill: usize;
    let mut iptr: usize=0;
    let mut ilen = _ilen;

    while ilen>0{
        if ilen>16-ctx.left{
            fill = 16-ctx.left;
        }else{
            fill = ilen;
        }
        
        ctx.buffer[ctx.left..ctx.left+fill].clone_from_slice(&input[iptr..iptr+fill]);

        ctx.left += fill;
        iptr += fill;
        ilen -= fill;

        if ctx.left == 16{
            ctx.left = 0;
            ret = internal_process(ctx);
            if ret != 0{
                return ret;
            }
        }
    }
    return 0;
}

/**
 * \brief          MD2 final digest
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */

pub(super) fn finish_ret(ctx: &mut super::MdContext_MD2, output: &mut Vec<u8>)->i32{
    use std::convert::TryFrom;

    let mut ret:i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut x: u8 = u8::try_from(16-ctx.left).unwrap();

    for i in ctx.left..16{
        ctx.buffer[i] = x;
    }

    ret = internal_process(ctx);
    if ret!=0{
        return ret;
    }

    ctx.buffer[..].clone_from_slice(&ctx.cksum[..]);
    ret = internal_process(ctx);
    if ret!=0{
        return ret;
    }

    output[..].clone_from_slice(&ctx.state[..16]);

    return 0;
}

/**
 * \brief          MD2 process data block (internal use only)
 *
 * \param ctx      MD2 context
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
pub(super) fn internal_process(ctx: &mut super::MdContext_MD2) -> i32{
    let mut t: u8 = 0;
    
    for i in 0..16{
        ctx.state[i+16] = ctx.buffer[i];
        ctx.state[i+32] = ctx.buffer[i] ^ ctx.state[i];
    }

    for i in 0..18{
        for j in 0..48{
            ctx.state[j] = ctx.state[j] ^ PI_SUBST[usize::from(t)];
            t = ctx.state[j];
        }
        t = t.wrapping_add(i);
    }

    t = ctx.cksum[15];
    
    for i in 0..16{
        ctx.cksum[i] = ctx.cksum[i] ^ PI_SUBST[usize::from(ctx.buffer[i] ^ t)];
        t = ctx.cksum[i];
    }

    return 0;
}

/**
 * \brief          Output = MD2( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
pub fn ret(input: &Vec<u8>, ilen: usize, output: &mut Vec<u8>) -> i32{
    let mut ret:i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut ctx: super::MdContext_MD2 = super::MdContext_MD2{ 
            cksum: vec![0;16], 
            state: vec![0;48], 
            buffer: vec![0;16], 
            left: 0,
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

    return ret;
}


#[cfg(test)]
pub mod test{    
    const test_str: [&str; 7] = [ "",
                                    "a",
                                    "abc",
                                    "message digest",
                                    "abcdefghijklmnopqrstuvwxyz",
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                                    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                                ];

    const test_strlen: [usize; 7] = [0, 1, 3, 14, 26, 62, 80];

    const test_sum: [[u8; 16]; 7] = [
                                        [ 0x83, 0x50, 0xE5, 0xA3, 0xE2, 0x4C, 0x15, 0x3D,
                                            0xF2, 0x27, 0x5C, 0x9F, 0x80, 0x69, 0x27, 0x73],
                                        [ 0x32, 0xEC, 0x01, 0xEC, 0x4A, 0x6D, 0xAC, 0x72,
                                            0xC0, 0xAB, 0x96, 0xFB, 0x34, 0xC0, 0xB5, 0xD1],
                                        [ 0xDA, 0x85, 0x3B, 0x0D, 0x3F, 0x88, 0xD9, 0x9B,
                                            0x30, 0x28, 0x3A, 0x69, 0xE6, 0xDE, 0xD6, 0xBB ],
                                        [ 0xAB, 0x4F, 0x49, 0x6B, 0xFB, 0x2A, 0x53, 0x0B,
                                            0x21, 0x9F, 0xF3, 0x30, 0x31, 0xFE, 0x06, 0xB0 ],
                                        [ 0x4E, 0x8D, 0xDF, 0xF3, 0x65, 0x02, 0x92, 0xAB,
                                            0x5A, 0x41, 0x08, 0xC3, 0xAA, 0x47, 0x94, 0x0B ],
                                        [ 0xDA, 0x33, 0xDE, 0xF2, 0xA4, 0x2D, 0xF1, 0x39,
                                            0x75, 0x35, 0x28, 0x46, 0xC3, 0x03, 0x38, 0xCD ],
                                        [ 0xD5, 0x97, 0x6F, 0x79, 0xD8, 0x3D, 0x3A, 0x0D,
                                            0xC9, 0x80, 0x6C, 0x3C, 0x66, 0xF3, 0xEF, 0xD8 ]
                                ];
    
    ///Credit for compare(): https://codereview.stackexchange.com/a/233878
    use std::cmp;
    fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
        a.iter()
            .zip(b)
            .map(|(x, y)| x.cmp(y))
            .find(|&ord| ord != cmp::Ordering::Equal)
            .unwrap_or(a.len().cmp(&b.len()))
    }

    use super::ret;
    #[test]
    pub fn self_test(){
        let mut md2sum: Vec<u8> = vec![0; 16];
        for i in 0..7{
            assert_eq!(0, ret(&test_str[i].as_bytes().to_vec(), test_strlen[i], &mut md2sum));
            assert_eq!(cmp::Ordering::Equal, compare(md2sum.as_ref(), &test_sum[i]));
        }
    }
}