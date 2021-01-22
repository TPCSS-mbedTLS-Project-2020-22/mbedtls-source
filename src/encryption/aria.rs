/*
 *  ARIA implementation
 */
#![allow(dead_code)]
use crate::encryption::MbedtlsAriaContext;
use crate::encryption::MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH;
use crate::encryption::MBEDTLS_ARIA_ENCRYPT;
use crate::encryption::MBEDTLS_ARIA_DECRYPT;
use crate::encryption::MBEDTLS_ARIA_MAX_ROUNDS;
use crate::encryption::MBEDTLS_ARIA_BLOCKSIZE;
use crate::encryption::MBEDTLS_ERR_ARIA_BAD_INPUT_DATA;
use std::convert::TryFrom;
use std::convert::TryInto;


/* ALERT!!! Parameter validation macros should be in platform_utils.h*/
/* Parameter validation macros */

/*
 * 32-bit integer manipulation macros (little endian)
 */

pub fn get_uint32_le(n: &mut u32, b: &[u8], i:usize){                                               
    *n = u32::from(b[i]) |    
         u32::from(b[i+1])<<8 |    
         u32::from(b[i+2])<<16 |    
         u32::from(b[i+3])<<24;    
}

pub fn put_uint32_le(n: u32, b:&mut [u8], i:usize){ 
    b[i] = u8::try_from(n & 0xFF).unwrap();    
    b[i+1] = u8::try_from((n >> 8) & 0xFF).unwrap();    
    b[i+2] = u8::try_from((n >> 16) & 0xFF).unwrap();    
    b[i+3] = u8::try_from((n >> 24) & 0xFF).unwrap();    
}


/*
 * modify byte order: ( A B C D ) -> ( B A D C ), i.e. swap pairs of bytes
 *
 * This is submatrix P1 in [1] Appendix B.1
 *
 * Common compilers fail to translate this to minimal number of instructions,
 * so let's provide asm versions for common platforms with C fallback.
 */

// ALERT!!! you've not used this macro here-MBEDTLS_HAVE_ASM
// ALERT!!! missing block #if defined(__arm__) /* rev16 available from v6 up */

pub fn aria_p1(x: u32)-> u32 {
	return (((x) >> 8) & 0x00FF00FF) ^ (((x) & 0x00FF00FF) << 8)
}

/*
 * modify byte order: ( A B C D ) -> ( C D A B ), i.e. rotate by 16 bits
 *
 * This is submatrix P2 in [1] Appendix B.1
 *
 * Common compilers will translate this to a single instruction.
 */
pub fn aria_p2(x: u32)->u32{
	return ((x) >> 16) ^ ((x) << 16);
} 

// ALERT!!! you've not used this macro here-MBEDTLS_HAVE_ASM
// ALERT!!! missing block #if defined(__arm__) /* rev16 available from v6 up */

/*
 * modify byte order: ( A B C D ) -> ( D C B A ), i.e. change endianness
 *
 * This is submatrix P3 in [1] Appendix B.1
 *
 * Some compilers fail to translate this to a single instruction,
 * so let's provide asm versions for common platforms with C fallback.
 */

pub fn aria_p3(x: u32)->u32{ 
	return aria_p2(aria_p1(x));
}

/*
 * ARIA Affine Transform
 * (a, b, c, d) = state in/out
 *
 * If we denote the first byte of input by 0, ..., the last byte by f,
 * then inputs are: a = 0123, b = 4567, c = 89ab, d = cdef.
 *
 * Reading [1] 2.4 or [2] 2.4.3 in columns and performing simple
 * rearrangements on adjacent pairs, output is:
 *
 * a = 3210 + 4545 + 6767 + 88aa + 99bb + dccd + effe
 *   = 3210 + 4567 + 6745 + 89ab + 98ba + dcfe + efcd
 * b = 0101 + 2323 + 5476 + 8998 + baab + eecc + ffdd
 *   = 0123 + 2301 + 5476 + 89ab + ba98 + efcd + fedc
 * c = 0022 + 1133 + 4554 + 7667 + ab89 + dcdc + fefe
 *   = 0123 + 1032 + 4567 + 7654 + ab89 + dcfe + fedc
 * d = 1001 + 2332 + 6644 + 7755 + 9898 + baba + cdef
 *   = 1032 + 2301 + 6745 + 7654 + 98ba + ba98 + cdef
 *
 * Note: another presentation of the A transform can be found as the first
 * half of App. B.1 in [1] in terms of 4-byte operators P1, P2, P3 and P4.
 * The implementation below uses only P1 and P2 as they are sufficient.
 */

pub fn aria_a(a:&mut u32, b:&mut u32, c:&mut u32, d:&mut u32)
{
    let (mut ta, mut tb, mut tc):(u32, u32, u32);
    ta  =  *b;                      // 4567
    *b  =  *a;                      // 0123
    *a  =  aria_p2( ta );           // 6745
    tb  =  aria_p2( *d );           // efcd
    *d  =  aria_p1( *c );           // 98ba
    *c  =  aria_p1( tb );           // fedc
    ta  ^= *d;                      // 4567+98ba
    tc  =  aria_p1( *b );           // 2301
    ta  =  aria_p1( ta ) ^ tc ^ *c; // 2301+5476+89ab+fedc
    tb  ^= aria_p1( *d );           // ba98+efcd
    tc  ^= aria_p1( *a );           // 2301+7654
    *b  ^= ta ^ tb;                 // 0123+2301+5476+89ab+ba98+efcd+fedc OUT
    tb  =  aria_p2( tb ) ^ ta;      // 2301+5476+89ab+98ba+cdef+fedc
    *a  ^= aria_p1( tb );           // 3210+4567+6745+89ab+98ba+dcfe+efcd OUT
    ta  =  aria_p2( ta );           // 0123+7654+ab89+dcfe
    *d  ^= aria_p1( ta ) ^ tc;      // 1032+2301+6745+7654+98ba+ba98+cdef OUT
    tc  =  aria_p2( tc );           // 0123+5476
    *c  ^= aria_p1( tc ) ^ ta;      // 0123+1032+4567+7654+ab89+dcfe+fedc OUT
}

/*
 * ARIA Substitution Layer SL1 / SL2
 * (a, b, c, d) = state in/out
 * (sa, sb, sc, sd) = 256 8-bit S-Boxes (see below)
 *
 * By passing sb1, sb2, is1, is2 as S-Boxes you get SL1
 * By passing is1, is2, sb1, sb2 as S-Boxes you get SL2
 */
pub fn aria_sl(a:&mut u32, b:&mut u32,
	        c:&mut u32, d:&mut u32,
	        sa: [u8; 256], sb: [u8; 256],
	        sc: [u8;256], sd:[u8; 256])
{
    *a = u32::from(sa[ (*a & 0xFF) as usize]) ^
         (u32::from(sb[((*a >>  8) & 0xFF) as usize]) <<  8) ^
         (u32::from(sc[((*a >> 16) & 0xFF) as usize]) << 16) ^
         (u32::from(sd[(*a >> 24) as usize]) << 24);
    *b = u32::from( sa[(*b & 0xFF) as usize]       ) ^
         (u32::from( sb[((*b >>  8) & 0xFF) as usize]) <<  8) ^
         (u32::from( sc[((*b >> 16) & 0xFF) as usize]) << 16) ^
         (u32::from( sd[(*b >> 24) as usize]) << 24);
    *c = u32::from( sa[ (*c & 0xFF) as usize]       ) ^
         (u32::from( sb[((*c >>  8) & 0xFF) as usize]) <<  8) ^
         (u32::from( sc[((*c >> 16) & 0xFF) as usize]) << 16) ^
         (u32::from( sd[(*c >> 24) as usize]) << 24);
    *d = u32::from( sa[(*d & 0xFF) as usize]       ) ^
         (u32::from( sb[((*d >>  8) & 0xFF) as usize]) <<  8) ^
         (u32::from( sc[((*d >> 16) & 0xFF) as usize]) << 16) ^
         (u32::from( sd[( *d >> 24) as usize]) << 24);
}

/*
 * S-Boxes
 */
pub const ARIA_SB1:[u8;256] =
[
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16
];

pub const ARIA_SB2:[u8;256] =
[
    0xE2, 0x4E, 0x54, 0xFC, 0x94, 0xC2, 0x4A, 0xCC, 0x62, 0x0D, 0x6A, 0x46,
    0x3C, 0x4D, 0x8B, 0xD1, 0x5E, 0xFA, 0x64, 0xCB, 0xB4, 0x97, 0xBE, 0x2B,
    0xBC, 0x77, 0x2E, 0x03, 0xD3, 0x19, 0x59, 0xC1, 0x1D, 0x06, 0x41, 0x6B,
    0x55, 0xF0, 0x99, 0x69, 0xEA, 0x9C, 0x18, 0xAE, 0x63, 0xDF, 0xE7, 0xBB,
    0x00, 0x73, 0x66, 0xFB, 0x96, 0x4C, 0x85, 0xE4, 0x3A, 0x09, 0x45, 0xAA,
    0x0F, 0xEE, 0x10, 0xEB, 0x2D, 0x7F, 0xF4, 0x29, 0xAC, 0xCF, 0xAD, 0x91,
    0x8D, 0x78, 0xC8, 0x95, 0xF9, 0x2F, 0xCE, 0xCD, 0x08, 0x7A, 0x88, 0x38,
    0x5C, 0x83, 0x2A, 0x28, 0x47, 0xDB, 0xB8, 0xC7, 0x93, 0xA4, 0x12, 0x53,
    0xFF, 0x87, 0x0E, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8E, 0x37, 0x74,
    0x32, 0xCA, 0xE9, 0xB1, 0xB7, 0xAB, 0x0C, 0xD7, 0xC4, 0x56, 0x42, 0x26,
    0x07, 0x98, 0x60, 0xD9, 0xB6, 0xB9, 0x11, 0x40, 0xEC, 0x20, 0x8C, 0xBD,
    0xA0, 0xC9, 0x84, 0x04, 0x49, 0x23, 0xF1, 0x4F, 0x50, 0x1F, 0x13, 0xDC,
    0xD8, 0xC0, 0x9E, 0x57, 0xE3, 0xC3, 0x7B, 0x65, 0x3B, 0x02, 0x8F, 0x3E,
    0xE8, 0x25, 0x92, 0xE5, 0x15, 0xDD, 0xFD, 0x17, 0xA9, 0xBF, 0xD4, 0x9A,
    0x7E, 0xC5, 0x39, 0x67, 0xFE, 0x76, 0x9D, 0x43, 0xA7, 0xE1, 0xD0, 0xF5,
    0x68, 0xF2, 0x1B, 0x34, 0x70, 0x05, 0xA3, 0x8A, 0xD5, 0x79, 0x86, 0xA8,
    0x30, 0xC6, 0x51, 0x4B, 0x1E, 0xA6, 0x27, 0xF6, 0x35, 0xD2, 0x6E, 0x24,
    0x16, 0x82, 0x5F, 0xDA, 0xE6, 0x75, 0xA2, 0xEF, 0x2C, 0xB2, 0x1C, 0x9F,
    0x5D, 0x6F, 0x80, 0x0A, 0x72, 0x44, 0x9B, 0x6C, 0x90, 0x0B, 0x5B, 0x33,
    0x7D, 0x5A, 0x52, 0xF3, 0x61, 0xA1, 0xF7, 0xB0, 0xD6, 0x3F, 0x7C, 0x6D,
    0xED, 0x14, 0xE0, 0xA5, 0x3D, 0x22, 0xB3, 0xF8, 0x89, 0xDE, 0x71, 0x1A,
    0xAF, 0xBA, 0xB5, 0x81
];

pub const ARIA_IS1:[u8;256] =
[
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
    0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
    0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
    0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
    0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
    0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
    0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
    0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0C, 0x7D
];

pub const ARIA_IS2:[u8; 256] =
[
    0x30, 0x68, 0x99, 0x1B, 0x87, 0xB9, 0x21, 0x78, 0x50, 0x39, 0xDB, 0xE1,
    0x72, 0x09, 0x62, 0x3C, 0x3E, 0x7E, 0x5E, 0x8E, 0xF1, 0xA0, 0xCC, 0xA3,
    0x2A, 0x1D, 0xFB, 0xB6, 0xD6, 0x20, 0xC4, 0x8D, 0x81, 0x65, 0xF5, 0x89,
    0xCB, 0x9D, 0x77, 0xC6, 0x57, 0x43, 0x56, 0x17, 0xD4, 0x40, 0x1A, 0x4D,
    0xC0, 0x63, 0x6C, 0xE3, 0xB7, 0xC8, 0x64, 0x6A, 0x53, 0xAA, 0x38, 0x98,
    0x0C, 0xF4, 0x9B, 0xED, 0x7F, 0x22, 0x76, 0xAF, 0xDD, 0x3A, 0x0B, 0x58,
    0x67, 0x88, 0x06, 0xC3, 0x35, 0x0D, 0x01, 0x8B, 0x8C, 0xC2, 0xE6, 0x5F,
    0x02, 0x24, 0x75, 0x93, 0x66, 0x1E, 0xE5, 0xE2, 0x54, 0xD8, 0x10, 0xCE,
    0x7A, 0xE8, 0x08, 0x2C, 0x12, 0x97, 0x32, 0xAB, 0xB4, 0x27, 0x0A, 0x23,
    0xDF, 0xEF, 0xCA, 0xD9, 0xB8, 0xFA, 0xDC, 0x31, 0x6B, 0xD1, 0xAD, 0x19,
    0x49, 0xBD, 0x51, 0x96, 0xEE, 0xE4, 0xA8, 0x41, 0xDA, 0xFF, 0xCD, 0x55,
    0x86, 0x36, 0xBE, 0x61, 0x52, 0xF8, 0xBB, 0x0E, 0x82, 0x48, 0x69, 0x9A,
    0xE0, 0x47, 0x9E, 0x5C, 0x04, 0x4B, 0x34, 0x15, 0x79, 0x26, 0xA7, 0xDE,
    0x29, 0xAE, 0x92, 0xD7, 0x84, 0xE9, 0xD2, 0xBA, 0x5D, 0xF3, 0xC5, 0xB0,
    0xBF, 0xA4, 0x3B, 0x71, 0x44, 0x46, 0x2B, 0xFC, 0xEB, 0x6F, 0xD5, 0xF6,
    0x14, 0xFE, 0x7C, 0x70, 0x5A, 0x7D, 0xFD, 0x2F, 0x18, 0x83, 0x16, 0xA5,
    0x91, 0x1F, 0x05, 0x95, 0x74, 0xA9, 0xC1, 0x5B, 0x4A, 0x85, 0x6D, 0x13,
    0x07, 0x4F, 0x4E, 0x45, 0xB2, 0x0F, 0xC9, 0x1C, 0xA6, 0xBC, 0xEC, 0x73,
    0x90, 0x7B, 0xCF, 0x59, 0x8F, 0xA1, 0xF9, 0x2D, 0xF2, 0xB1, 0x00, 0x94,
    0x37, 0x9F, 0xD0, 0x2E, 0x9C, 0x6E, 0x28, 0x3F, 0x80, 0xF0, 0x3D, 0xD3,
    0x25, 0x8A, 0xB5, 0xE7, 0x42, 0xB3, 0xC7, 0xEA, 0xF7, 0x4C, 0x11, 0x33,
    0x03, 0xA2, 0xAC, 0x60
];

/*
 * Helper for key schedule: r = FO( p, k ) ^ x
 */
pub fn aria_fo_xor(mut r:[u32; 4], p:[u32; 4],
                          k:[u32; 4], x:[u32;4])
{
    let (mut a, mut b, mut c, mut d):(u32, u32, u32, u32);

    a = p[0] ^ k[0];
    b = p[1] ^ k[1];
    c = p[2] ^ k[2];
    d = p[3] ^ k[3];

    aria_sl(&mut a, &mut b, &mut c, &mut d, ARIA_SB1, ARIA_SB2, ARIA_IS1, ARIA_IS2 );
    aria_a( &mut a, &mut b, &mut c, &mut d );

    r[0] = a ^ x[0];
    r[1] = b ^ x[1];
    r[2] = c ^ x[2];
    r[3] = d ^ x[3];
}

/*
 * Helper for key schedule: r = FE( p, k ) ^ x
 */
pub fn aria_fe_xor(mut r:[u32;4], p:[u32;4],
                         k:[u32;4], x:[u32;4] )
{
    let (mut a, mut b, mut c, mut d):(u32, u32, u32, u32);

    a = p[0] ^ k[0];
    b = p[1] ^ k[1];
    c = p[2] ^ k[2];
    d = p[3] ^ k[3];

    aria_sl( &mut a, &mut b, &mut c, &mut d, ARIA_IS1, ARIA_IS2, ARIA_SB1, ARIA_SB2 );
    aria_a( &mut a, &mut b, &mut c, &mut d );

    r[0] = a ^ x[0];
    r[1] = b ^ x[1];
    r[2] = c ^ x[2];
    r[3] = d ^ x[3];
}

/*
 * Big endian 128-bit rotation: r = a ^ (b <<< n), used only in key setup.
 *
 * We chose to store bytes into 32-bit words in little-endian format (see
 * GET/PUT_UINT32_LE) so we need to reverse bytes here.
 */
pub fn aria_rot128( r:&mut [u32], a:[u32;4],
                         b:[u32;4], n:u8 )
{
    let mut j:u8;
    let (mut t, mut u):(u32, u32);
    let n1:u8 = n % 32;              // bit offset
    let n2:u8 = if n1 > 0 {32-n1} else { 0 };    // reverse bit offset

    j = ( n / 32 ) % 4;                     // initial word offset
    t = aria_p3( b[j as usize] );                    // big endian
    for i in 0..4
    {
        j = ( j + 1 ) % 4;                  // get next word, big endian
        u = aria_p3( b[j as usize] );
        t <<= n1;                           // rotate
        t |= u >> n2;
        t = aria_p3( t );                   // back to little endian
        r[i] = a[i] ^ t;                    // store
        t = u;                              // move to next word
    }
}

/*
 * Set encryption key
 */
pub fn mbedtls_aria_setkey_enc(ctx: &mut MbedtlsAriaContext,
                             key:  &[u8], keybits: u32 )->i32
{
    /* round constant masks */
    let rc=
    [[   0xB7C17C51, 0x940A2227, 0xE8AB13FE, 0xE06E9AFA  ],
        [  0xCC4AB16D, 0x20C8219E, 0xD5B128FF, 0xB0E25DEF ],
        [  0x1D3792DB, 0x70E92621, 0x75972403, 0x0EC9E804  ]
    ];

    let  mut i:usize;
    let mut w=[[ 0u32; 4];4];
    let mut w2 =[0u32;4];

    if keybits != 128 && keybits != 192 && keybits != 256
        { return MBEDTLS_ERR_ARIA_BAD_INPUT_DATA; }

    /* Copy key to W0 (and potential remainder to W1) */
    get_uint32_le( &mut w[0][0], key,  0 );
    get_uint32_le( &mut w[0][1], key,  4 );
    get_uint32_le( &mut w[0][2], key,  8 );
    get_uint32_le( &mut w[0][3], key, 12 );

    if keybits >= 192
    {
        get_uint32_le( &mut w[1][0], key, 16 );  // 192 bit key
        get_uint32_le( &mut w[1][1], key, 20 );
    }
    if keybits == 256
    {
        get_uint32_le( &mut w[1][2], key, 24 );  // 256 bit key
        get_uint32_le( &mut w[1][3], key, 28 );
    }
    
    i = (( keybits - 128 ) >> 6).try_into().unwrap();             // index: 0, 1, 2
    ctx.nr = u8::try_from(12 + 2 * i).unwrap();                   // no. rounds: 12, 14, 16

    aria_fo_xor( w[1], w[0], rc[i], w[1] ); // W1 = FO(W0, CK1) ^ KR
    i = if i < 2  { i + 1 } else { 0 };
    aria_fe_xor( w[2], w[1], rc[i], w[0] ); // W2 = FE(W1, CK2) ^ W0
    i = if i < 2  { i + 1 } else { 0 };
    aria_fo_xor( w[3], w[2], rc[i], w[1] ); // W3 = FO(W2, CK3) ^ W1

    for i in 1..4                // create round keys
    {
        w2 = w[(i + 1) & 3];
        aria_rot128( &mut ctx.rk[i], w[i], w2, 128 - 19 );
        aria_rot128( &mut ctx.rk[i +  4], w[i], w2, 128 - 31 );
        aria_rot128( &mut ctx.rk[i +  8], w[i], w2,       61 );
        aria_rot128( &mut ctx.rk[i + 12], w[i], w2,       31 );
    }
    aria_rot128( &mut ctx.rk[16], w[0], w[1], 19 );

    /* w holds enough info to reconstruct the round keys */
    w=[[ 0u32; 4];4];

    return 0;
}

/*
 * Set decryption key
 */
pub fn mbedtls_aria_setkey_dec( ctx:&mut MbedtlsAriaContext,
                             key:& [u8], keybits: u32 )->i32
{
    let mut i:usize;
    let mut j:usize;
    let _k:usize;
    let ret:i32;

    ret = mbedtls_aria_setkey_enc( ctx, key, keybits );
    if ret != 0 {
            return ret ;
        }

    /* flip the order of round keys */
    i = 0; j = ctx.nr.into();   
    while i<j    
    {
        for k in 0..4
        {
            let t = ctx.rk[i][k];
            ctx.rk[i][k] = ctx.rk[j][k];
            ctx.rk[j][k] = t;
        }
        i+=1; j-=1;
    }

    /* apply affine transform to middle keys */
    i=1;
    while i<ctx.nr.into()
    {
        let (mut a, mut b, mut c, mut d):(u32, u32, u32, u32);

        a= ctx.rk[i][0];
        b= ctx.rk[i][1];
        c= ctx.rk[i][2]; 
        d= ctx.rk[i][3];
     
        aria_a(&mut a,&mut b,&mut c,&mut d);

        ctx.rk[i][0]=a;
        ctx.rk[i][1]=b;
        ctx.rk[i][2]=c; 
        ctx.rk[i][3]=d;
        i+=1;
    }

    return 0 ;
}

/*
 * Encrypt a block
 */
pub fn mbedtls_aria_crypt_ecb( ctx: &mut MbedtlsAriaContext,
                            input:& [u8;MBEDTLS_ARIA_BLOCKSIZE as usize],
                             output:&mut [u8;MBEDTLS_ARIA_BLOCKSIZE as usize] )->i32
{
    let mut i:usize;

    let  (mut a, mut b, mut c, mut d) =(0u32, 0u32, 0u32, 0u32);    
    
    get_uint32_le( &mut a, input,  0 );
    get_uint32_le( &mut b, input,  4 );
    get_uint32_le( &mut c, input,  8 );
    get_uint32_le( &mut d, input, 12 );

    i = 0;
    loop 
    {
        a ^= ctx.rk[i][0];
        b ^= ctx.rk[i][1];
        c ^= ctx.rk[i][2];
        d ^= ctx.rk[i][3];
        i+=1;

        aria_sl( &mut a, &mut b, &mut c, &mut d, ARIA_SB1, ARIA_SB2, ARIA_IS1, ARIA_IS2 );
        aria_a( &mut a, &mut b, &mut c, &mut d );

        a ^= ctx.rk[i][0];
        b ^= ctx.rk[i][1];
        c ^= ctx.rk[i][2];
        d ^= ctx.rk[i][3];
        i+=1;

        aria_sl( &mut a, &mut b, &mut c, &mut d, ARIA_IS1, ARIA_IS2, ARIA_SB1, ARIA_SB2 );
        if i >= ctx.nr.into() 
            { break; }
        aria_a( &mut a, &mut b, &mut c, &mut d );
    }

    /* final key mixing */
    a ^= ctx.rk[i][0];
    b ^= ctx.rk[i][1];
    c ^= ctx.rk[i][2];
    d ^= ctx.rk[i][3];

    put_uint32_le( a,  output,  0 );
    put_uint32_le( b,  output,  4 );
    put_uint32_le( c,  output,  8 );
    put_uint32_le( d,  output, 12 );

    return 0 ;
}

/* Initialize context */
pub fn mbedtls_aria_init( ctx:&mut MbedtlsAriaContext )
{
    ctx.nr=0u8;
    ctx.rk=[[0u32; (MBEDTLS_ARIA_BLOCKSIZE / 4) as usize] ;(MBEDTLS_ARIA_MAX_ROUNDS+1) as usize]; 
}

/* Clear context */
fn mbedtls_aria_free( ctx:&mut MbedtlsAriaContext )
{
    ctx.nr=0u8;
    ctx.rk=[[0u32; (MBEDTLS_ARIA_BLOCKSIZE / 4) as usize] ;(MBEDTLS_ARIA_MAX_ROUNDS+1) as usize];
}

// ALERT!!! this check is missing #if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * ARIA-CBC buffer encryption/decryption
 */
pub fn mbedtls_aria_crypt_cbc( ctx:&mut MbedtlsAriaContext,
                            mode:i32,
                            mut length:u32,
                            mut iv:[u8;MBEDTLS_ARIA_BLOCKSIZE as usize],
                            input:&[u8],
                            output:&mut [u8] )->i32
{
    let mut temp =[0u8;MBEDTLS_ARIA_BLOCKSIZE as usize];

    
    assert!( mode != MBEDTLS_ARIA_ENCRYPT.try_into().unwrap() ||
                       mode != MBEDTLS_ARIA_DECRYPT.try_into().unwrap() );
    assert!( length != 0);
    

    if length % MBEDTLS_ARIA_BLOCKSIZE>0
        { return MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH; }

    if mode == MBEDTLS_ARIA_DECRYPT.try_into().unwrap()
    {
        let mut j:u32=0;
        let mut a:u32;
        let mut b:u32;
        while length > 0
        {   a=MBEDTLS_ARIA_BLOCKSIZE*j;
            b=MBEDTLS_ARIA_BLOCKSIZE*(j+1);
            temp.copy_from_slice(&input[a as usize..b as usize]);

            let mut input_bytes =[0u8;16];
            let mut output_bytes =[0u8;16];
            input_bytes.copy_from_slice(&input[a as usize..b as usize]);
            output_bytes.copy_from_slice(&output[a as usize..b as usize]);
            
            mbedtls_aria_crypt_ecb( ctx, &mut input_bytes, &mut output_bytes );
            output[a as usize..b as usize].copy_from_slice(&output_bytes);

            for i in 0..MBEDTLS_ARIA_BLOCKSIZE
                { output[i as usize] = u8::try_from( output[i as usize] ^ iv[i as usize] ).unwrap(); }

            iv.copy_from_slice(&temp);
            length -= MBEDTLS_ARIA_BLOCKSIZE;
            j+=1;
        }
    }
    else
    {
        let mut j:u32=0;
        let mut a:u32;
        let mut b:u32;
        while length > 0
        {
            for i in 0..MBEDTLS_ARIA_BLOCKSIZE
                { output[i as usize] = u8::try_from( input[i as usize] ^ iv[i as usize] ).unwrap(); }

            a=MBEDTLS_ARIA_BLOCKSIZE*j;
            b=MBEDTLS_ARIA_BLOCKSIZE*(j+1);

            let mut output_bytes1 =[0u8;16];
            let mut output_bytes2 =[0u8;16];
            output_bytes1.copy_from_slice(&output[a as usize..b as usize]);
            output_bytes2.copy_from_slice(&output[a as usize..b as usize]);
            
            mbedtls_aria_crypt_ecb( ctx, &mut output_bytes1, &mut output_bytes2 );
            output[a as usize..b as usize].copy_from_slice(&output_bytes2);

            iv.copy_from_slice(&output[a as usize..b as usize]);
            length -= MBEDTLS_ARIA_BLOCKSIZE;
            j+=1;
        }
    }

    return 0;
}


/*
 * ARIA-CFB128 buffer encryption/decryption
 */
pub fn mbedtls_aria_crypt_cfb128( ctx:&mut MbedtlsAriaContext,
                               mode:i32,
                               mut length:usize,
                               iv_off:&mut usize,
                               mut iv:[u8;MBEDTLS_ARIA_BLOCKSIZE as usize],
                               input:&[u8],
                               output:&mut [u8] )->i32
{
    let mut c:u8;
    let mut n:usize;

    
    assert!( mode != MBEDTLS_ARIA_ENCRYPT.try_into().unwrap() ||
                       mode != MBEDTLS_ARIA_DECRYPT.try_into().unwrap() );
    assert!(length!=0);

    n = (*iv_off).try_into().unwrap();

    /* An overly large value of n can lead to an unlimited
     * buffer overflow. Therefore, guard against this
     * outside of parameter validation. */
    if n >= MBEDTLS_ARIA_BLOCKSIZE.try_into().unwrap()
        { return MBEDTLS_ERR_ARIA_BAD_INPUT_DATA; }

    if mode == MBEDTLS_ARIA_DECRYPT.try_into().unwrap()
    {
        let mut j:usize=0;
        while length>0 
        {
            if n == 0
                {   
                    let mut iv1=[0u8; MBEDTLS_ARIA_BLOCKSIZE as usize];
                    iv1.copy_from_slice(&iv);
                    mbedtls_aria_crypt_ecb( ctx, &mut iv1, &mut iv ); 
                }

            c = input[j];
            output[j]= c ^ iv[n];
            iv[n] = c;

            n = ( n + 1 ) & 0x0F;
            length-=1;
            j+=1;
        }
    }
    else
    {   let mut j:usize=0;
        while length>0 
        {
            if n == 0
                {   
                    let mut iv1=[0u8; MBEDTLS_ARIA_BLOCKSIZE as usize];
                    iv1.copy_from_slice(&iv);
                    mbedtls_aria_crypt_ecb( ctx, &mut iv1, &mut iv ); 
                }
            output[j] = iv[n] ^ input[j];
            iv[n] = output[j];

            n = ( n + 1 ) & 0x0F;
            length-=1;
            j+=1;
        }
    }

    *iv_off = n;

    return 0;
}

/*
 * ARIA-CTR buffer encryption/decryption
 */
pub fn mbedtls_aria_crypt_ctr(mut ctx:&mut MbedtlsAriaContext,
                            mut length:usize,
                            nc_off:&mut usize,
                            mut nonce_counter:[u8;MBEDTLS_ARIA_BLOCKSIZE as usize],
                            mut stream_block:[u8;MBEDTLS_ARIA_BLOCKSIZE as usize],
                            input:&[u8],
                            output:&mut [u8] )->i32
{
    let mut c:u8;
    let mut n:usize;

    assert!(length!=0);

    n = *nc_off;
    /* An overly large value of n can lead to an unlimited
     * buffer overflow. Therefore, guard against this
     * outside of parameter validation. */
    if n >= MBEDTLS_ARIA_BLOCKSIZE.try_into().unwrap()
        { return MBEDTLS_ERR_ARIA_BAD_INPUT_DATA; }

    let mut j:usize=0;
    while length>0
    {
        if n == 0 {
            mbedtls_aria_crypt_ecb( &mut ctx, &mut nonce_counter,
                                &mut stream_block );

            for i in (1..(MBEDTLS_ARIA_BLOCKSIZE+1)).rev(){
                nonce_counter[(i - 1) as usize]+=1;
                if nonce_counter[(i - 1) as usize] != 0
                    { break; }
            }
        }
        c = input[j];
        output[j] = u8::try_from( c ^ stream_block[n] ).unwrap();

        n = ( n + 1 ) & 0x0F;
        length-=1;
        j+=1;
    }

    *nc_off = n;

    return 0;
}

/*
 * Basic ARIA ECB test vectors from RFC 5794
 */
pub const ARIA_TEST1_ECB_KEY:[u8;32] =           // test key
[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,     // 128 bit
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,     // 192 bit
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F      // 256 bit
];

pub const ARIA_TEST1_ECB_PT:[u8;MBEDTLS_ARIA_BLOCKSIZE as usize] =            // plaintext
[
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,     // same for all
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF      // key sizes
];

pub const ARIA_TEST1_ECB_CT:[[u8;MBEDTLS_ARIA_BLOCKSIZE as usize];3] =         // ciphertext
[
    [ 0xD7, 0x18, 0xFB, 0xD6, 0xAB, 0x64, 0x4C, 0x73,   // 128 bit
          0x9D, 0xA9, 0x5F, 0x3B, 0xE6, 0x45, 0x17, 0x78 ],
    [ 0x26, 0x44, 0x9C, 0x18, 0x05, 0xDB, 0xE7, 0xAA,   // 192 bit
          0x25, 0xA4, 0x68, 0xCE, 0x26, 0x3A, 0x9E, 0x79 ],
    [ 0xF9, 0x2B, 0xD7, 0xC7, 0x9F, 0xB7, 0x2E, 0x2F,   // 256 bit
          0x2B, 0x8F, 0x80, 0xC1, 0x97, 0x2D, 0x24, 0xFC ]
];

/*
 * Mode tests from "Test Vectors for ARIA"  Version 1.0
 * http://210.104.33.10/ARIA/doc/ARIA-testvector-e.pdf
 */
pub const ARIA_TEST2_KEY:[u8; 32] =
[
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,     // 128 bit
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,     // 192 bit
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff      // 256 bit
];

pub const ARIA_TEST2_PT:[u8;48] =
[
    0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa,     // same for all
    0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb,
    0x11, 0x11, 0x11, 0x11, 0xcc, 0xcc, 0xcc, 0xcc,
    0x11, 0x11, 0x11, 0x11, 0xdd, 0xdd, 0xdd, 0xdd,
    0x22, 0x22, 0x22, 0x22, 0xaa, 0xaa, 0xaa, 0xaa,
    0x22, 0x22, 0x22, 0x22, 0xbb, 0xbb, 0xbb, 0xbb,
];

pub const ARIA_TEST2_IV:[u8;MBEDTLS_ARIA_BLOCKSIZE as usize] =
[
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,     // same for CBC, CFB
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0      // CTR has zero IV
];

pub const ARIA_TEST2_CBC_CT:[[u8;48];3] =         // CBC ciphertext
[
    [ 0x49, 0xd6, 0x18, 0x60, 0xb1, 0x49, 0x09, 0x10,   // 128-bit key
          0x9c, 0xef, 0x0d, 0x22, 0xa9, 0x26, 0x81, 0x34,
          0xfa, 0xdf, 0x9f, 0xb2, 0x31, 0x51, 0xe9, 0x64,
          0x5f, 0xba, 0x75, 0x01, 0x8b, 0xdb, 0x15, 0x38,
          0xb5, 0x33, 0x34, 0x63, 0x4b, 0xbf, 0x7d, 0x4c,
          0xd4, 0xb5, 0x37, 0x70, 0x33, 0x06, 0x0c, 0x15 ],
    [ 0xaf, 0xe6, 0xcf, 0x23, 0x97, 0x4b, 0x53, 0x3c,   // 192-bit key
          0x67, 0x2a, 0x82, 0x62, 0x64, 0xea, 0x78, 0x5f,
          0x4e, 0x4f, 0x7f, 0x78, 0x0d, 0xc7, 0xf3, 0xf1,
          0xe0, 0x96, 0x2b, 0x80, 0x90, 0x23, 0x86, 0xd5,
          0x14, 0xe9, 0xc3, 0xe7, 0x72, 0x59, 0xde, 0x92,
          0xdd, 0x11, 0x02, 0xff, 0xab, 0x08, 0x6c, 0x1e ],
    [ 0x52, 0x3a, 0x8a, 0x80, 0x6a, 0xe6, 0x21, 0xf1,   // 256-bit key
          0x55, 0xfd, 0xd2, 0x8d, 0xbc, 0x34, 0xe1, 0xab,
          0x7b, 0x9b, 0x42, 0x43, 0x2a, 0xd8, 0xb2, 0xef,
          0xb9, 0x6e, 0x23, 0xb1, 0x3f, 0x0a, 0x6e, 0x52,
          0xf3, 0x61, 0x85, 0xd5, 0x0a, 0xd0, 0x02, 0xc5,
          0xf6, 0x01, 0xbe, 0xe5, 0x49, 0x3f, 0x11, 0x8b ]
];


pub const ARIA_TEST2_CFB_CT:[[u8;48];3] =         // CFB ciphertext
[
    [ 0x37, 0x20, 0xe5, 0x3b, 0xa7, 0xd6, 0x15, 0x38,   // 128-bit key
          0x34, 0x06, 0xb0, 0x9f, 0x0a, 0x05, 0xa2, 0x00,
          0xc0, 0x7c, 0x21, 0xe6, 0x37, 0x0f, 0x41, 0x3a,
          0x5d, 0x13, 0x25, 0x00, 0xa6, 0x82, 0x85, 0x01,
          0x7c, 0x61, 0xb4, 0x34, 0xc7, 0xb7, 0xca, 0x96,
          0x85, 0xa5, 0x10, 0x71, 0x86, 0x1e, 0x4d, 0x4b ],
    [ 0x41, 0x71, 0xf7, 0x19, 0x2b, 0xf4, 0x49, 0x54,   // 192-bit key
          0x94, 0xd2, 0x73, 0x61, 0x29, 0x64, 0x0f, 0x5c,
          0x4d, 0x87, 0xa9, 0xa2, 0x13, 0x66, 0x4c, 0x94,
          0x48, 0x47, 0x7c, 0x6e, 0xcc, 0x20, 0x13, 0x59,
          0x8d, 0x97, 0x66, 0x95, 0x2d, 0xd8, 0xc3, 0x86,
          0x8f, 0x17, 0xe3, 0x6e, 0xf6, 0x6f, 0xd8, 0x4b ],
    [ 0x26, 0x83, 0x47, 0x05, 0xb0, 0xf2, 0xc0, 0xe2,   // 256-bit key
          0x58, 0x8d, 0x4a, 0x7f, 0x09, 0x00, 0x96, 0x35,
          0xf2, 0x8b, 0xb9, 0x3d, 0x8c, 0x31, 0xf8, 0x70,
          0xec, 0x1e, 0x0b, 0xdb, 0x08, 0x2b, 0x66, 0xfa,
          0x40, 0x2d, 0xd9, 0xc2, 0x02, 0xbe, 0x30, 0x0c,
          0x45, 0x17, 0xd1, 0x96, 0xb1, 0x4d, 0x4c, 0xe1 ]
];

pub const ARIA_TEST2_CTR_CT:[[u8;48];3] =         // CTR ciphertext
[
    [ 0xac, 0x5d, 0x7d, 0xe8, 0x05, 0xa0, 0xbf, 0x1c,   // 128-bit key
          0x57, 0xc8, 0x54, 0x50, 0x1a, 0xf6, 0x0f, 0xa1,
          0x14, 0x97, 0xe2, 0xa3, 0x45, 0x19, 0xde, 0xa1,
          0x56, 0x9e, 0x91, 0xe5, 0xb5, 0xcc, 0xae, 0x2f,
          0xf3, 0xbf, 0xa1, 0xbf, 0x97, 0x5f, 0x45, 0x71,
          0xf4, 0x8b, 0xe1, 0x91, 0x61, 0x35, 0x46, 0xc3 ],
    [ 0x08, 0x62, 0x5c, 0xa8, 0xfe, 0x56, 0x9c, 0x19,   // 192-bit key
          0xba, 0x7a, 0xf3, 0x76, 0x0a, 0x6e, 0xd1, 0xce,
          0xf4, 0xd1, 0x99, 0x26, 0x3e, 0x99, 0x9d, 0xde,
          0x14, 0x08, 0x2d, 0xbb, 0xa7, 0x56, 0x0b, 0x79,
          0xa4, 0xc6, 0xb4, 0x56, 0xb8, 0x70, 0x7d, 0xce,
          0x75, 0x1f, 0x98, 0x54, 0xf1, 0x88, 0x93, 0xdf ],
    [ 0x30, 0x02, 0x6c, 0x32, 0x96, 0x66, 0x14, 0x17,   // 256-bit key
          0x21, 0x17, 0x8b, 0x99, 0xc0, 0xa1, 0xf1, 0xb2,
          0xf0, 0x69, 0x40, 0x25, 0x3f, 0x7b, 0x30, 0x89,
          0xe2, 0xa3, 0x0e, 0xa8, 0x6a, 0xa3, 0xc8, 0x8f,
          0x59, 0x40, 0xf0, 0x5a, 0xd7, 0xee, 0x41, 0xd7,
          0x13, 0x47, 0xbb, 0x72, 0x61, 0xe3, 0x48, 0xf1 ]
];

/*
 * Checkup routine
 */
 #[test]
pub fn mbedtls_aria_self_test( )
{
    let mut blk =[0u8;MBEDTLS_ARIA_BLOCKSIZE as usize];
    let mut ctx=MbedtlsAriaContext {
        nr: 0u8,
        rk: [[0u32; (MBEDTLS_ARIA_BLOCKSIZE / 4) as usize] ;(MBEDTLS_ARIA_MAX_ROUNDS+1) as usize] 
    };

    let mut j:usize;

    let mut buf:[u8;48];
    let mut iv =[0u8;MBEDTLS_ARIA_BLOCKSIZE as usize];

    /*
     * Test set 1
     */
    for i in 0..3
    {
        /* test ECB encryption */
        println!( "  ARIA-ECB-{} (enc): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &mut ctx, & ARIA_TEST1_ECB_KEY, 128 + 64 * i );
        mbedtls_aria_crypt_ecb( &mut ctx, & ARIA_TEST1_ECB_PT, &mut blk );
        blk.copy_from_slice(&ARIA_TEST1_ECB_CT[i as usize]);

        /* test ECB decryption */
        println!( "  ARIA-ECB-{} (dec): ", 128 + 64 * i );
        mbedtls_aria_setkey_dec( &mut ctx, & ARIA_TEST1_ECB_KEY, 128 + 64 * i );
        mbedtls_aria_crypt_ecb( &mut ctx, & ARIA_TEST1_ECB_CT[i as usize], &mut blk );
        blk.copy_from_slice(&ARIA_TEST1_ECB_PT);
    }
        println!( "\n" );

    /*
     * Test set 2
     */
    for i in 0..3
    {
        /* Test CBC encryption */
        println!( "  ARIA-CBC-{} (enc): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &mut ctx, & ARIA_TEST2_KEY, 128 + 64 * i );
        iv.copy_from_slice(&ARIA_TEST2_IV);
        buf=[0x55;48];
        mbedtls_aria_crypt_cbc( &mut ctx, MBEDTLS_ARIA_ENCRYPT.try_into().unwrap(), 48, iv,
            &ARIA_TEST2_PT, &mut buf );

        /* Test CBC decryption */
        println!( "  ARIA-CBC-{} (dec): ", 128 + 64 * i );
        mbedtls_aria_setkey_dec( &mut ctx, & ARIA_TEST2_KEY, 128 + 64 * i );
        iv.copy_from_slice(&ARIA_TEST2_IV);
        buf=[0xAA;48];
        mbedtls_aria_crypt_cbc( &mut ctx, MBEDTLS_ARIA_DECRYPT.try_into().unwrap(), 48, iv,
            &ARIA_TEST2_CBC_CT[i as usize], &mut buf );
    }
    println!( "\n" );

    for i in 0..3
    {
        /* Test CFB encryption */
        println!( "  ARIA-CFB-{} (enc): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &mut ctx, & ARIA_TEST2_KEY, 128 + 64 * i );
        iv.copy_from_slice(&ARIA_TEST2_IV);
        buf=[0x55;48];
        j = 0;
        mbedtls_aria_crypt_cfb128( &mut ctx, MBEDTLS_ARIA_ENCRYPT.try_into().unwrap(), 48, &mut j, iv,
            &ARIA_TEST2_PT, &mut buf );
    
        /* Test CFB decryption */
        println!( "  ARIA-CFB-{} (dec): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &mut ctx, & ARIA_TEST2_KEY, 128 + 64 * i );
        iv.copy_from_slice(&ARIA_TEST2_IV);
        buf=[0xAA;48];
        j = 0;
        mbedtls_aria_crypt_cfb128( &mut ctx, MBEDTLS_ARIA_DECRYPT.try_into().unwrap(), 48, &mut j,
            iv, &ARIA_TEST2_CFB_CT[i as usize], &mut buf );
    }
    println!( "\n" );
    for i in 0..3
    {
        println!( "  ARIA-CTR-{} (enc): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &mut ctx, & ARIA_TEST2_KEY, 128 + 64 * i );
        iv=[0;MBEDTLS_ARIA_BLOCKSIZE as usize];
        buf=[ 0x55;48];
        j = 0;
        mbedtls_aria_crypt_ctr( &mut ctx, 48, &mut j, iv, blk,
            &ARIA_TEST2_PT, &mut buf );
        println!( "  ARIA-CTR-{} (dec): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &mut ctx, & ARIA_TEST2_KEY, 128 + 64 * i );
        iv=[0;MBEDTLS_ARIA_BLOCKSIZE as usize];
        buf= [0xAA;48];
        j = 0;
        mbedtls_aria_crypt_ctr( &mut ctx, 48, &mut j, iv, blk,
            &ARIA_TEST2_CTR_CT[i as usize], &mut buf );
    }
    println!( "\n" );

}
