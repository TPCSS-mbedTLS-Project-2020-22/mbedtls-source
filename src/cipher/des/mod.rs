use std::convert::TryFrom;
#[allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

pub const MBEDTLS_DES_ENCRYPT: usize = 1;
pub const MBEDTLS_DES_DECRYPT: usize = 0;
pub const MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH: i32 = -0x0032;
pub const MBEDTLS_ERR_DES_HW_ACCEL_FAILED: i32 = 0x0033;
pub const MBEDTLS_DES_KEY_SIZE: usize = 8;
pub const WEAK_KEY_COUNT: usize = 16;

//DES context structure
pub struct mbedtls_des_context {
    pub sk: [u32; 32],
}
impl mbedtls_des_context {
    pub fn init() -> mbedtls_des_context {
        let sk = [0; 32];
        mbedtls_des_context { sk }
    }
}
//Tripple DES context structure
pub struct mbedtls_des3_context {
    pub sk: [u32; 96],
}
impl mbedtls_des3_context {
    pub fn init() -> mbedtls_des3_context {
        let sk = [0; 96];
        mbedtls_des3_context { sk }
    }
}
pub const sb1: [u32; 64] = [
    0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400, 0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000, 0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000, 0x00010004, 0x00010400, 0x00000000, 0x01010004,
];
pub const sb2: [u32; 64] = [
    0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000, 0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020, 0x80000000, 0x80100020, 0x80108020, 0x00108000,
];
pub const sb3: [u32; 64] = [
    0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000, 0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208, 0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000, 0x00020208, 0x00000008, 0x08020008, 0x00020200,
];
pub const sb4: [u32; 64] = [
    0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002000, 0x00802080,
];
pub const sb5: [u32; 64] = [
    0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100, 0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000, 0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000, 0x00000000, 0x40080000, 0x02080100, 0x40000100,
];
pub const sb6: [u32; 64] = [
    0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010, 0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000, 0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000, 0x20404000, 0x20000000, 0x00400010, 0x20004010,
];
pub const sb7: [u32; 64] = [
    0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002,
];
pub const sb8: [u32; 64] = [
    0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000,
];
/*
* PC1: left and right halves bit-swap
*/
pub const lhs: [u32; 16] = [
    0x00000000, 0x00000001, 0x00000100, 0x00000101, 0x00010000, 0x00010001, 0x00010100, 0x00010101,
    0x01000000, 0x01000001, 0x01000100, 0x01000101, 0x01010000, 0x01010001, 0x01010100, 0x01010101,
];

pub const rhs: [u32; 16] = [
    0x00000000, 0x01000000, 0x00010000, 0x01010000, 0x00000100, 0x01000100, 0x00010100, 0x01010100,
    0x00000001, 0x01000001, 0x00010001, 0x01010001, 0x00000101, 0x01000101, 0x00010101, 0x01010101,
];
/*
 * 32-bit integer manipulation macros (little endian)
 */
pub const ODD_PARITY_TABLE: [u8; 128] = [
    1, 2, 4, 7, 8, 11, 13, 14, 16, 19, 21, 22, 25, 26, 28, 31, 32, 35, 37, 38, 41, 42, 44, 47, 49,
    50, 52, 55, 56, 59, 61, 62, 64, 67, 69, 70, 73, 74, 76, 79, 81, 82, 84, 87, 88, 91, 93, 94, 97,
    98, 100, 103, 104, 107, 109, 110, 112, 115, 117, 118, 121, 122, 124, 127, 128, 131, 133, 134,
    137, 138, 140, 143, 145, 146, 148, 151, 152, 155, 157, 158, 161, 162, 164, 167, 168, 171, 173,
    174, 176, 179, 181, 182, 185, 186, 188, 191, 193, 194, 196, 199, 200, 203, 205, 206, 208, 211,
    213, 214, 217, 218, 220, 223, 224, 227, 229, 230, 233, 234, 236, 239, 241, 242, 244, 247, 248,
    251, 253, 254,
];

pub const WEAK_KEY_TABLE: [[u8; MBEDTLS_DES_KEY_SIZE]; WEAK_KEY_COUNT] = [
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
    [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
    [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
    [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
    [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
    [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
    [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
    [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
    [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
    [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
    [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
    [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
    [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
    [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
    [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
];

pub fn get_uint32_be(n: &mut u32, b: &[u8], i: usize) {
    *n = u32::from(b[i])
        | u32::from(b[i + 1]) << 8
        | u32::from(b[i + 2]) << 16
        | u32::from(b[i + 3]) << 24;
}

pub fn put_uint32_be(n: u32, b: &mut [u8; 8], i: usize) {
    b[i] = u8::try_from(n & 0xFF).unwrap();
    b[i + 1] = u8::try_from((n >> 8) & 0xFF).unwrap();
    b[i + 2] = u8::try_from((n >> 16) & 0xFF).unwrap();
    b[i + 3] = u8::try_from((n >> 24) & 0xFF).unwrap();
}
/*
 * Initial Permutation
 */
pub fn des_ip(x: &mut u32, y: &mut u32) {
    let mut t: u32;

    t = (((*x) >> 4) ^ (*y)) & 0x0F0F0F0F;
    (*y) ^= t;
    (*x) ^= t << 4;
    t = (((*x) >> 16) ^ (*y)) & 0x0000FFFF;
    (*y) ^= t;
    (*x) ^= t << 16;
    t = (((*y) >> 2) ^ (*x)) & 0x33333333;
    (*x) ^= t;
    (*y) ^= t << 2;
    t = (((*y) >> 8) ^ (*x)) & 0x00FF00FF;
    (*x) ^= t;
    (*y) ^= (t << 8);
    (*y) = (((*y) << 1) | ((*y) >> 31)) & 0xFFFFFFFF;
    t= ((*x) ^ (*y)) & 0xAAAAAAAA;
    (*y) ^= t;
    (*x) ^= t;
    (*x) = (((*x) << 1) | ((*x) >> 31)) & 0xFFFFFFFF;
}
/*
 * Final Permutation
 */

pub fn des_fp(x: &mut u32, y: &mut u32) {
    let mut t: u32;
    (*x) = (((*x) << 31) | ((*x) >> 1)) & 0xFFFFFFFF;
    t = ((*x) ^ (*y)) & 0xAAAAAAAA;
    (*x) ^= t;
    (*y) ^= t;
    (*y) = (((*y) << 31) | ((*y) >> 1)) & 0xFFFFFFFF;
    t = (((*y) >> 8) ^ (*x)) & 0x00FF00FF;
    (*x) ^= t;
    (*y) ^= t << 8;
    t= (((*y) >> 2) ^ (*x)) & 0x33333333;
    (*x) ^= t;
    (*y) ^= t<< 2;
    t = (((*x) >> 16) ^ (*y)) & 0x0000FFFF;
    (*y) ^= t;
    (*x) ^= t << 16;
    t= (((*x) >> 4) ^ (*y)) & 0x0F0F0F0F;
    (*y) ^= t;
    (*x) ^= t<< 4;
}
pub fn mbedtls_des_key_set_parity(mut key: [u8; MBEDTLS_DES_KEY_SIZE]) {
    let mut i: usize;
    for i in 0..MBEDTLS_DES_KEY_SIZE {
        key[i] = ODD_PARITY_TABLE[(key[i as usize] / 2) as usize];
    }
}

pub fn mbedtls_des_key_check_key_parity(mut key: [u8; MBEDTLS_DES_KEY_SIZE]) -> i32 {
    let mut i: usize;
    for i in 0..MBEDTLS_DES_KEY_SIZE {
        if key[i] == ODD_PARITY_TABLE[(key[i as usize] / 2) as usize] {
            return 1;
        }
    }
    return 0;
}
pub fn mbedtls_des_setkey(sk: &mut [u32; 32], mut key: [u8; MBEDTLS_DES_KEY_SIZE]) {
    let mut x: u32 = 0;
    let mut y: u32 = 0;
    let mut t: u32 = 0;
    let mut j: usize = 0;
    get_uint32_be(&mut x, &mut key, 0);
    get_uint32_be(&mut y, &mut key, 4);

    t = ((y >> 4) ^ x) & 0x0F0F0F0F;
    x^= t;
    y ^= t << 4;
    t = ((y) ^ x) & 0x10101010;
    x^= t;
    y^=t;

    x = (lhs[((x) & 0xF) as usize] << 3)
        | (lhs[((x >> 8) & 0xF) as usize] << 2)
        | (lhs[((x >> 16) & 0xF) as usize] << 1)
        | (lhs[((x >> 24) & 0xF) as usize])
        | (lhs[((x >> 5) & 0xF) as usize] << 7)
        | (lhs[((x >> 13) & 0xF) as usize] << 6)
        | (lhs[((x >> 21) & 0xF) as usize] << 5)
        | (lhs[((x >> 29) & 0xF) as usize] << 4);

    y = (rhs[((y >> 1) & 0xF) as usize] << 3)
        | (rhs[((y >> 9) & 0xF) as usize] << 2)
        | (rhs[((y>> 17) & 0xF) as usize] << 1)
        | (rhs[((y >> 25) & 0xF) as usize])
        | (rhs[((y >> 4) & 0xF) as usize] << 7)
        | (rhs[((y >> 12) & 0xF) as usize] << 6)
        | (rhs[((y >> 20) & 0xF) as usize] << 5)
        | (rhs[((y >> 28) & 0xF) as usize] << 4);

    x &= 0x0FFFFFFF;
    y &= 0x0FFFFFFF;

    for i in 0..16 {
        if i < 2 || i == 8 || i == 15 {
            x= ((x << 1) | (x >> 27)) & 0x0FFFFFFF;
            y = ((y << 1) | (y >> 27)) & 0x0FFFFFFF;
        } else {
            x= ((x<< 2) | (x>> 26)) & 0x0FFFFFFF;
            y = ((y<< 2) | (y >> 26)) & 0x0FFFFFFF;
        }
        sk[j] = ((x << 4) & 0x24000000)
            | ((x << 28) & 0x10000000)
            | ((x << 14) & 0x08000000)
            | ((x << 18) & 0x02080000)
            | ((x << 6) & 0x01000000)
            | ((x << 9) & 0x00200000)
            | ((x >> 1) & 0x00100000)
            | ((x << 10) & 0x00040000)
            | ((x << 2) & 0x00020000)
            | ((x >> 10) & 0x00010000)
            | ((y >> 13) & 0x00002000)
            | ((y >> 4) & 0x00001000)
            | ((y << 6) & 0x00000800)
            | ((y >> 1) & 0x00000400)
            | ((y >> 14) & 0x00000200)
            | ((y) & 0x00000100)
            | ((y >> 5) & 0x00000020)
            | ((y >> 10) & 0x00000010)
            | ((y >> 3) & 0x00000008)
            | ((y >> 18) & 0x00000004)
            | ((y >> 26) & 0x00000002)
            | ((y >> 24) & 0x00000001);
        j = j + 1;

        sk[j] = ((x << 15) & 0x20000000)
            | ((x << 17) & 0x10000000)
            | ((x << 10) & 0x08000000)
            | ((x << 22) & 0x04000000)
            | ((x >> 2) & 0x02000000)
            | ((x << 1) & 0x01000000)
            | ((x << 16) & 0x00200000)
            | ((x << 11) & 0x00100000)
            | ((x << 3) & 0x00080000)
            | ((x >> 6) & 0x00040000)
            | ((x << 15) & 0x00020000)
            | ((x >> 4) & 0x00010000)
            | ((y >> 2) & 0x00002000)
            | ((y << 8) & 0x00001000)
            | ((y >> 14) & 0x00000808)
            | ((y >> 9) & 0x00000400)
            | ((y) & 0x00000200)
            | ((y << 7) & 0x00000100)
            | ((y >> 7) & 0x00000020)
            | ((y >> 3) & 0x00000011)
            | ((y << 2) & 0x00000004)
            | ((y >> 21) & 0x00000002);
        j = j + 1;
    }
}
/*
 * DES key schedule for (56-bit, encryption)
 */
pub fn mbedtls_des_setkey_enc(
    ctx: &mut mbedtls_des_context,
    key: [u8; MBEDTLS_DES_KEY_SIZE],
) -> i32 {
    mbedtls_des_setkey(&mut (*ctx).sk, key);
    println!("Set keys done for Encryption");
    return 0;
}
/*
 * DES key schedule for  (56-bit, decryption)
 */
pub fn mbedtls_des_setkey_dec(
    ctx: &mut mbedtls_des_context,
    key: [u8; MBEDTLS_DES_KEY_SIZE],
) -> i32 {
    let mut i: usize = 0;
    let mut temp1: u32;
    let mut temp2: u32;
    mbedtls_des_setkey(&mut (*ctx).sk, key);

    while i < 16 {
        // Swaping (*ctx).sk[i] and (*ctx).sk[30-i]
        let temp1 = (*ctx).sk[i];
        (*ctx).sk[i] = (*ctx).sk[30 - i];
        (*ctx).sk[30 - i] = temp1;

        // Swaping (*ctx).sk[i+1] and (*ctx).sk[31-i]
        let temp2 = (*ctx).sk[i + 1];
        (*ctx).sk[i + 1] = (*ctx).sk[31 - i];
        (*ctx).sk[31 - i] = temp2;
        i += 2;
    }
    println!("Set keys done for Decryption");
    return 0;
}

/*
 * DES-ECB block encryption/decryption
 */
pub fn mbedtls_des_crypt_ecb(
    mut ctx: &mut mbedtls_des_context,
    mut input: [u8; 8],
    mut output: &mut [u8; 8],
) -> i32 {
    let mut i: usize = 0;
    let mut count: usize = 0;
    let mut X: u32 = 0;
    let mut Y: u32 = 0;
    let mut T: u32 = 0;
    let sk1: *mut u32 = &mut (*ctx).sk[0];

    get_uint32_be(&mut X, &mut input, 0);
    get_uint32_be(&mut Y, &mut input, 4);
    des_ip(&mut X, &mut Y);
    while i < 8 {
        //DES_ROUND(Y,X);
        T = (*ctx).sk[count] ^ (Y);
        count += 1;
        (X) ^= sb8[((T) & 0x3F) as usize]
            ^ sb6[((T >> 8) & 0x3F) as usize]
            ^ sb4[((T >> 16) & 0x3F) as usize]
            ^ sb2[((T >> 24) & 0x3F) as usize];

        T = (*ctx).sk[count] ^ (((Y) << 28) | ((Y) >> 4));
        count += 1;
        (X) ^= sb7[((T) & 0x3F) as usize]
            ^ sb5[((T >> 8) & 0x3F) as usize]
            ^ sb3[((T >> 16) & 0x3F) as usize]
            ^ sb1[((T >> 24) & 0x3F) as usize];

        //DES_ROUND(X,Y);
        T = (*ctx).sk[count] ^ (X);
        count += 1;
        (Y) ^= sb8[((T) & 0x3F) as usize]
            ^ sb6[((T >> 8) & 0x3F) as usize]
            ^ sb4[((T >> 16) & 0x3F) as usize]
            ^ sb2[((T >> 24) & 0x3F) as usize];

        T = (*ctx).sk[count] ^ (((X) << 28) | ((X) >> 4));
        count += 1;
        (Y) ^= sb7[((T) & 0x3F) as usize]
            ^ sb5[((T >> 8) & 0x3F) as usize]
            ^ sb3[((T >> 16) & 0x3F) as usize]
            ^ sb1[((T >> 24) & 0x3F) as usize];
        i += 1;
    }

    des_fp(&mut Y, &mut X);
    put_uint32_be(Y, &mut output, 0);
    put_uint32_be(X, &mut output, 4);

    return 0;
}

/*
 * DES-CBC buffer encryption/decryption
 */

pub fn mbedtls_des_crypt_cbc(
    mut ctx: &mut mbedtls_des_context,
    mode: usize,
    mut length: usize,
    iv: &mut [char; 8],
    mut input: String,
    mut output: &mut String,
) -> i32 {
    let mut i: i32;
    let mut temp: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    let mut inputbytes: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    let mut outputbytes: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    let mut result: String = String::from("").to_owned();
    if length % 8 != 0 {
        return MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH;
    }
    let mut k: usize = 0;
    if mode == MBEDTLS_DES_ENCRYPT {
        while length > 0 {
            for i in 0..8 {
                inputbytes[i] = input.chars().nth(i + k).unwrap() as u8;
                outputbytes[i] = output.chars().nth(i + k).unwrap() as u8;
            }

            for i in 0..8 {
                let temp1: u8 = iv[i] as u8;
                outputbytes[i] = inputbytes[i] ^ temp1;
            }

            mbedtls_des_crypt_ecb(&mut ctx, outputbytes, &mut outputbytes);
            for i in 0..8 {
                iv[i] = outputbytes[i] as char;
            }
            k += 8;
            length -= 8;
            let mut out: [char; 8] = ['0', '0', '0', '0', '0', '0', '0', '0'];
            for i in 0..8 {
                out[i] = outputbytes[i] as char;
                result.push(out[i]);
            }
        }
    } else {
        while length > 0 {
            for i in 0..8 {
                inputbytes[i] = input.chars().nth(i + k).unwrap() as u8;
                temp[i] = inputbytes[i];
                outputbytes[i] = output.chars().nth(i + k).unwrap() as u8;
            }
            mbedtls_des_crypt_ecb(&mut ctx, inputbytes, &mut outputbytes);
            for i in 0..8 {
                let temp1: u8 = iv[i] as u8;
                outputbytes[i] = outputbytes[i] ^ temp1;
            }
            for i in 0..8 {
                iv[i] = temp[i] as char;
            }

            k += 8;
            length -= 8;
            let mut out: [char; 8] = ['0', '0', '0', '0', '0', '0', '0', '0'];
            for i in 0..8 {
                out[i] = outputbytes[i] as char;
                result.push(out[i]);
            }
        }
    }
    *output = result;
    return 0;
}

pub fn des3_set2key(
    esk: &mut [u32; 96],
    dsk: &mut [u32; 96],
    mut key: [u8; MBEDTLS_DES_KEY_SIZE * 2],
) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    //Creating arrays
    let mut esk32: [u32; 32];
    let mut esk32 = [0; 32];
    let mut dsk32: [u32; 32];
    let mut dsk32 = [0; 32];
    let mut key8: [u8; 8];
    let mut key8 = [0; 8];
    let mut key16: [u8; 8];
    let mut key16 = [0; 8];
    for i in 0..32 {
        esk32[i] = esk[i] as u32;
    }
    for i in 0..8 {
        key8[i] = key[i] as u8;
    }
    let mut j: usize = 0;
    for i in 32..64 {
        dsk32[j] = dsk[i] as u32;
        j += 1;
    }
    let mut j: usize = 0;
    for i in 8..16 {
        key16[j] = key[i] as u8;
        j += 1;
    }
    mbedtls_des_setkey(&mut esk32, key8);
    mbedtls_des_setkey(&mut dsk32, key16);
    while j < 32 {
        dsk[j] = esk[30 - j];
        dsk[j + 1] = esk[31 - j];

        esk[j + 32] = dsk[62 - j];
        esk[j + 33] = dsk[63 - j];

        esk[j + 64] = esk[j];
        esk[j + 65] = esk[j + 1];

        dsk[j + 64] = dsk[j];
        dsk[j + 65] = dsk[j + 1];
        j += 2;
    }
}

/*
 * Triple-DES key schedule (112-bit, encryption)
 */
pub fn mbedtls_des3_set2key_enc(
    ctx: &mut mbedtls_des3_context,
    key: [u8; MBEDTLS_DES_KEY_SIZE * 2],
) -> i32 {
    let mut sk96: [u32; 96];
    let mut sk96 = [0; 96];
    des3_set2key(&mut (*ctx).sk, &mut sk96, key);
    println!("Set keys done for Encryption-3DES");
    return 0;
}

/*
* Triple-DES key schedule (112-bit, decryption)
*/
pub fn mbedtls_des3_set2key_dec(
    ctx: &mut mbedtls_des3_context,
    key: [u8; MBEDTLS_DES_KEY_SIZE * 2],
) -> i32 {
    let mut sk96: [u32; 96];
    let mut sk96 = [0; 96];
    des3_set2key(&mut (*ctx).sk, &mut sk96, key);
    println!("Set keys done for Decryption-3DES");
    return 0;
}
pub fn des3_set3key(
    esk: &mut [u32; 96],
    dsk: &mut [u32; 96],
    mut key: [u8; MBEDTLS_DES_KEY_SIZE * 3],
) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    //Creating arrays
    let mut esk32: [u32; 32];
    let mut esk32 = [0; 32];
    let mut key8: [u8; 8];
    let mut key8 = [0; 8];

    let mut dsk32: [u32; 32];
    let mut dsk32 = [0; 32];
    let mut key16: [u8; 8];
    let mut key16 = [0; 8];

    let mut esk64: [u32; 32];
    let mut esk64 = [0; 32];
    let mut key64: [u8; 8];
    let mut key64 = [0; 8];

    for i in 0..32 {
        esk32[i] = esk[i] as u32;
    }
    for i in 0..8 {
        key8[i] = key[i] as u8;
    }

    let mut j: usize = 0;
    for i in 32..64 {
        dsk32[j] = dsk[i] as u32;
        j += 1;
    }

    let mut j: usize = 0;
    for i in 8..16 {
        key16[i] = key[i] as u8;
    }
    for i in 64..96 {
        esk64[j] = esk[i] as u32;
        j += 1;
    }
    let mut j: usize = 0;
    for i in 16..24 {
        key64[j] = key[i] as u8;
        j += 1;
    }
    mbedtls_des_setkey(&mut esk32, key8);
    mbedtls_des_setkey(&mut dsk32, key16);
    mbedtls_des_setkey(&mut esk64, key64);
    let mut j: usize = 0;
    while j < 32 {
        dsk[j] = esk[94 - j];
        dsk[j + 1] = esk[95 - j];

        esk[j + 32] = dsk[62 - j];
        esk[j + 33] = dsk[63 - j];

        dsk[j + 64] = esk[30 - j];
        dsk[j + 65] = esk[31 - j];
        j += 2;
    }
}

/*
 * Triple-DES key schedule (168-bit, encryption)
 */
pub fn mbedtls_des3_set3key_enc(
    ctx: &mut mbedtls_des3_context,
    key: [u8; MBEDTLS_DES_KEY_SIZE * 3],
) -> i32 {
    let mut sk96: [u32; 96];
    let mut sk96 = [0; 96];
    des3_set3key(&mut (*ctx).sk, &mut sk96, key);
    println!("Set keys done for Encryption-3DES-168 Bit");
    return 0;
}

/*
* Triple-DES key schedule (168-bit, decryption)
*/
pub fn mbedtls_des3_set3key_dec(
    ctx: &mut mbedtls_des3_context,
    key: [u8; MBEDTLS_DES_KEY_SIZE * 3],
) -> i32 {
    let mut sk96: [u32; 96];
    let mut sk96 = [0; 96];
    des3_set3key(&mut (*ctx).sk, &mut sk96, key);
    println!("Set keys done for Decryption-3DES-168 Bit");
    return 0;
}

/*
 * 3DES-ECB block encryption/decryption
 */
pub fn mbedtls_des3_crypt_ecb(
    mut ctx: &mut mbedtls_des3_context,
    mut input: [u8; 8],
    mut output: &mut [u8; 8],
) -> i32 {
    let mut i: usize = 0;
    let mut count: usize = 0;
    let mut x: u32 = 0;
    let mut y: u32 = 0;
    let mut t: u32 = 0;
    let sk1: *mut u32 = &mut (*ctx).sk[0];

    get_uint32_be(&mut x, &mut input, 0);
    get_uint32_be(&mut y, &mut input, 4);
    des_ip(&mut x, &mut y);
    while i < 8 {
        //DES_ROUND(Y,X);
        t = (*ctx).sk[count] ^ (y);
        count += 1;
        (x) ^= sb8[((t) & 0x3F) as usize]
            ^ sb6[((t >> 8) & 0x3F) as usize]
            ^ sb4[((t >> 16) & 0x3F) as usize]
            ^ sb2[((t >> 24) & 0x3F) as usize];

        t= (*ctx).sk[count] ^ (((y) << 28) | ((y) >> 4));
        count += 1;
        (x) ^= sb7[((t) & 0x3F) as usize]
            ^ sb5[((t >> 8) & 0x3F) as usize]
            ^ sb3[((t >> 16) & 0x3F) as usize]
            ^ sb1[((t >> 24) & 0x3F) as usize];

        //DES_ROUND(X,Y);
        t = (*ctx).sk[count] ^ (x);
        count += 1;
        (y) ^= sb8[((t) & 0x3F) as usize]
            ^ sb6[((t>> 8) & 0x3F) as usize]
            ^ sb4[((t >> 16) & 0x3F) as usize]
            ^ sb2[((t >> 24) & 0x3F) as usize];

        t = (*ctx).sk[count] ^ (((x) << 28) | ((x) >> 4));
        count += 1;
        (y) ^= sb7[((t) & 0x3F) as usize]
            ^ sb5[((t >> 8) & 0x3F) as usize]
            ^ sb3[((t >> 16) & 0x3F) as usize]
            ^ sb1[((t >> 24) & 0x3F) as usize];
        i += 1;
    }
    while i < 8 {
        //DES_ROUND(X,Y);
        t= (*ctx).sk[count] ^ (x);
        count += 1;
        (y) ^= sb8[((t) & 0x3F) as usize]
            ^ sb6[((t >> 8) & 0x3F) as usize]
            ^ sb4[((t >> 16) & 0x3F) as usize]
            ^ sb2[((t >> 24) & 0x3F) as usize];

        t = (*ctx).sk[count] ^ (((x) << 28) | ((x) >> 4));
        count += 1;
        (y) ^= sb7[((t) & 0x3F) as usize]
            ^ sb5[((t >> 8) & 0x3F) as usize]
            ^ sb3[((t >> 16) & 0x3F) as usize]
            ^ sb1[((t >> 24) & 0x3F) as usize];
        i += 1;
        //DES_ROUND(Y,X);
        t= (*ctx).sk[count] ^ (y);
        count += 1;
        (x) ^= sb8[((t) & 0x3F) as usize]
            ^ sb6[((t >> 8) & 0x3F) as usize]
            ^ sb4[((t >> 16) & 0x3F) as usize]
            ^ sb2[((t >> 24) & 0x3F) as usize];

        t = (*ctx).sk[count] ^ (((y) << 28) | ((y) >> 4));
        count += 1;
        (x) ^= sb7[((t) & 0x3F) as usize]
            ^ sb5[((t >> 8) & 0x3F) as usize]
            ^ sb3[((t >> 16) & 0x3F) as usize]
            ^ sb1[((t >> 24) & 0x3F) as usize];
    }
    while i < 8 {
        //DES_ROUND(Y,X);
        t= (*ctx).sk[count] ^ (y);
        count += 1;
        (x) ^= sb8[((t) & 0x3F) as usize]
            ^ sb6[((t >> 8) & 0x3F) as usize]
            ^ sb4[((t >> 16) & 0x3F) as usize]
            ^ sb2[((t >> 24) & 0x3F) as usize];

    t= (*ctx).sk[count] ^ (((y) << 28) | ((y) >> 4));
        count += 1;
        (x) ^= sb7[((t) & 0x3F) as usize]
            ^ sb5[((t >> 8) & 0x3F) as usize]
            ^ sb3[((t >> 16) & 0x3F) as usize]
            ^ sb1[((t >> 24) & 0x3F) as usize];

        //DES_ROUND(X,Y);
        t= (*ctx).sk[count] ^ (x);
        count += 1;
        (y) ^= sb8[((t) & 0x3F) as usize]
            ^ sb6[((t >> 8) & 0x3F) as usize]
            ^ sb4[((t >> 16) & 0x3F) as usize]
            ^ sb2[((t >> 24) & 0x3F) as usize];

        t = (*ctx).sk[count] ^ (((x) << 28) | ((x) >> 4));
        count += 1;
        (y) ^= sb7[((t) & 0x3F) as usize]
            ^ sb5[((t >> 8) & 0x3F) as usize]
            ^ sb3[((t >> 16) & 0x3F) as usize]
            ^ sb1[((t >> 24) & 0x3F) as usize];
        i += 1;
    }

    des_fp(&mut y, &mut x);
    put_uint32_be(y, &mut output, 0);
    put_uint32_be(x, &mut output, 4);

    return 0;
}
