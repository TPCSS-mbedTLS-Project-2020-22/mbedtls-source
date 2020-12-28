pub const MBEDTLS_BLOWFISH_ENCRYPT:usize = 1;
pub const MBEDTLS_BLOWFISH_DECRYPT:usize = 0;
pub const MBEDTLS_BLOWFISH_MAX_KEY_BITS:u32 = 448;
pub const MBEDTLS_BLOWFISH_MIN_KEY_BITS:u32 = 32;
pub const MBEDTLS_BLOWFISH_ROUNDS:usize = 16;
pub const MBEDTLS_BLOWFISH_BLOCKSIZE:usize = 8;

pub const MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA:i32 = -0x0016;
pub const MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH:i32 = -0x0018;
pub const MODULU32:u64=4294967296;

pub struct mbedtls_blowfish_context{
    pub P:[u32;MBEDTLS_BLOWFISH_ROUNDS+2],
    pub S:[[u32;256];4],
}

pub fn run()
{
    println!("{:?}",MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA);
}