#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused)]
#![allow(unused_imports)]

//constants as defined in the corresponding c files
pub const MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA:i32=-0x0051;
pub const MBEDTLS_ERR_CHACHA20_FEATURE_UNAVAILABLE:i32=-0x0053;
pub const MBEDTLS_ERR_CHACHA20_HW_ACCEL_FAILED:i32=-0x0055;
pub const CHACHA20_BLOCK_SIZE_BYTES:usize=64;
pub const CHACHA20_CTR_INDEX:usize=12;
pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED:i32=-0x006E;

// structure holding chacha20 context 
pub struct mbedtls_chacha20_context{
    pub state:[u32;16],  //The state (before round operations)
    pub keystream8:[u8;64], //Leftover keystream bytes.
    pub keystream_bytes_used:usize //Number of keystream bytes already used
}