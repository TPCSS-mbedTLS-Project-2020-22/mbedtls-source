pub mod aria;
// struct from aria.h
#[derive(Debug)]
pub struct MbedtlsAriaContext {
	nr: u8,
	rk: [[u32; (MBEDTLS_ARIA_BLOCKSIZE / 4) as usize] ;(MBEDTLS_ARIA_MAX_ROUNDS+1) as usize] 
}

// ARIA
pub const MBEDTLS_ARIA_ENCRYPT : u32=1;
pub const MBEDTLS_ARIA_DECRYPT :u32=0; 

pub const MBEDTLS_ARIA_BLOCKSIZE: u32=16; 
pub const MBEDTLS_ARIA_MAX_ROUNDS:  u32=16;
pub const MBEDTLS_ARIA_MAX_KEYSIZE: u32=32;

pub const MBEDTLS_ERR_ARIA_BAD_INPUT_DATA: i32= -0x005C;
pub const MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH: i32= -0x005E;
pub const MBEDTLS_ERR_ARIA_FEATURE_UNAVAILABLE: i32=  -0x005A;
pub const MBEDTLS_ERR_ARIA_HW_ACCEL_FAILED: i32= -0x0058;
