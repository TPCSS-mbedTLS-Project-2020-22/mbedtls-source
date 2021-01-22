
use std::ffi::c_void;

pub const MBEDTLS_ENTROPY_BLOCK_SIZE: usize = 64;
pub const MBEDTLS_ENTROPY_MAX_GATHER: usize = 128;
pub const MBEDTLS_ENTROPY_MAX_SEED_SIZE: usize = 1024;
pub const MBEDTLS_ENTROPY_MAX_SOURCES: usize = 20;
pub const MBEDTLS_ENTROPY_SOURCE_MANUAL: usize = MBEDTLS_ENTROPY_MAX_SOURCES;
pub const MBEDTLS_ENTROPY_SOURCE_STRONG: i32 = 1;
pub const MBEDTLS_ENTROPY_SOURCE_WEAK: i32 = 0;

pub const MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR: i32 = -0x003F;
pub const MBEDTLS_ERR_ENTROPY_MAX_SOURCES: i32 = -0x003E;
pub const MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED: i32 = -0x0040;
pub const MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE: i32 = -0x003D;
pub const MBEDTLS_ERR_ENTROPY_SOURCE_FAILED: i32 = -0x003C;


pub struct mbedtls_sha512_context
{
    pub total: [u64; 2],
    pub state: [u64; 8],
    pub buffer: [u8; 128],
    pub is384: i32
}
impl Default for mbedtls_sha512_context {
    fn default() -> mbedtls_sha512_context {
        mbedtls_sha512_context {
            total: Default::default(),
            state: Default::default(),
            buffer: [0; 128],
            is384: Default::default()
        }
    }
}

pub fn mbedtls_platform_entropy_poll(data: Option<*mut c_void>, output: &mut [u8], len: usize, olen: usize) -> i32 {

    println!("Default for entropy f_source ptr");
    return 2;
}

pub type mbedtls_entropy_f_source_ptr = fn(data: Option<*mut c_void>, output: &mut [u8], len: usize, olen: usize) -> i32;

pub struct mbedtls_entropy_source_state {
    pub f_source: mbedtls_entropy_f_source_ptr,
    pub p_source: Option<*mut c_void>,
    pub size: usize,
    pub threshold: usize,
    pub strong: i32
}
impl Default for mbedtls_entropy_source_state {
    fn default() -> mbedtls_entropy_source_state {
        mbedtls_entropy_source_state {
            f_source: mbedtls_platform_entropy_poll,
            p_source: None,
            size: Default::default(),
            threshold: Default::default(),
            strong: Default::default()
        }
    }
}

#[derive(Default)]
pub struct mbedtls_entropy_context
{
    pub accumulator_started: i32,
    pub source_count: usize,
    pub source: [mbedtls_entropy_source_state; MBEDTLS_ENTROPY_MAX_SOURCES],
    pub accumulator: mbedtls_sha512_context,
    pub initial_entropy_run: i32
}
