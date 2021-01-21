/*NOte: -------  Errors in this file are due to the dependencies on the other files that are not implemented yet. -------*/

pub const MBEDTLS_GCM_ENCRYPT :usize =1;
pub const MBEDTLS_GCM_DECRYPT:usize = 0;
pub const MBEDTLS_ERR_GCM_AUTH_FAILED : i32 = -0x0012;
pub const MBEDTLS_ERR_GCM_HW_ACCEL_FAILED: i32 = -0x0013;
pub const MBEDTLS_ERR_GCM_BAD_INPUT: i32 = -0x0014;
pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED: i32 = - 0x006E;
pub const MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED : i32 = -0x0072;


pub struct mbedtls_gcm_context 
{
    pub cipher_ctx: mbedtls_cipher_context_t,
    pub HL:[u64;16],
    pub HH:[u64;16],
    pub len: u64,
    pub add_len : u64,
    pub base_ectr:[u8;16],
    pub y:[u8;16],
    pub buf:[u8;16],
    pub mode: i32
}
