pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED       :i32 = 1234;
pub const MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA         :i32 = -0x0057; 
pub const MBEDTLS_ERR_POLY1305_FEATURE_UNAVAILABLE    :i32 = -0x0059; 
pub const MBEDTLS_ERR_POLY1305_HW_ACCEL_FAILED        :i32 = -0x005B; 
pub const POLY1305_BLOCK_SIZE_BYTES 				  :usize = 16;

pub struct mbedtls_poly1305_context
    {
        pub r:[u32; 4],     
        pub s:[u32; 4],     
        pub acc:[u32; 5],   
        pub queue:[u8; 16], 
        pub queue_len:usize   	 
    }