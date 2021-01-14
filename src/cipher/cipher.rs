extern crate strum;



use strum::IntoEnumIterator;
use strum_macros::EnumIter;



#[allow(non_camel_case_types)]
#[derive(EnumIter, Debug, PartialEq)]
pub enum cipher_type_t {
    MBEDTLS_CIPHER_NONE,             /**< Placeholder to mark the end of cipher-pair lists. */
    MBEDTLS_CIPHER_NULL,                 /**< The identity stream cipher. */
    MBEDTLS_CIPHER_AES_128_ECB,          /**< AES cipher with 128-bit ECB mode. */
    MBEDTLS_CIPHER_AES_192_ECB,          /**< AES cipher with 192-bit ECB mode. */
    MBEDTLS_CIPHER_AES_256_ECB,          /**< AES cipher with 256-bit ECB mode. */
    MBEDTLS_CIPHER_AES_128_CBC,          /**< AES cipher with 128-bit CBC mode. */
    MBEDTLS_CIPHER_AES_192_CBC,          /**< AES cipher with 192-bit CBC mode. */
    MBEDTLS_CIPHER_AES_256_CBC,          /**< AES cipher with 256-bit CBC mode. */
    MBEDTLS_CIPHER_AES_128_CFB128,       /**< AES cipher with 128-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_192_CFB128,       /**< AES cipher with 192-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_256_CFB128,       /**< AES cipher with 256-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_128_CTR,          /**< AES cipher with 128-bit CTR mode. */
    MBEDTLS_CIPHER_AES_192_CTR,          /**< AES cipher with 192-bit CTR mode. */
    MBEDTLS_CIPHER_AES_256_CTR,          /**< AES cipher with 256-bit CTR mode. */
    MBEDTLS_CIPHER_AES_128_GCM,          /**< AES cipher with 128-bit GCM mode. */
    MBEDTLS_CIPHER_AES_192_GCM,          /**< AES cipher with 192-bit GCM mode. */
    MBEDTLS_CIPHER_AES_256_GCM,          /**< AES cipher with 256-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_ECB,     /**< Camellia cipher with 128-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_ECB,     /**< Camellia cipher with 192-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_ECB,     /**< Camellia cipher with 256-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CBC,     /**< Camellia cipher with 128-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CBC,     /**< Camellia cipher with 192-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CBC,     /**< Camellia cipher with 256-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CFB128,  /**< Camellia cipher with 128-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CFB128,  /**< Camellia cipher with 192-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CFB128,  /**< Camellia cipher with 256-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CTR,     /**< Camellia cipher with 128-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CTR,     /**< Camellia cipher with 192-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CTR,     /**< Camellia cipher with 256-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_GCM,     /**< Camellia cipher with 128-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_GCM,     /**< Camellia cipher with 192-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_GCM,     /**< Camellia cipher with 256-bit GCM mode. */
    MBEDTLS_CIPHER_DES_ECB,              /**< DES cipher with ECB mode. */
    MBEDTLS_CIPHER_DES_CBC,              /**< DES cipher with CBC mode. */
    MBEDTLS_CIPHER_DES_EDE_ECB,          /**< DES cipher with EDE ECB mode. */
    MBEDTLS_CIPHER_DES_EDE_CBC,          /**< DES cipher with EDE CBC mode. */
    MBEDTLS_CIPHER_DES_EDE3_ECB,         /**< DES cipher with EDE3 ECB mode. */
    MBEDTLS_CIPHER_DES_EDE3_CBC,         /**< DES cipher with EDE3 CBC mode. */
    MBEDTLS_CIPHER_BLOWFISH_ECB,         /**< Blowfish cipher with ECB mode. */
    MBEDTLS_CIPHER_BLOWFISH_CBC,         /**< Blowfish cipher with CBC mode. */
    MBEDTLS_CIPHER_BLOWFISH_CFB64,       /**< Blowfish cipher with CFB64 mode. */
    MBEDTLS_CIPHER_BLOWFISH_CTR,         /**< Blowfish cipher with CTR mode. */
    MBEDTLS_CIPHER_ARC4_128,             /**< RC4 cipher with 128-bit mode. */
    MBEDTLS_CIPHER_AES_128_CCM,          /**< AES cipher with 128-bit CCM mode. */
    MBEDTLS_CIPHER_AES_192_CCM,          /**< AES cipher with 192-bit CCM mode. */
    MBEDTLS_CIPHER_AES_256_CCM,          /**< AES cipher with 256-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CCM,     /**< Camellia cipher with 128-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CCM,     /**< Camellia cipher with 192-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CCM,     /**< Camellia cipher with 256-bit CCM mode. */
    MBEDTLS_CIPHER_ARIA_128_ECB,         /**< Aria cipher with 128-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_192_ECB,         /**< Aria cipher with 192-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_256_ECB,         /**< Aria cipher with 256-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_128_CBC,         /**< Aria cipher with 128-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_192_CBC,         /**< Aria cipher with 192-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_256_CBC,         /**< Aria cipher with 256-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_128_CFB128,      /**< Aria cipher with 128-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_192_CFB128,      /**< Aria cipher with 192-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_256_CFB128,      /**< Aria cipher with 256-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_128_CTR,         /**< Aria cipher with 128-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_192_CTR,         /**< Aria cipher with 192-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_256_CTR,         /**< Aria cipher with 256-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_128_GCM,         /**< Aria cipher with 128-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_192_GCM,         /**< Aria cipher with 192-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_256_GCM,         /**< Aria cipher with 256-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_128_CCM,         /**< Aria cipher with 128-bit key and CCM mode. */
    MBEDTLS_CIPHER_ARIA_192_CCM,         /**< Aria cipher with 192-bit key and CCM mode. */
    MBEDTLS_CIPHER_ARIA_256_CCM,         /**< Aria cipher with 256-bit key and CCM mode. */
    MBEDTLS_CIPHER_AES_128_OFB,          /**< AES 128-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_192_OFB,          /**< AES 192-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_256_OFB,          /**< AES 256-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_128_XTS,          /**< AES 128-bit cipher in XTS block mode. */
    MBEDTLS_CIPHER_AES_256_XTS,          /**< AES 256-bit cipher in XTS block mode. */
    MBEDTLS_CIPHER_CHACHA20,             /**< ChaCha20 stream cipher. */
    MBEDTLS_CIPHER_CHACHA20_POLY1305,    /**< ChaCha20-Poly1305 AEAD cipher. */
    MBEDTLS_CIPHER_AES_128_KW,           /**< AES cipher with 128-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_192_KW,           /**< AES cipher with 192-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_256_KW,           /**< AES cipher with 256-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_128_KWP,          /**< AES cipher with 128-bit NIST KWP mode. */
    MBEDTLS_CIPHER_AES_192_KWP,          /**< AES cipher with 192-bit NIST KWP mode. */
    /**< AES cipher with 256-bit NIST KWP mode. */
    MBEDTLS_CIPHER_AES_256_KWP,
}

/** Supported cipher modes. */
#[allow(non_camel_case_types)]
#[derive(PartialEq)]
pub enum  cipher_mode_t{
    MBEDTLS_MODE_NONE,               /**< None.                        */
    MBEDTLS_MODE_ECB,                    /**< The ECB cipher mode.         */
    MBEDTLS_MODE_CBC,                    /**< The CBC cipher mode.         */
    MBEDTLS_MODE_CFB,                    /**< The CFB cipher mode.         */
    MBEDTLS_MODE_OFB,                    /**< The OFB cipher mode.         */
    MBEDTLS_MODE_CTR,                    /**< The CTR cipher mode.         */
    MBEDTLS_MODE_GCM,                    /**< The GCM cipher mode.         */
    MBEDTLS_MODE_STREAM,                 /**< The stream cipher mode.      */
    MBEDTLS_MODE_CCM,                    /**< The CCM cipher mode.         */
    MBEDTLS_MODE_XTS,                    /**< The XTS cipher mode.         */
    MBEDTLS_MODE_CHACHAPOLY,             /**< The ChaCha-Poly cipher mode. */
    MBEDTLS_MODE_KW,                     /**< The SP800-38F KW mode */
    /**< The SP800-38F KWP mode */
    MBEDTLS_MODE_KWP,
}


#[allow(non_camel_case_types)]
pub struct cipher_base_t
{
    /** Base Cipher type (e.g. MBEDTLS_CIPHER_ID_AES) */
    cipher: cipher_id_t,

    /** Encrypt using ECB */
    ecb_func: fn (), 

    /** Encrypt using CBC */
    cbc_func: fn(),


    /** Encrypt using CFB (Full length) */
    cfb_fnc: fn(),

    /** Encrypt using OFB (Full length) */
    ofb_func: fn(), 

    /** Encrypt using CTR */
    ctr_func: fn(),

    /** Encrypt or decrypt using XTS. */
    xts_func: fn(),

    /** Encrypt using STREAM */
    stream_func: fn(),

    /** Set key for encryption purposes */
    setkey_enc_func: fn(),

    /** Set key for decryption purposes */
    setket_dec_func: fn(),

    /** Allocate a new context */
    ctx_alloc_func: fn(),

    /** Free the given context */
    ctx_free_func: fn(),
}

#[allow(non_camel_case_types)]
//#[derive(PartialEq)]
pub struct cipher_info_t
{
    /** Full cipher identifier. For example,
     * MBEDTLS_CIPHER_AES_256_CBC.
     */
    cipher_type: cipher_type_t, 

    /** The cipher mode. For example, MBEDTLS_MODE_CBC. */
    mode: cipher_mode_t,

    /** The cipher key length, in bits. This is the
     * default length for variable sized ciphers.
     * Includes parity bits for ciphers like DES.
     */
    key_bitlen: u32,

    /** Name of the cipher. */
    name: String,

    /** IV or nonce size, in Bytes.
     * For ciphers that accept variable IV sizes,
     * this is the recommended size.
     */
    iv_size: u32,

    /** Bitflag comprised of MBEDTLS_CIPHER_VARIABLE_IV_LEN and
     *  MBEDTLS_CIPHER_VARIABLE_KEY_LEN indicating whether the
     *  cipher supports variable IV or variable key sizes, respectively.
     */
    flags: i32,

    /** The block size, in Bytes. */
    block_size: usize,

    /** Struct for base cipher information and functions. */
    base: cipher_base_t,

}

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
pub enum cipher_id_t {
    MBEDTLS_CIPHER_ID_NONE,  /**< Placeholder to mark the end of cipher ID lists. */
    MBEDTLS_CIPHER_ID_NULL,      /**< The identity cipher, treated as a stream cipher. */
    MBEDTLS_CIPHER_ID_AES,       /**< The AES cipher. */
    MBEDTLS_CIPHER_ID_DES,       /**< The DES cipher. */
    MBEDTLS_CIPHER_ID_3DES,      /**< The Triple DES cipher. */
    MBEDTLS_CIPHER_ID_CAMELLIA,  /**< The Camellia cipher. */
    MBEDTLS_CIPHER_ID_BLOWFISH,  /**< The Blowfish cipher. */
    MBEDTLS_CIPHER_ID_ARC4,      /**< The RC4 cipher. */
    MBEDTLS_CIPHER_ID_ARIA,      /**< The Aria cipher. */
    /**< The ChaCha20 cipher. */
    MBEDTLS_CIPHER_ID_CHACHA20,
}

#[allow(non_camel_case_types)]
pub struct cipher_definition_t {
    cipher_type: cipher_type_t,
    info: cipher_info_t,
}


pub fn memcmp(v1: &[u8], v2: &[u8], len: usize) -> bool {
    if v1.len() != v2.len()  {
        return false;
    } else {
        for i in 0 .. v1.len() {
            if v1[i] != v2[i] {
                return false;
            }
        }
    }

    true

}

#[cfg(test)]
#[test]
fn memcmp_test() {
    let v1 = b"hello";
    let v2 = b"hello";
    println!("Cipher Test");
    assert!(memcmp(v1, v2, 5));
    assert!(!memcmp(b"hell", b"fire", 4));
}

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
enum  operation_t {
    MBEDTLS_OPERATION_NONE,     //: -1,
    MBEDTLS_DECRYPT,        //: 0,
    MBEDTLS_ENCRYPT,            //: 1,
}

const MBEDTLS_MAX_BLOCK_LENGTH: u32 = 16;

/**
 * Generic cipher context.
 */
struct cipher_context_t
{
    /** Information about the associated cipher. */
    cipher_info: cipher_info_t,

    /** Key length to use. */
    key_bitlen: i32,

    /** Operation that the key of the context has been
     * initialized for.
     */
    operation: operation_t,

    add_padding: fn(),
    get_padding: fn(),


    /** Buffer for input that has not been processed yet. */
    unprocessed_data: [u32;16],

    /** Number of Bytes that have not been processed yet. */
    unprocessed_len: usize,

    /** Current IV or NONCE_COUNTER for CTR-mode, data unit (or sector) number
     * for XTS-mode. */
    iv: [u8;16],

    /** IV size in Bytes, for ciphers with variable-length IVs. */
    iv_size: usize,

    /** The cipher-specific context. */
    //cipher_ctx: Box<>,

    /** Indicates whether the cipher operations should be performed
     *  by Mbed TLS' own crypto library or an external implementation
     *  of the PSA Crypto API.
     *  This is unset if the cipher context was established through
     *  mbedtls_cipher_setup(), and set if it was established through
     *  mbedtls_cipher_setup_psa().
     */
    psa_enabled: i32,
}



/*
 * No padding: don't pad :)
 *
 * There is no add_padding function (check for NULL in mbedtls_cipher_finish)
 * but a trivial get_padding function
 */
pub fn get_no_padding (input: &str, input_len: usize,
                           data_len: usize) -> i32
{
    if input.len() == data_len {
        return 0
    }
    -1
}


#[allow(dead_code)]
pub fn get_zeros_padding(input: &str, input_len: usize,
                               data_len: &mut usize) -> i32 {
    for (i, x) in input.char_indices().rev() {
        if x != '0' {
            *data_len = input_len - i-1;
            break;
        }
    }
    return 0;
}

#[test]
fn test_get_zeros_padding() {
    let s = "abcd0000000";
    let len = s.len();
    let mut data_len: usize = 0;
    get_zeros_padding(&s, len, &mut data_len);

    assert!(data_len == 7);

}


#[allow(non_upper_case_globals)]
static mut supported_init: i32 = 0;

fn dummy() {
    panic!("You need to add this function");
}


#[allow(non_upper_case_globals)]
const cipher_definitions : Vec<cipher_definition_t> = Vec::new();

#[allow(non_upper_case_globals)]
const cipher_supported : Vec<i32> = Vec::new();//[cipher_type_t::MBEDTLS_CIPHER_NONE];

fn cipher_list() -> i32  {

    unsafe {
        if supported_init != 0 {
            //            def = cipher_definitions;
            //cipher_type = cipher_supported;
            //            for def in cipher_definitions {
            //                if cipher_supported.contains(def.cip) {
            //                    supported_init = 1;
            //               }
            //            }
 
        }
    }
    1
}


fn cipher_info_from_type(cipher_type: cipher_type_t ) -> Option<cipher_info_t>
{

    for def in cipher_definitions {
        if def.cipher_type == cipher_type  {
            return  Some(def.info);
        }
    }
    return None;
}


fn mbedtls_cipher_info_from_string(cipher_name: &str ) ->  Option<cipher_info_t> {
    let mut def: cipher_definition_t;

    if cipher_name.is_empty() {
        return None;
    }

    for def in cipher_definitions {
        if def.info.name == cipher_name {
            return Some(def.info);
        }
    }

    return None;
}

fn cipher_info_from_values(cipher_id: cipher_id_t,
                           key_bitlen: u32,
                           mode: cipher_mode_t) -> Option<cipher_info_t> {   
    for def in cipher_definitions {

        if def.info.base.cipher == cipher_id &&
            def.info.key_bitlen == key_bitlen &&
            def.info.mode == mode {
                return Some(def.info);
            }
    }
    None
}


fn cipher_init( ctx: cipher_context_t)
{
}
/**< Bad input parameters. */
const  MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA: i32 = -0x6100;
const  MBEDTLS_ERR_CIPHER_ALLOC_FAILED: i32 = -0x6180;  /**< Failed to allocate memory. */
fn cipher_setup(ctx: &mut cipher_context_t,
                          cipher_info: cipher_info_t) -> i32
{

    ctx.cipher_info = cipher_info;

    return 0;
}



/**
 * \brief        This function returns the block size of the given cipher.
 *
 * \param ctx    The context of the cipher. This must be initialized.
 *
 * \return       The block size of the underlying cipher.
 * \return       \c 0 if \p ctx has not been initialized.
 */
fn cipher_get_block_size(ctx: &cipher_context_t) -> usize
{

    let info = Some(&ctx.cipher_info);
    match info {
        Some(p)=> {return ctx.cipher_info.block_size},
        None => {return 0;}
    }
}


static MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED: i32 = -0x006E;  /**< This is a bug in the library */
static MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE: i32 =  -0x6080;  /**< The selected feature is not available. */
static MBEDTLS_ERR_CIPHER_INVALID_CONTEXT: i32 = -0x6380;  /**< The context is invalid. For example, because it was freed. */
static MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED: i32 =  -0x6280;  /**< Decryption of block requires a full block. */


fn cipher_update(ctx: &mut cipher_context_t, input: &str,
                   ilen:&mut usize, output: &str, olen: &mut usize ) -> i32
{
    let mut ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut block_size: usize;

    let info = Some(&ctx.cipher_info);

    match info {
        Some(x) => {},
        None => {return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA},
    }
    

    if ctx.psa_enabled == 1 {
        /* While PSA Crypto has an API for multipart
         * operations, we currently don't make it
         * accessible through the cipher layer. */
        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE ;
    }

    *olen = 0;
    block_size = cipher_get_block_size(ctx);
    if  0 == block_size {
        return MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }

    if ctx.cipher_info.mode == cipher_mode_t::MBEDTLS_MODE_ECB {
        if *ilen != block_size  {
            return MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }


        *olen = *ilen;

        // if 0 != ( ret = ctx.cipher_info.base.ecb_func( ctx.cipher_ctx,
        //             ctx.operation, input, output)) {
        //     return ret;
        // }

        return 0;
    }


    // if( ctx.cipher_info.mode == cipher_mode_t::MBEDTLS_MODE_GCM )
    // {
    //     *olen = ilen;
    // 
    // 
    // }


    // if ( ctx->cipher_info->type == MBEDTLS_CIPHER_CHACHA20_POLY1305 )
    // {
    //     *olen = ilen;
    //     return( mbedtls_chachapoly_update( (mbedtls_chachapoly_context*) ctx->cipher_ctx,
    //                                        ilen, input, output ) );
    // }


    if input == output &&  ctx.unprocessed_len != 0 || *ilen % block_size != 0 {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }


    if ctx.cipher_info.mode == cipher_mode_t::MBEDTLS_MODE_CBC {
        let mut copy_len: usize = 0;

        /*
         * If there is not enough data for a full block, cache it.
         */
        if ( ctx.operation == operation_t::MBEDTLS_DECRYPT && None != Some(ctx.add_padding) &&
                *ilen <= block_size - ctx.unprocessed_len ) ||
            ( ctx.operation == operation_t::MBEDTLS_DECRYPT && None == Some(ctx.add_padding) &&
                *ilen < block_size - ctx.unprocessed_len ) ||
             ( ctx.operation == operation_t::MBEDTLS_ENCRYPT &&
               *ilen < block_size - ctx.unprocessed_len ) {

                 //                 memcpy( &( ctx.unprocessed_data[ctx.unprocessed_len] ), input,
                 //                    ilen );

                 ctx.unprocessed_len += *ilen;
            return 0;
        }

        /*
         * Process cached data first
         */
        if 0 != ctx.unprocessed_len {
            copy_len = block_size - ctx.unprocessed_len;

            // memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input, // 
                    // copy_len );

            // if 0 != ( ret = ctx.cipher_info.base.cbc_func( ctx.cipher_ctx,
            //         ctx.operation, block_size, ctx.iv,
            //         ctx.unprocessed_data, output ) ) 
            // {
            //     return ret ;
            // }

            *olen += block_size;
            //output += block_size;
            ctx.unprocessed_len = 0;

            //input += copy_len;
            *ilen -= copy_len;
        }

        /*
         * Cache final, incomplete block
         */
        if 0 != *ilen
        {
            /* Encryption: only cache partial blocks
             * Decryption w/ padding: always keep at least one whole block
             * Decryption w/o padding: only cache partial blocks
             */
            copy_len = *ilen % block_size;
            if copy_len == 0 &&
                ctx.operation == operation_t::MBEDTLS_DECRYPT &&
                None != Some(ctx.add_padding)
            {
                copy_len = block_size;
            }

            // memcpy( ctx->unprocessed_data, &( input[ilen - copy_len] ),
                    // copy_len );

            ctx.unprocessed_len += copy_len;
            *ilen -= copy_len;
        }

        /*
         * Process remaining full blocks
         */
        if  *ilen > 0 {
            // if 0 != ( ret = ctx.cipher_info.base.cbc_func( ctx.cipher_ctx,
            //         ctx.operation, ilen, ctx.iv, input, output ) )
            // {
            //     return ret;
            // }

            *olen += *ilen;
        }

        return 0;
    }



    if ctx.cipher_info.mode == cipher_mode_t::MBEDTLS_MODE_CFB {
        // if 0 != ( ret = ctx.cipher_info.base.cfb_func( ctx.cipher_ctx,
        //         ctx.operation, ilen, &ctx.unprocessed_len, ctx.iv,
        //         input, output ) ) 
        // {
        //     return ret;
        // }

        *olen = *ilen;

        return 0;
    }



    if ctx.cipher_info.mode == cipher_mode_t::MBEDTLS_MODE_OFB 
    {
        // if 0 != ( ret = ctx.cipher_info.base.ofb_func( ctx.cipher_ctx,
        //         ilen, &ctx.unprocessed_len, ctx.iv, input, output ) ) 
        // {
        //     return ret;
        // }

        *olen = *ilen;

        return 0;
    }



    if ctx.cipher_info.mode == cipher_mode_t::MBEDTLS_MODE_CTR 
    {
        // if 0 != ( ret = ctx.cipher_info.base.ctr_func( ctx.cipher_ctx,
        //         ilen, &ctx.unprocessed_len, ctx.iv,
        //         ctx.unprocessed_data, input, output ) ) 
        // {
        //     return ret;
        // }

        *olen = *ilen;

        return 0;
    }



    if ctx.cipher_info.mode == cipher_mode_t::MBEDTLS_MODE_XTS
    {
        if ctx.unprocessed_len > 0  {
            /* We can only process an entire data unit at a time. */
            return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        // ret = ctx.cipher_info.base.xts_func( ctx.cipher_ctx,
        //         ctx.operation, ilen, ctx.iv, input, output );
        if ret != 0 
        {
            return ret;
        }

        *olen = *ilen;

        return 0;
    }



    if ctx.cipher_info.mode == cipher_mode_t::MBEDTLS_MODE_STREAM {
        // if 0 != ( ret = ctx.cipher_info.base.stream_func( ctx.cipher_ctx,
        //                                             ilen, input, output ) ) 
        // {
        //     return ret;
        // }

        *olen = *ilen;

        return 0;
    }


    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}



/*
static cipher_definitions: cipher_definition_t = cipher_definition_t {
    cipher_type:  cipher_type_t::MBEDTLS_CIPHER_NONE,
    info: cipher_info_t {
        cipher_type: cipher_type_t::MBEDTLS_CIPHER_NONE,
        //mode: cipher_mode_t::
        key_bitlen: 0,
        name: b"",
        iv_size: 0,
        flags: 0,
        block_size: 0,
        base: cipher_base_t {
            cipher: cipher_id_t::MBEDTLS_CIPHER_ID_NONE,
            ecb_func: dummy,
            cbc_func: dummy,
            cfb_fnc: dummy,
            ofb_func: dummy,
            ctr_func: dummy,
            xts_func: dummy,
            stream_func: dummy,
            setkey_enc_func: dummy,
            setket_dec_func: dummy,
            ctx_alloc_func: dummy,
            ctx_free_func: dummy,
        }
    }
};
*/

