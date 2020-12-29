#[cfg(feature = "MD2")]
pub mod md2;
#[cfg(feature = "MD4")]
pub mod md4;
#[cfg(feature = "MD5")]
pub mod md5;
use super::error;

/// The selected feature is not available.
pub const ERR_MD_FEATURE_UNAVAILABLE : i32 = -0x5080;
/// Bad input parameters to function.
pub const ERR_MD_BAD_INPUT_DATA      : i32 = -0x5100;
/// Failed to allocate memory.
pub const ERR_MD_ALLOC_FAILED        : i32 = -0x5180;
/// Opening or reading of file failed.
pub const ERR_MD_FILE_IO_ERROR       : i32 = -0x5200;


const MD_MAX_SIZE: usize = if cfg!(feature = "SHA512") {64} else{32};
const MD_MAX_BLOCK_SIZE: usize = if cfg!(feature = "SHA512") {128} else{64};

/// Supported message digests
pub enum MdTypeT{
    /// None.
    NONE=0,    
    /// The MD2 message digest.
    MD2,       
    /// The MD4 message digest.
    MD4,       
    /// The MD5 message digest.
    MD5,       
    /// The SHA-1 message digest.
    SHA1,      
    /// The SHA-224 message digest.
    SHA224,    
    /// The SHA-256 message digest.
    SHA256,    
    /// The SHA-384 message digest.
    SHA384,    
    /// The SHA-512 message digest.
    SHA512,    
    /// The RIPEMD-160 message digest.
    RIPEMD160, 
}

const SUPPORTED_DIGESTS: &'static [MdTypeT] = &[
        #[cfg(feature = "MD2")]
        MdTypeT::MD2,
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4,
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5,
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1,
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224,
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256,
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384,
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512,
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160
];

const DUMMY_INFO: MdInfoT = MdInfoT{
    name: ("none"),
    md_type: MdTypeT::NONE,
    size: 0,
    block_size: 0,
};

#[cfg(feature = "MD2")]
pub const MD2_INFO: MdInfoT = MdInfoT{
    name: ("MD2"),
    md_type: MdTypeT::MD2,
    size: 16,
    block_size: 16,
};

#[cfg(feature = "MD4")]
const MD4_INFO: MdInfoT = MdInfoT{
    name: ("MD4"),
    md_type: MdTypeT::MD4,
    size: 16,
    block_size: 64,
};

#[cfg(feature = "MD5")]
const MD5_INFO: MdInfoT = MdInfoT{
    name: ("MD5"),
    md_type: MdTypeT::MD5,
    size: 16,
    block_size: 64,
};

#[cfg(feature = "RIPEMD160")]
const RIPEMD160_INFO: MdInfoT = MdInfoT{
    name: ("RIPEMD160"),
    md_type: MdTypeT::RIPEMD160,
    size: 20,
    block_size: 64,
};

#[cfg(feature = "SHA1")]
const SHA1_INFO: MdInfoT = MdInfoT{
    name: ("SHA1"),
    md_type: MdTypeT::SHA1,
    size: 20,
    block_size: 64,
};

#[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
const SHA224_INFO: MdInfoT = MdInfoT{
    name: ("SHA224"),
    md_type: MdTypeT::SHA224,
    size: 28,
    block_size: 64,
};

#[cfg(feature = "SHA256")]
const SHA256_INFO: MdInfoT = MdInfoT{
    name: ("SHA256"),
    md_type: MdTypeT::SHA256,
    size: 32,
    block_size: 64,
};

#[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
const SHA384_INFO: MdInfoT = MdInfoT{
    name: ("SHA384"),
    md_type: MdTypeT::SHA384,
    size: 48,
    block_size: 128,
};

#[cfg(feature = "SHA512")]
const SHA512_INFO: MdInfoT = MdInfoT{
    name: ("SHA512"),
    md_type: MdTypeT::SHA512,
    size: 64,
    block_size: 128,
};

pub struct Context{
    /// Information about the associated message digest.
    md_info: &'static MdInfoT,
    /// The digest-specific context for MD2.
    md_ctx_md_2: MdContextMD2,
    /// The digest-specific context for non-MD2.
    md_ctx: MdContext,
    /// The HMAC part of the context.
    hmac_ctx: Vec<u8>,
}

struct MdContextMD2{
    /// checksum of the data block
    cksum: Vec<u8>,    
    /// intermediate digest state
    state: Vec<u8>,    
    /// data block being processed
    buffer: Vec<u8>,   
    /// amount of data in buffer
    left: usize
}

struct MdContext{
    /// number of bytes processed
    total: Vec<u32>,    
    /// intermediate digest state
    state: Vec<u32>,    
    /// data block being processed
    buffer: Vec<u8>,
}

fn list() -> &'static [MdTypeT] {
    return &SUPPORTED_DIGESTS;
}

fn info_from_type(md_type: &MdTypeT) -> Option<&'static MdInfoT>{
    match md_type{
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => return Some(&MD2_INFO),
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => return Some(&MD4_INFO),
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => return Some(&MD5_INFO),
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => return Some(&SHA1_INFO),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => return Some(&SHA224_INFO),
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => return Some(&SHA256_INFO),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => return Some(&SHA384_INFO),
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512 => return Some(&SHA512_INFO),
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => return Some(&RIPEMD160_INFO),
        _ => return None,
    }
}

fn info_from_string(md_name: &str) -> Option<&'static MdInfoT>{
    match md_name{
        #[cfg(feature = "MD2")]
        "MD2" => return info_from_type(&MdTypeT::MD2),
        
        #[cfg(feature = "MD4")]
        "MD4" => return info_from_type(&MdTypeT::MD4),
        
        #[cfg(feature = "MD5")]
        "MD5" => return info_from_type(&MdTypeT::MD5),
        
        #[cfg(feature = "SHA1")]
        "SHA1" => return info_from_type(&MdTypeT::SHA1),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        "SHA224" => return info_from_type(&MdTypeT::SHA224),
        
        #[cfg(feature = "SHA256")]
        "SHA256" => return info_from_type(&MdTypeT::SHA256),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        "SHA384" => return info_from_type(&MdTypeT::SHA384),
        
        #[cfg(feature = "SHA512")]
        "SHA512" => return info_from_type(&MdTypeT::SHA512),
        
        #[cfg(feature = "RIPEMD160")]
        "RIPEMD160" => return info_from_type(&MdTypeT::RIPEMD160),
        
        _ => return None,
    }
}

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
pub struct MdInfoT{
    /// Name of the message digest
    name: &'static str,
    /// Digest identifier
    md_type: MdTypeT,
    /// Output length of the digest function in bytes
    size: u8,
    /// Block length of the digest function in bytes
    block_size: u8,
    
}
/**
 * This function generates a new Context based on 
 * type given.
 * 
 * Note that inner vectors of md_ctx have 0 size.
 * You should still call init() fuction before you 
 * call any other methods.
 */

fn create_context() -> Box<Context> {
    //TODO: generate context based on given type
    let md_ctx_md2 = MdContextMD2{
        cksum: Vec::new(),
        state: Vec::new(),
        buffer: Vec::new(),
        left: 0,
    };

    let md_ctx = MdContext{
        total: Vec::new(),
        state: Vec::new(),
        buffer: Vec::new(),
    };

    let ctx = Context{
        // Note that this is just a placeholder
        md_info: &DUMMY_INFO,
        md_ctx_md_2: md_ctx_md2,
        md_ctx: md_ctx,
        hmac_ctx: Vec::new(),
    };

    return Box::new(ctx);
}

/**
 * \brief           This function selects the message digest algorithm to use,
 *                  and allocates internal structures.
 *
 *                  Makes it necessary to call
 *                  mbedtls_md_free() later.
 *
 * \param ctx       The context to set up.
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 * \param hmac      Defines if HMAC is used. False: HMAC is not used (saves some memory),
 *                  or True: HMAC is used with this context.
 *
 * \return          \c 0 on success.
 * \return          #ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
fn setup(ctx: &mut Context, md_type: &MdTypeT, hmac: bool) -> i32{
    match md_type{
        
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => {
            md2::init(&mut ctx.md_ctx_md_2);
            ctx.md_info = &MD2_INFO;
        },
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => {
            md4::init(&mut ctx.md_ctx);
            ctx.md_info = &MD4_INFO;
        },
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => {
            md5::init(&mut ctx.md_ctx);
            ctx.md_info = &MD5_INFO;
        },
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => {
            sha1::init(&mut ctx.md_ctx);
            ctx.md_info = &SHA1_INFO;
        },
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => {
            sha256::init(&mut ctx.md_ctx);
            ctx.md_info = &SHA224_INFO;
        },
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => {
            sha256::init(&mut ctx.md_ctx);
            ctx.md_info = &SHA256_INFO;
        },
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => {
            sha512::init(&mut ctx.md_ctx);
            ctx.md_info = &SHA384_INFO;
        },
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512 => {
            sha512::init(&mut ctx.md_ctx);
            ctx.md_info = &SHA512_INFO;
        },
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => {
            ripemd160::init(&mut ctx.md_ctx);
            ctx.md_info = &RIPEMD160_INFO;
        },
    
        _ => return ERR_MD_BAD_INPUT_DATA,
    }

    if hmac{
        ctx.hmac_ctx = vec![0; (ctx.md_info.block_size*(2u8)).into()];
    }

    return 0;
}

/**
 * 
 * This function relies on specialised free methods 
 * to free algorithm specific context.
 * 
 * Then it zeroes out hmac specific vectors, 
 * and at last it shrinks the size of hmac vector.
 */
pub fn free(ctx: &mut Context){
    match ctx.md_info.md_type{
        
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => md2::free(&mut ctx.md_ctx_md_2),
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => md4::free(&mut ctx.md_ctx),
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => md5::free(&mut ctx.md_ctx),
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => sha1::free(&mut ctx.md_ctx),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => sha256::free(&mut ctx.md_ctx),
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => sha256::free(&mut ctx.md_ctx),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => sha512::free(&mut ctx.md_ctx),
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512 => sha512::free(&mut ctx.md_ctx),
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => ripemd160::free(&mut ctx.md_ctx),

        _ => panic!("Control flow would not have reached here!"),
    }

    for i in &mut ctx.hmac_ctx.iter_mut(){
        *i = 0u8;
    }
    
    ctx.hmac_ctx.resize(0, 0);
}

/**
 * \brief           This function clones the state of an message-digest
 *                  context.
 *
 * \note            You must call init() on \c dst before calling
 *                  this function.
 *
 * \note            The two contexts must have the same type,
 *                  for example, both are SHA-256.
 *
 * \warning         This function clones the message-digest state, not the
 *                  HMAC state.
 *
 * \param dst       The destination context.
 * \param src       The context to be cloned.
 *
 * \return          \c 0 on success.
 * \return          #ERR_MD_BAD_INPUT_DATA on parameter-verification failure.
 */
pub fn clone(dst: &mut Context , src: &Context) -> i32{
    if dst.md_info.name != src.md_info.name{
        return ERR_MD_BAD_INPUT_DATA;
    }
    match src.md_info.md_type{
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => md2::clone(&mut dst.md_ctx_md_2, &src.md_ctx_md_2),
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => md4::clone(&mut dst.md_ctx, &src.md_ctx),
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => md5::clone(&mut dst.md_ctx, &src.md_ctx),
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => sha1::clone(&mut dst.md_ctx, &src.md_ctx),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => sha256::clone(&mut dst.md_ctx, &src.md_ctx),
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => sha256::clone(&mut dst.md_ctx, &src.md_ctx),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => sha512::clone(&mut dst.md_ctx, &src.md_ctx),
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512 => sha512::clone(&mut dst.md_ctx, &src.md_ctx),
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => ripemd160::clone(&mut dst.md_ctx, &src.md_ctx),
        _ => return ERR_MD_BAD_INPUT_DATA,
    }
    return 0;
}

/**
 * \brief           This function starts a message-digest computation.
 *
 *                  You must call this function after initializing context
 *                  with init(), and before passing data with
 *                  update().
 *
 * \param ctx       The generic message-digest context.
 *
 * \return          \c 0 on success.
 * \return          #ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
pub fn starts(ctx: &mut Context) -> i32{
    match ctx.md_info.md_type{
        
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => return md2::starts_ret(&mut ctx.md_ctx_md_2),
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => return md4::starts_ret(&mut ctx.md_ctx),
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => return md5::starts_ret(&mut ctx.md_ctx),
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => return sha1::starts_ret(&mut ctx.md_ctx),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => return sha256::starts_ret(&mut ctx.md_ctx, 1),
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => return sha256::starts_ret(&mut ctx.md_ctx, 0),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => return sha512::starts_ret(&mut ctx.md_ctx, 1),
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512 => return sha512::starts_ret(&mut ctx.md_ctx, 0),
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => return ripemd160::starts_ret(&mut ctx.md_ctx),
        
        _ => return ERR_MD_BAD_INPUT_DATA,
    }
}

/**
 * \brief           This function feeds an input buffer into an ongoing
 *                  message-digest computation.
 *
 *                  You must call starts() before calling this
 *                  function. You may call this function multiple times.
 *                  Afterwards, call finish().
 *
 * \param ctx       The generic message-digest context.
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
pub fn update(ctx: &mut Context, input: &Vec<u8>, ilen: usize) -> i32{
    match ctx.md_info.md_type{
        
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => return md2::update_ret(&mut ctx.md_ctx_md_2, input, ilen),
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => return md4::update_ret(&mut ctx.md_ctx, input, ilen),
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => return md5::update_ret(&mut ctx.md_ctx, input, ilen),
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => return sha1::update_ret(&mut ctx.md_ctx, input, ilen),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => return sha256::update_ret(&mut ctx.md_ctx, input, ilen),
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => return sha256::update_ret(&mut ctx.md_ctx, input, ilen),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => return sha512::update_ret(&mut ctx.md_ctx, input, ilen),
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512 => return sha512::update_ret(&mut ctx.md_ctx, input, ilen),
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => return ripemd160::update_ret(&mut ctx.md_ctx, input, ilen),
        
        _ => return ERR_MD_BAD_INPUT_DATA,
    }
}

/**
 * \brief           This function finishes the digest operation,
 *                  and writes the result to the output buffer.
 *
 *                  Call this function after a call to starts(),
 *                  followed by any number of calls to update().
 *                  Afterwards, you may either clear the context with
 *                  free(), or call starts() to reuse
 *                  the context for another digest operation with the same
 *                  algorithm.
 *
 * \param ctx       The generic message-digest context.
 * \param output    The buffer for the generic message-digest checksum result.
 *
 * \return          \c 0 on success.
 * \return          #ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
pub fn finish(ctx: &mut Context, output: &mut Vec<u8>) -> i32{
    match ctx.md_info.md_type{
        
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => return md2::finish_ret(&mut ctx.md_ctx_md_2, output),
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => return md4::finish_ret(&mut ctx.md_ctx, output),
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => return md5::finish_ret(&mut ctx.md_ctx, output),
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => return sha1::finish_ret(&mut ctx.md_ctx, output),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => return sha256::finish_ret(&mut ctx.md_ctx, output),
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => return sha256::finish_ret(&mut ctx.md_ctx, output),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => return sha512::finish_ret(&mut ctx.md_ctx, output),
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512 => return sha512::finish_ret(&mut ctx.md_ctx, output),
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => return ripemd160::finish_ret(&mut ctx.md_ctx, output),
        
        _ => return ERR_MD_BAD_INPUT_DATA,
    }

}

fn md(md_info: &MdInfoT, input: &Vec<u8>, ilen: usize, output: &mut Vec<u8>) -> i32{
    match md_info.md_type{
        
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => return md2::ret(input, ilen, output),
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => return md4::ret(input, ilen, output),
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => return md5::ret(input, ilen, output),
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => return sha1::ret(input, ilen, output),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => return sha256::ret(input, ilen, output, 1),
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => return sha256::ret(input, ilen, output, 0),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => return sha512::ret(input, ilen, output, 1),
        
        #[cfg(feature = "SHA384")]
        MdTypeT::SHA512 => return sha512::ret(input, ilen, output, 0),

        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => return ripemd160::ret(input, ilen, output),

        _ => return ERR_MD_BAD_INPUT_DATA,
    };
}

// #[cfg(feature = "FS_IO")]
fn md_file(md_info: &MdInfoT, path_str: &String, output: &mut Vec<u8>) -> i32 {
    use std::fs::File;
    use std::path::Path;
    use std::io::{self, prelude::*, BufReader};

    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    let path = Path::new(path_str);
    let mut file = match File::open(path){
        Err(why) => panic!("couldn't open {}: {}", path.display(), why),
        Ok(file) => file,
    };

    let mut s = String::new();
    match file.read_to_string(&mut s){
        Err(why) => panic!("couldn't read {}: {}", path.display(), why),
        Ok(_) => (),
    }
    
    let s_vec: Vec<u8> = s.as_bytes().to_vec();
    ret = md(md_info, &s_vec, s_vec.len(), output);
    if ret!=0{
        return ret;
    }

    return 0;
}


/**
 * \brief           This function sets the HMAC key and prepares to
 *                  authenticate a new message.
 *
 *                  Call this function after setup(), to use
 *                  the MD context for an HMAC calculation, then call
 *                  hmac_update() to provide the input data, and
 *                  hmac_finish() to get the HMAC value.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param key       The HMAC secret key.
 * \param keylen    The length of the HMAC key in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
pub fn hmac_starts(ctx: &mut Context, key: &Vec<u8>, mut keylen: usize) -> i32{
    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut final_key: Vec<u8> = key.clone();

    if ctx.hmac_ctx.len() != usize::from(ctx.md_info.block_size*2){
        return ERR_MD_BAD_INPUT_DATA;
    }

    let clean = |x: &mut Vec<u8>| {for i in &mut x.iter_mut(){*i = 0;}};

    if keylen > usize::from(ctx.md_info.block_size){
        ret = starts(ctx);
        if ret!=0 { clean(&mut final_key); }

        ret = update(ctx, key, keylen);
        if ret!=0 { clean(&mut final_key); };

        ret = finish(ctx, &mut final_key);
        if ret!=0 {clean(&mut final_key); };

        keylen = usize::from(ctx.md_info.size);
    }

    let mut opad: &mut [u8] = &mut ctx.hmac_ctx[(ctx.md_info.block_size as usize) ..];
    for i in &mut opad.iter_mut(){
        *i = 0x5C;
    }
    for i in 0..keylen{
        opad[i] = opad[i] ^ key[i];
    }

    let mut ipad: &mut [u8] = &mut ctx.hmac_ctx[.. (ctx.md_info.block_size as usize)];
    for i in &mut ipad.iter_mut(){
        *i = 0x36;
    }
    for i in 0..keylen{
        ipad[i] = ipad[i] ^ key[i];
    }

    ret = starts(ctx);
    if ret!=0{
        clean(&mut final_key);
    }

    ret = update(ctx, &ctx.hmac_ctx[.. (ctx.md_info.block_size as usize)].to_vec(), ctx.md_info.block_size as usize);
    if ret!=0{
        clean(&mut final_key);
    }

    clean(&mut final_key);
    return ret;
}

pub fn hmac_update(ctx: &mut Context, input: &Vec<u8>, ilen: usize) -> i32{
    if ctx.hmac_ctx.len() != usize::from(ctx.md_info.block_size*2){
        return ERR_MD_BAD_INPUT_DATA;
    }

    return update(ctx, input, ilen);
}

pub fn hmac_finish(ctx: &mut Context, output: &mut Vec<u8>) -> i32{
    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    let mut tmp: Vec<u8> = vec![0; output.len()];
    
    if ctx.hmac_ctx.len() != usize::from(ctx.md_info.block_size*2){
        return ERR_MD_BAD_INPUT_DATA;
    }

    let opad = Vec::from(&ctx.hmac_ctx[(ctx.md_info.block_size as usize) ..]);
    
    ret = finish(ctx, &mut tmp);
    if ret!=0{
        return ret;
    }

    ret = starts(ctx);
    if ret!=0{
        return ret;
    }

    ret = update(ctx, &opad, ctx.md_info.block_size as usize);
    if ret!=0{
        return ret;
    }

    ret = update(ctx, &tmp.to_vec(), ctx.md_info.size as usize);
    if ret!=0{
        return ret;
    }

    return finish(ctx, output);
}

pub fn hmac_reset(ctx: &mut Context) -> i32{
    let mut ret: i32 = error::ERR_ERROR_CORRUPTION_DETECTED;
    
    if ctx.hmac_ctx.len() != usize::from(ctx.md_info.block_size*2){
        return ERR_MD_BAD_INPUT_DATA;
    }

    let mut ipad = ctx.hmac_ctx.clone();
    ret = starts(ctx);
    if ret!=0{
        return ret;
    }

    return update(ctx, &ipad, ctx.md_info.block_size as usize);
}

fn hmac(md_info: &MdInfoT, key: &Vec<u8>, keylen: usize, input: &Vec<u8>, ilen: usize, output: &mut Vec<u8>) -> i32{
    let mut ctx = create_context();
    let mut ret = error::ERR_ERROR_CORRUPTION_DETECTED;
    
    ret = setup(ctx.as_mut(), &md_info.md_type, true);
    if ret!=0{
        free(ctx.as_mut());
        return ret;
    }

    ret =  hmac_starts(ctx.as_mut(), key, keylen);
    if ret!=0{
        free(ctx.as_mut());
        return ret;
    }

    ret =  hmac_update(ctx.as_mut(), input, ilen);
    if ret!=0{
        free(ctx.as_mut());
        return ret;
    }

    ret = hmac_finish(ctx.as_mut(), output);
    if ret!=0{
        free(ctx.as_mut());
        return ret;
    }

    return ret;
}

fn process(ctx: &mut Context, data: &[u8])->i32{
    match ctx.md_info.md_type{
        #[cfg(feature = "MD2")]
        MdTypeT::MD2 => return md2::internal_process(&mut ctx.md_ctx_md_2),
        
        #[cfg(feature = "MD4")]
        MdTypeT::MD4 => return md4::internal_process(&mut ctx.md_ctx, data),
        
        #[cfg(feature = "MD5")]
        MdTypeT::MD5 => return md5::internal_process(&mut ctx.md_ctx, data),
        
        #[cfg(feature = "SHA1")]
        MdTypeT::SHA1 => return sha1::internal_process(&mut ctx.md_ctx, data),
        
        #[cfg(all(feature = "SHA256", not(feature = "NO_SHA224")))]
        MdTypeT::SHA224 => return sha256::internal_process(&mut ctx.md_ctx, data),
        
        #[cfg(feature = "SHA256")]
        MdTypeT::SHA256 => return sha256::internal_process(&mut ctx.md_ctx, data),
        
        #[cfg(all(feature = "SHA512", not(feature = "NO_SHA384")))]
        MdTypeT::SHA384 => return sha512::internal_process(&mut ctx.md_ctx, data),
        
        #[cfg(feature = "SHA512")]
        MdTypeT::SHA512 => return sha512::internal_process(&mut ctx.md_ctx, data),
        
        #[cfg(feature = "RIPEMD160")]
        MdTypeT::RIPEMD160 => return ripemd160::internal_process(&mut ctx.md_ctx, data),

        _ => return ERR_MD_BAD_INPUT_DATA,
    }
}

fn get_size(md_info: MdInfoT) -> u8{
    return md_info.size;
}

fn get_type(md_info: MdInfoT) -> MdTypeT{
    return md_info.md_type;
}

fn get_name(md_info: &MdInfoT) -> &'static str{
    return md_info.name;
}
#[cfg(test)]
mod test{
    /**
     * MD2 specific tests
     */
     const test_str: [&str; 7] = 
     [  "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
     ];

    const test_strlen: [usize; 7] = [0, 1, 3, 14, 26, 62, 80];

    const test_sum: [[u8; 16]; 7] = 
    [
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

    use std::cmp;
    fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
        a.iter()
        .zip(b)
        .map(|(x, y)| x.cmp(y))
        .find(|&ord| ord != cmp::Ordering::Equal)
        .unwrap_or(a.len().cmp(&b.len()))
    }

    #[cfg(feature = "MD2")]
    #[test]
    pub fn md_test(){
        let mut md2sum: Vec<u8> = vec![0; 16];
        for i in 0..7{
            assert_eq!(0, 
                super::md( &super::MD2_INFO, 
                &test_str[i].as_bytes().to_vec(), 
                test_strlen[i], &mut md2sum)
            );

            assert_eq!(cmp::Ordering::Equal, 
                compare(md2sum.as_ref(), 
                &test_sum[i])
            );
        }
    }

    #[cfg(feature = "MD2")]
    // #[test]
    //If you want to enable this test create appropriate md2_input.txt
    pub fn md_file_test(){
        // TODO: This test uses hardcoded absolute file path. Fix this.
        let mut md2sum: Vec<u8> = vec![0; 16];
        let path = String::from(
            "C:\\Users\\vimal patel\\Desktop\\TPCSS_MBED_TLS\\source\\src\\hashing\\test\\md2_input.txt"
        );
        assert_eq!(0, super::md_file( &super::MD2_INFO, &path, &mut md2sum));
        assert_eq!(cmp::Ordering::Equal, compare(md2sum.as_ref(), &test_sum[6]));
    }

    // MD2 based HMAC tests
    #[cfg(feature = "MD2")]
    #[test]
    fn hmac_test(){
        let key = String::from("key");
        let input = String::from("The quick brown fox jumps over the lazy dog");
        let actual_output: [u8; 16] = [
            0x13, 0x75, 0x8b, 0x95, 
            0x34, 0xbf, 0xb3, 0x8d,
            0x85, 0x04, 0x57, 0x81,
            0x46, 0x13, 0xb0, 0xc1
        ];
        let mut output: Vec<u8> = vec![0; super::MD2_INFO.size as usize];
        let key_vec = key.as_bytes().to_vec();
        let input_vec = input.as_bytes().to_vec();
        
        assert_eq!(0, super::hmac(&super::MD2_INFO, 
                        &key_vec, key_vec.len(), 
                        &input_vec, input_vec.len(), 
                        &mut output));
        assert_eq!(cmp::Ordering::Equal, 
                    compare(output.as_ref(), 
                    &actual_output));
    }

}
