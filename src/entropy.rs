#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused)]
#![allow(unused_imports)]

pub mod entropy_poll_header;
pub mod entropy_header;

use entropy_header::*;
use entropy_poll_header::*;

// use std::fs;
use std::ffi::c_void;

pub const ENTROPY_MAX_LOOP: i32 = 256;

pub fn check() {
    println!("paras");
}

pub fn mbedtls_sha512_free(ctx: *mut mbedtls_sha512_context ) -> () {
    if ctx.is_null() {
        return;
    }
    unsafe {
        *ctx = Default::default();
    }
}

pub fn mbedtls_entropy_free(ctx: &mut mbedtls_entropy_context) -> () {

    mbedtls_sha512_free(&mut ctx.accumulator);
    ctx.initial_entropy_run = 0;

    ctx.source_count = 0;
    ctx.source = Default::default();
    ctx.accumulator_started = 0;
}

pub fn mbedtls_sha512_init(ctx: &mut mbedtls_sha512_context ) -> () {

    *ctx = Default::default();
}

fn mbedtls_hardclock_poll(data: Option<*mut c_void>, output: &mut [u8], len: usize, olen: usize) -> i32 {

    println!("Default for entropy f_source ptr");
    return 2;
}
fn mbedtls_nv_seed_poll(data: Option<*mut c_void>, output: &mut [u8], len: usize, olen: usize) -> i32 {

    println!("For entropy f_source ptr");
    return 2;
}

pub fn mbedtls_platform_entropy_poll(data: Option<*mut c_void>, output: &mut [u8], len: usize, olen: usize) -> i32 {

    println!("Default for entropy f_source ptr");
    return 2;
}

fn mbedtls_sha512_ret(input: &mut [u8], ilen: usize, output: &mut [u8], is384: i32) -> i32 {

    println!("sha.c file's function template");
    return 0;
}

fn mbedtls_sha512_starts_ret(ctx: &mut mbedtls_sha512_context, is384: i32) -> i32 {
    println!("sha.c file's function template");
    return 0;
}

fn mbedtls_sha512_update_ret(ctx: &mut mbedtls_sha512_context, input: &mut [u8], ilen: usize) -> i32 {
    println!("sha.c file's function template");
    return 0;
}

fn mbedtls_sha512_finish_ret(ctx: &mut mbedtls_sha512_context, is384: &mut [u8]) -> i32 {
    println!("sha.c file's function template");
    return 0;
}


pub fn mbedtls_entropy_init(ctx: &mut mbedtls_entropy_context) -> () {

    ctx.source_count = 0;
    ctx.source = Default::default();
    ctx.accumulator_started = 0;

    mbedtls_sha512_init(&mut ctx.accumulator);

    mbedtls_entropy_add_source(&mut *ctx, mbedtls_platform_entropy_poll, None, MBEDTLS_ENTROPY_MIN_PLATFORM, MBEDTLS_ENTROPY_SOURCE_STRONG);

    mbedtls_entropy_add_source(&mut *ctx, mbedtls_hardclock_poll, None, MBEDTLS_ENTROPY_MIN_HARDCLOCK, MBEDTLS_ENTROPY_SOURCE_WEAK);

    mbedtls_entropy_add_source(&mut *ctx, mbedtls_nv_seed_poll, None, MBEDTLS_ENTROPY_BLOCK_SIZE, MBEDTLS_ENTROPY_SOURCE_STRONG);
    ctx.initial_entropy_run = 0;
}


fn mbedtls_entropy_add_source(ctx: &mut mbedtls_entropy_context, f_source: mbedtls_entropy_f_source_ptr , p_source: Option<*mut c_void>, threshold: usize, strong: i32) -> i32 {

    let mut ret: i32 = 0;
    let mut idx: usize = 0;

    idx = ctx.source_count;

    if idx >= MBEDTLS_ENTROPY_MAX_SOURCES {

        ret = MBEDTLS_ERR_ENTROPY_MAX_SOURCES ;
    }
    else {

        ctx.source[idx].f_source  = f_source;
        ctx.source[idx].p_source  = p_source;
        ctx.source[idx].threshold = threshold;
        ctx.source[idx].strong    = strong;

        ctx.source_count += 1;
    }

    return ret;
}


fn entropy_cleanup(tmp: &mut [u8], ret: i32) -> i32 {

    for i in &mut *tmp { *i = 0; }
    return ret;
}

fn entropy_update(ctx: &mut mbedtls_entropy_context, source_id: u8, data: &mut [u8], len: usize) -> i32 {

    let mut header: [u8; 2] = [0; 2];
    let mut tmp: [u8; MBEDTLS_ENTROPY_BLOCK_SIZE] = [0; MBEDTLS_ENTROPY_BLOCK_SIZE];
    let mut use_len: usize = len;
    let mut p: &[u8] = data;
    let mut ret: i32 = 0;

    if use_len > MBEDTLS_ENTROPY_BLOCK_SIZE {
        ret = mbedtls_sha512_ret(&mut *data, len, &mut tmp, 0);
        if ret != 0 {
            return entropy_cleanup(&mut tmp, ret);
        }
        p = &tmp;
        use_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    }

    header[0] = source_id;
    header[1] = (use_len as u8) & 0xFF;

    /*
     * Start the accumulator if this has not already happened. Note that
     * it is sufficient to start the accumulator here only because all calls to
     * gather entropy eventually execute this code.
     */

    ret = mbedtls_sha512_starts_ret(&mut ctx.accumulator, 0);
    if ctx.accumulator_started == 0 && ret != 0 {
        return entropy_cleanup(&mut tmp, ret);
    }
    else {
        ctx.accumulator_started = 1;
    }
    ret = mbedtls_sha512_update_ret(&mut ctx.accumulator, &mut header, 2);
    if ret != 0 {
        return entropy_cleanup(&mut tmp, ret);
    }


    return entropy_cleanup(&mut tmp, ret);
}


fn mbedtls_entropy_update_manual(ctx: &mut mbedtls_entropy_context, data: &mut [u8], len: usize) -> i32 {

    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ret = entropy_update(&mut *ctx, MBEDTLS_ENTROPY_SOURCE_MANUAL as u8, data, len);
    return ret;
}


fn entropy_gather_internal(ctx: &mut mbedtls_entropy_context) -> i32 {

    let mut ret: i32 = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    let mut i: i32 = 0;
    let mut have_one_strong: i32 = 0;
    let mut buf: [u8; MBEDTLS_ENTROPY_MAX_GATHER] = [0; MBEDTLS_ENTROPY_MAX_GATHER];
    let mut olen: usize = 0;

    if ctx.source_count == 0 {
        return MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED;
    }

    /*
     * Run through our entropy sources
     */
    for i in 0..(ctx.source_count) {

        if ctx.source[i].strong == MBEDTLS_ENTROPY_SOURCE_STRONG {
            have_one_strong = 1;
        }

        olen = 0;

        ret = (ctx.source[i].f_source)(ctx.source[i].p_source, &mut buf, MBEDTLS_ENTROPY_MAX_GATHER, olen);

        if ret != 0 {
            return entropy_cleanup(&mut buf, ret);
        }

        /*
         * Add if we actually gathered something
         */

        if olen > 0 {
            ret = entropy_update(ctx, i as u8, &mut buf, olen);
            if ret != 0 {
                return ret;
            }
            ctx.source[i].size += olen;
        }
    }

    if have_one_strong == 0 {
        ret = MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE;
    }

    return entropy_cleanup(&mut buf, ret);
}


fn mbedtls_entropy_gather(ctx: &mut mbedtls_entropy_context) -> i32 {

    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ret = entropy_gather_internal(&mut *ctx);
    return ret;
}


fn mbedtls_entropy_func(ctx: &mut mbedtls_entropy_context, output: &mut [u8], len: usize) -> i32 {

    let mut ret: i32 = 0;
    let mut i: i32 = 0;
    let mut thresholds_reached: bool = false;
    let mut count: i32 = 0;
    let mut strong_size: usize = 0;
    // let mut ctx: mbedtls_entropy_context = data;
    let mut buf: [u8; MBEDTLS_ENTROPY_BLOCK_SIZE] = [0; MBEDTLS_ENTROPY_BLOCK_SIZE];

    if len > MBEDTLS_ENTROPY_BLOCK_SIZE {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    /* Update the NV entropy seed before generating any entropy for outside
     * use.
     */
    if ctx.initial_entropy_run == 0 {
        ctx.initial_entropy_run = 1;
        ret = mbedtls_entropy_update_nv_seed(&mut *ctx);
        if ret != 0 {
            return ret;
        }
    }

    /*
     * Always gather extra entropy before a call
     */

    loop {

        if count > ENTROPY_MAX_LOOP {
            count += 1;
            ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
            return entropy_cleanup(&mut buf, ret);
        }
        else {
            count += 1;
        }

        ret = entropy_gather_internal(&mut *ctx);

        if ret != 0 {
            return entropy_cleanup(&mut buf, ret);
        }

        thresholds_reached = true;
        strong_size = 0;

        for i in 0..ctx.source_count {

            if ctx.source[i].size < ctx.source[i].threshold {
                thresholds_reached = false;
            }
            if ctx.source[i].strong == MBEDTLS_ENTROPY_SOURCE_STRONG {
                strong_size += ctx.source[i].size;
            }
        }
        if (thresholds_reached && strong_size >= MBEDTLS_ENTROPY_BLOCK_SIZE) {
            break;
        }
    }

    for i in &mut buf { *i = 0; }

    ret = mbedtls_sha512_finish_ret(&mut ctx.accumulator, &mut buf);
    if ret != 0 {
        return entropy_cleanup(&mut buf, ret);
    }
    mbedtls_sha512_free(&mut ctx.accumulator);
    mbedtls_sha512_init(&mut ctx.accumulator);

    ret = mbedtls_sha512_starts_ret(&mut ctx.accumulator, 0);
    if ret != 0 {
        return entropy_cleanup(&mut buf, ret);
    }
    ret = mbedtls_sha512_update_ret(&mut ctx.accumulator, &mut buf, MBEDTLS_ENTROPY_BLOCK_SIZE);
    if ret != 0 {
        return entropy_cleanup(&mut buf, ret);
    }

    let mut buf_output: [u8; MBEDTLS_ENTROPY_BLOCK_SIZE] = buf;

    ret = mbedtls_sha512_ret(&mut buf, MBEDTLS_ENTROPY_BLOCK_SIZE, &mut buf_output, 0);
    if ret != 0 {
        return entropy_cleanup(&mut buf, ret);
    }

    for i in 0..ctx.source_count {
        ctx.source[i].size = 0;
    }

    for i in 0..len {
        output[i] = buf[i];
    }

    ret = 0;
    return entropy_cleanup(&mut buf, ret);
}

fn mbedtls_entropy_update_nv_seed(ctx: &mut mbedtls_entropy_context) -> i32 {

    let mut ret: i32 = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    let mut buf: [u8; MBEDTLS_ENTROPY_BLOCK_SIZE] = [0; MBEDTLS_ENTROPY_BLOCK_SIZE];

    ret = mbedtls_entropy_func(&mut *ctx, &mut buf, MBEDTLS_ENTROPY_BLOCK_SIZE);
    if ret != 0 {
        return ret;
    }

    // if mbedtls_nv_seed_write(buf, MBEDTLS_ENTROPY_BLOCK_SIZE) < 0 {
    //     return MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    // }

    for i in &mut buf { *i = 0; }
    ret = mbedtls_entropy_update_manual(&mut *ctx, &mut buf, MBEDTLS_ENTROPY_BLOCK_SIZE);

    return ret;
}
