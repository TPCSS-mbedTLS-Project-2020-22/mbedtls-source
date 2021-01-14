use std::fs;
use std::mem;
use std::ptr;

const MBEDTLS_ENTROPY_MAX_SOURCES: i32 = 2;

struct mbedtls_entropy_context
{
    accumulator_started: i32,
    source_count: i32,
    source: [mbedtls_entropy_source_state; MBEDTLS_ENTROPY_MAX_SOURCES],

    #[cfg(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR")]
    accumulator: mbedtls_sha512_context,

    #[cfg(not(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR"))]
    accumulator: mbedtls_sha256_context,

    #[cfg(feature="MBEDTLS_HAVEGE_C")]
    havege_data: mbedtls_havege_state,

    #[cfg(feature="MBEDTLS_THREADING_C")]
    mutex: mbedtls_threading_mutex_t,

    #[cfg(feature="MBEDTLS_ENTROPY_NV_SEED")]
    initial_entropy_run: i32
}

fn mbedtls_entropy_init(ctx: &mut mbedtls_entropy_context) -> () {

    ctx.source_count = 0;

    // memset ctx.source //TODO:
    for i in &mut ctx.source { *i = 0 }

    #[cfg(feature="MBEDTLS_THREADING_C")]
    mbedtls_mutex_init(&mut ctx.mutex);

    ctx.accumulator_started = 0;

    #[cfg(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR")]
    mbedtls_sha512_init(&mut ctx.accumulator);

    #[cfg(not(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR"))]
    mbedtls_sha256_init(&mut ctx.accumulator);

    #[cfg(feature="MBEDTLS_HAVEGE_C")]
    mbedtls_havege_init(&mut ctx.havege_data);

    #[cfg(feature="MBEDTLS_TEST_NULL_ENTROPY")]
    mbedtls_entropy_add_source(&mut ctx, mbedtls_null_entropy_poll, None, 1, MBEDTLS_ENTROPY_SOURCE_STRONG);

    if (#[cfg(not(feature="MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES"))]) {

        if ()#[cfg(not(feature="MBEDTLS_NO_PLATFORM_ENTROPY"))]
        mbedtls_entropy_add_source(&mut ctx, mbedtls_platform_entropy_poll, None, MBEDTLS_ENTROPY_MIN_PLATFORM, MBEDTLS_ENTROPY_SOURCE_STRONG);

        #[cfg(feature="MBEDTLS_TIMING_C")]
        mbedtls_entropy_add_source(&mut ctx, mbedtls_hardclock_poll, None, MBEDTLS_ENTROPY_MIN_HARDCLOCK, MBEDTLS_ENTROPY_SOURCE_WEAK);

        #[cfg(feature="MBEDTLS_HAVEGE_C")]
        mbedtls_entropy_add_source(&mut ctx, mbedtls_havege_poll, &mut ctx.havege_data, MBEDTLS_ENTROPY_MIN_HAVEGE, MBEDTLS_ENTROPY_SOURCE_STRONG);

        #[cfg(feature="MBEDTLS_ENTROPY_HARDWARE_ALT")]
        mbedtls_entropy_add_source(&mut ctx, mbedtls_hardware_poll, None, MBEDTLS_ENTROPY_MIN_HARDWARE, MBEDTLS_ENTROPY_SOURCE_STRONG);

        if #[cfg(feature="MBEDTLS_ENTROPY_NV_SEED")] {
            mbedtls_entropy_add_source(&mut ctx, mbedtls_nv_seed_poll, None, MBEDTLS_ENTROPY_BLOCK_SIZE, MBEDTLS_ENTROPY_SOURCE_STRONG);
            ctx.initial_entropy_run = 0;
        }
    }

}

fn mbedtls_entropy_free(ctx: &mut mbedtls_entropy_context) -> () {

    #[cfg(feature="MBEDTLS_HAVEGE_C")]
    mbedtls_havege_free(&mut ctx.havege_data);

    #[cfg(feature="MBEDTLS_THREADING_C")]
    mbedtls_mutex_free(&mut ctx.mutex);

    #[cfg(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR")]
    mbedtls_sha512_free(&mut ctx.accumulator);

    #[cfg(not(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR"))]
    mbedtls_sha256_free(&mut ctx.accumulator);

    #[cfg(feature="MBEDTLS_ENTROPY_NV_SEED")]
    ctx.initial_entropy_run = 0;

    ctx.source_count = 0;
    mbedtls_platform_zeroize(ctx.source, mem::size_of::<ctx.source>());
    ctx.accumulator_started = 0;
}


fn mbedtls_entropy_add_source(ctx: &mut mbedtls_entropy_context, f_source: mbedtls_entropy_f_source_ptr , *p_source, threshold: usize, strong: i32) {

    let mut ret, idx: i32 = 0;

    ret = mbedtls_mutex_lock(&mut ctx.mutex);
    #[cfg(feature="MBEDTLS_THREADING_C")]
    if ret != 0 {
        return ret;
    }

    idx = ctx.source_count;

    if idx >= MBEDTLS_ENTROPY_MAX_SOURCES {

        ret = MBEDTLS_ERR_ENTROPY_MAX_SOURCES;
    }
    else {

        ctx.source[idx].f_source  = f_source;
        ctx.source[idx].p_source  = p_source;
        ctx.source[idx].threshold = threshold;
        ctx.source[idx].strong    = strong;

        ctx.source_count++;
    }

    #[cfg(feature="MBEDTLS_THREADING_C")]
    if mbedtls_mutex_unlock(&mut ctx.mutex) != 0 {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return ret;
}

fn entropy_cleanup(tmp: &mut [u8], size_of_tmp: usize, ret: &mut i32) -> i32 {

    mbedtls_platform_zeroize(tmp, size_of_tmp);
    return ret;
}

fn entropy_update(ctx: &mut mbedtls_entropy_context, source_id: u8, data: *mut u8, len: usize) -> i32 {

    let mut header: [u8: 2];
    let mut tmp: [u8: MBEDTLS_ENTROPY_BLOCK_SIZE];
    let mut use_len: usize = len;
    let p: *const u8 = data;
    let mut ret: i32 = 0;

    if use_len > MBEDTLS_ENTROPY_BLOCK_SIZE {
        if #[cfg(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR")] {
            ret = mbedtls_sha512_ret(data, len, tmp, 0);
            if ret != 0 {
                return entropy_update_cleanup(&mut tmp, MBEDTLS_ENTROPY_BLOCK_SIZE, ret);
            }
        }
        else {
            ret = mbedtls_sha256_ret(data, len, tmp, 0);
            if ret != 0 {
                return entropy_update_cleanup(&mut tmp, MBEDTLS_ENTROPY_BLOCK_SIZE, ret);
            }
        }
        p = tmp;
        use_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    }

    header[0] = source_id;
    header[1] = use_len & 0xFF;

    /*
     * Start the accumulator if this has not already happened. Note that
     * it is sufficient to start the accumulator here only because all calls to
     * gather entropy eventually execute this code.
     */

    if #[cfg(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR")] {
        ret = mbedtls_sha512_starts_ret(&mut ctx.accumulator, 0);
        if ctx.accumulator_started == 0 && ret != 0 {
            return entropy_update_cleanup(&mut tmp, MBEDTLS_ENTROPY_BLOCK_SIZE, ret);
        }
        else {
            ctx.accumulator_started = 1;
        }
        ret = mbedtls_sha512_update_ret(&mut ctx.accumulator, header, 2);
        if ret != 0 {
            return entropy_update_cleanup(&mut tmp, MBEDTLS_ENTROPY_BLOCK_SIZE, ret);
        }
    }
    else {
        ret = mbedtls_sha256_starts_ret(&mut ctx.accumulator, 0);
        if ctx.accumulator_started == 0 && ret != 0 {
            return entropy_update_cleanup(&mut tmp, MBEDTLS_ENTROPY_BLOCK_SIZE, ret);
        }
        else {
            ctx.accumulator_started = 1;
        }
        ret = mbedtls_sha256_update_ret(&mut ctx.accumulator, header, 2);
        if ret != 0 {
            return entropy_update_cleanup(&mut tmp, MBEDTLS_ENTROPY_BLOCK_SIZE, ret);
        }
    }

    return entropy_update_cleanup(&mut tmp, MBEDTLS_ENTROPY_BLOCK_SIZE, ret);
}


fn mbedtls_entropy_update_manual(ctx: &mut  mbedtls_entropy_context, data: *mut u8, len: usize) -> i32 {

    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_mutex_lock(&mut ctx.mutex);

    #[cfg(feature="MBEDTLS_THREADING_C")]
    if ret != 0 {
        return ret;
    }

    ret = entropy_update(ctx, MBEDTLS_ENTROPY_SOURCE_MANUAL, data, len);

    #[cfg(feature="MBEDTLS_THREADING_C")]
    if mbedtls_mutex_unlock(&mut ctx.mutex) != 0 {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return ret;
}


fn entropy_gather_internal(ctx: &mut mbedtls_entropy_context) -> i32 {

    let mut ret: i32 = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    let mut i: i32;
    let mut have_one_strong: i32 = 0;
    let mut buf: [u8, MBEDTLS_ENTROPY_MAX_GATHER];
    let mut olen: usize;

    if ctx.source_count == 0 {
        return MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED;
    }

    /*
     * Run through our entropy sources
     */
    for i in 0..(ctx.source_count) {

        if ctx.source[i].strong == MBEDTLS_ENTROPY_SOURCE_STRONG
            have_one_strong = 1;

        olen = 0;

        ret = ctx.source[i].f_source(ctx.source[i].p_source, buf, MBEDTLS_ENTROPY_MAX_GATHER, &mut olen);

        if ret != 0 {
            return entropy_cleanup(&mut buf, MBEDTLS_ENTROPY_MAX_GATHER, ret);
        }

        /*
         * Add if we actually gathered something
         */

        if olen > 0 {
            ret = entropy_update(ctx, i as u8, buf, olen);
            if ret != 0 {
                return ret;
            }
            ctx.source[i].size += olen;
        }
    }

    if have_one_strong == 0 {
        ret = MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE;
    }

    return entropy_cleanup(&mut buf, MBEDTLS_ENTROPY_MAX_GATHER, ret);
}


/*
 * Thread-safe wrapper for entropy_gather_internal()
 */
fn mbedtls_entropy_gather(ctx: &mut mbedtls_entropy_context) -> i32 {

    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if #[cfg(feature="MBEDTLS_THREADING_C")] {
        ret = mbedtls_mutex_lock(&mut ctx.mutex);
        if ret != 0 {
            return ret;
        }
    }

    ret = entropy_gather_internal(ctx);

    if #[cfg(feature="MBEDTLS_THREADING_C")] {
        if mbedtls_mutex_unlock(&mut ctx.mutex) != 0 {
            return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
        }
    }

    return ret;
}


fn entropy_exit(tmp: &mut [u8], size_of_tmp: usize, ret: &mut i32, ctx: &mut mbedtls_entropy_context) -> i32 {

    mbedtls_platform_zeroize(tmp, size_of_tmp);

    #[cfg(feature="MBEDTLS_THREADING_C")]
    if mbedtls_mutex_unlock(&mut ctx.mutex) != 0 {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return ret;
}

fn mbedtls_entropy_func(data: *mut, output: *mut u8, len: usize) -> i32 {

    let mut ret, i, threasholds_reached: i32;
    let mut count: i32 = 0;
    let mut strong_size: usize;
    let mut ctx: mbedtls_entropy_context = data as mbedtls_entropy_context;
    let mut buf: [u8, MBEDTLS_ENTROPY_BLOCK_SIZE];

    if len > MBEDTLS_ENTROPY_BLOCK_SIZE {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    /* Update the NV entropy seed before generating any entropy for outside
     * use.
     */
    #[cfg(feature="MBEDTLS_ENTROPY_NV_SEED")]
    if ctx.initial_entropy_run == 0 {
        ctx.initial_entropy_run = 1;
        ret = mbedtls_entropy_update_nv_seed(ctx);
        if ret != 0 {
            return ret;
        }
    }

    if #[cfg(feature="MBEDTLS_THREADING_C")] {

        ret = mbedtls_mutex_lock(&mut ctx.mutex);
        if ret != 0 {
            return ret;
        }
    }


    /*
     * Always gather extra entropy before a call
     */

    loop {

        if count > ENTROPY_MAX_LOOP
        {
            count += 1;
            ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }
        else {
            count += 1;
        }

        ret = entropy_gather_internal(ctx);

        if ret != 0
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);

        thresholds_reached = 1;
        strong_size = 0;

        for i in 0..ctx.source_count {

            if ctx.source[i].size < ctx.source[i].threshold {
                thresholds_reached = 0;
            }
            if ctx.source[i].strong == MBEDTLS_ENTROPY_SOURCE_STRONG {
                strong_size += ctx.source[i].size;
            }
        }
        if (thresholds_reached && strong_size >= MBEDTLS_ENTROPY_BLOCK_SIZE) {
            break;
        }
    }

    // memset
    for i in &mut buf { *i = 0 }

    if #[cfg(feature="MBEDTLS_ENTROPY_SHA512_ACCUMULATOR")] {
        ret = mbedtls_sha512_finish_ret(&mut ctx.accumulator, buf);
        if ret != 0 {
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }
        mbedtls_sha512_free(&mut ctx.accumulator);
        mbedtls_sha512_init(&mut ctx.accumulator);
        ret = mbedtls_sha512_starts_ret(&mut ctx.accumulator, 0);
        if ret != 0 {
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }
        ret = mbedtls_sha512_update_ret(&mut ctx.accumulator, buf, MBEDTLS_ENTROPY_BLOCK_SIZE);
        if ret != 0 {
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }
        ret = mbedtls_sha512_ret(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, buf, 0);
        if ret != 0 {
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }
    }
    else {

        ret = mbedtls_sha256_finish_ret(&mut ctx.accumulator, buf);
        if ret != 0 {
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }

        mbedtls_sha256_free(&mut ctx.accumulator);
        mbedtls_sha256_init(&mut ctx.accumulator);
        ret = mbedtls_sha256_starts_ret(&mut ctx.accumulator, 0);

        if ret != 0 {
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }

        ret = mbedtls_sha256_update_ret(&mut ctx.accumulator, buf, MBEDTLS_ENTROPY_BLOCK_SIZE);

        if ret != 0 {
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }

        ret = mbedtls_sha256_ret(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, buf, 0);

        if ret != 0 {
            return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
        }

    }

    for i in 0..ctx.source_count {
        ctx.source[i].size = 0;
    }

    for i in 0..len {
        output[i] = buf[i];
    }

    ret = 0;
    return entropy_exit(buf, MBEDTLS_ENTROPY_BLOCK_SIZE, ret, ctx);
}

#[cfg(feature="MBEDTLS_ENTROPY_NV_SEED")]
fn mbedtls_entropy_update_nv_seed(ctx: &mutmbedtls_entropy_context) -> i32{

    let mut ret: i32 = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    let mut buf: [u8, MBEDTLS_ENTROPY_BLOCK_SIZE];

    ret = mbedtls_entropy_func(ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE);
    if ret != 0 {
        return ret;
    }

    if mbedtls_nv_seed_write(buf, MBEDTLS_ENTROPY_BLOCK_SIZE) < 0 {
        return MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    }

    for i in &mut buf { *i = 0 }
    ret = mbedtls_entropy_update_manual(ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE);

    return ret;
}

#if defined(MBEDTLS_FS_IO)
int mbedtls_entropy_write_seed_file( mbedtls_entropy_context *ctx, const char *path )
{
    int ret = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    FILE *f;
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];

    if( ( f = fopen( path, "wb" ) ) == NULL )
        return( MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR );

    if( ( ret = mbedtls_entropy_func( ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE ) ) != 0 )
        goto exit;

    if( fwrite( buf, 1, MBEDTLS_ENTROPY_BLOCK_SIZE, f ) != MBEDTLS_ENTROPY_BLOCK_SIZE )
    {
        ret = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
        goto exit;
    }

    ret = 0;

exit:
    mbedtls_platform_zeroize( buf, sizeof( buf ) );

    fclose( f );
    return( ret );
}




fn mbedtls_entropy_update_seed_file(ctx: &mut mbedtls_entropy_context, path: [i8]) -> i32 {

    let mut ret: i32 = 0;
    let mut f = File::open(path).expect("Can't open file");
    let mut n: usize = Default::default();
    let mut buf: [u8; MBEDTLS_ENTROPY_MAX_SEED_SIZE] = Default::default();

    if f == None {
        return MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    }

    f.seek(SeekFrom::Start()).expect("Unable to seek to 40 bytes");

}

use std::fs;

#[cfg(feature="MBEDTLS_FS_IO")]
fn mbedtls_entropy_write_seed_file(ctx: &mut mbedtls_entropy_context, path: i8) -> i32 {

    let mut ret: i32 = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    let mut buf: [u8, MBEDTLS_ENTROPY_BLOCK_SIZE];
    let mut f = fs::File::open(path)?;

    if f == NULL {
        return MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    }

    ret = mbedtls_entropy_func(ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE);

    if ret == 0 {

        if fwrite(buf, 1, MBEDTLS_ENTROPY_BLOCK_SIZE, f) != MBEDTLS_ENTROPY_BLOCK_SIZE {
            ret = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
        }
        else{
            ret = 0;
        }
    }

    mbedtls_platform_zeroize(buf, MBEDTLS_ENTROPY_BLOCK_SIZE);

    fclose(f);
    return ret;
}

fn mbedtls_entropy_update_seed_file(ctx: &mut mbedtls_entropy_context, path: i8) -> i32 {

    let mut ret: i32 = 0;
    let mut buf: [u8, MBEDTLS_ENTROPY_MAX_SEED_SIZE];
    let mut f = fs::File::open(path)?;
    let mut n: usize;

    if f == NULL
        return MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;

    n = f.metadata().unwrap().len();
    f.seek(SeekFrom::Start(0))?;

    if n > MBEDTLS_ENTROPY_MAX_SEED_SIZE
        n = MBEDTLS_ENTROPY_MAX_SEED_SIZE;

    let contents = fs::read_to_string(filename)?;

    if contents.len() != n
        ret = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    else
        ret = mbedtls_entropy_update_manual(ctx, buf, n);

    fclose(f);

    mbedtls_platform_zeroize(buf, MBEDTLS_ENTROPY_MAX_SEED_SIZE);

    if ret != 0
        return ret;

    return mbedtls_entropy_write_seed_file(ctx, path);
}


fn entropy_dummy_source(output: &mut [u8], len: usize, olen: &mut usize) -> i32 {

    for i in 0..len {
        output[i] = 0x2a;
    }
    *olen = len;

    return 0;
}

fn mbedtls_entropy_source_self_test_gather(buf: &mut [u8], buf_len: usize) -> i32 {

    let mut ret: i32 = 0;
    let mut entropy_len: usize = 0;
    let mut olen: usize = 0;
    let mut attempts: usize = buf_len;

    while (attempts > 0) && (entropy_len < buf_len) {
        if (ret = mbedtls_hardware_poll(None, buf + entropy_len, buf_len - entropy_len, &olen) != 0) {
            return ret;
        }
        entropy_len += olen;
        attempts -= 1;
    }

    if entropy_len < buf_len {
        ret = 1;
    }

    return ret;
}

fn mbedtls_entropy_source_self_test_check_bits(buf: &mut [u8], buf_len: usize) -> bool {

    let mut set: u8 = 0xFF;
    let mut unset: u8 = 0x00;
    let mut i: usize = Default::default();;

    for i in 0..buf_len {
        set &= buf[i];
        unset |= buf[i];
    }

    return (set == 0xFF || unset == 0x00);
}



fn mbedtls_entropy_source_self_test(verbose: i32) -> bool {

    let mut ret: i32 = 0;

    const size_of_buf: usize = 2 * mem::size_of::<u32>();

    let mut buf0: [i8; size_of_buf] = Default::default();
    let mut buf1: [i8; size_of_buf] = Default::default();

    if verbose != 0 {
        println!("  ENTROPY_BIAS test: ");
    }

    unsafe {
        for i in &mut buf0 { *i = 0x00 }
        for i in &mut buf1 { *i = 0x00 }
    }

    if ret = mbedtls_entropy_source_self_test_gather( buf0, size_of_buf ) == 0 {
        if ret = mbedtls_entropy_source_self_test_gather( buf1, size_of_buf ) == 0 {
            if ret = mbedtls_entropy_source_self_test_check_bits( buf0, size_of_buf ) == 0 {
                if ret = mbedtls_entropy_source_self_test_check_bits( buf1, size_of_buf ) == 0 {

                    for i in 0..size_of_buf {
                        if buf0[i] != buf1[i] {
                            ret = 1;
                            break;
                        }
                    }
                }
            }
        }
    }

    if verbose != 0 {
        if ret != 0 {
            println!("failed");
        }
        else {
            println!("passed");
        }
        println!();
    }

    return ret != 0;
}


fn self_test_cleanup(verbose: i32) -> bool {

    if verbose != 0 {

        if ret != 0
            mbedtls_printf( "failed\n" );
        else
            mbedtls_printf( "passed\n" );

        mbedtls_printf( "\n" );
    }

    return ret != 0;
}


fn mbedtls_entropy_self_test(verbose: i32) -> bool {

    let mut ret: i32 = 1;

    if #[cfg(not(feature="MBEDTLS_TEST_NULL_ENTROPY"))] {
        let mut ctx: mbedtls_entropy_context;
        let mut buf: [u8, MBEDTLS_ENTROPY_BLOCK_SIZE];
        let mut acc: [u8, MBEDTLS_ENTROPY_BLOCK_SIZE];
    }

    if verbose != 0 {
        mbedtls_printf("ENTROPY test: ");
    }

    if #[cfg(not(feature="MBEDTLS_TEST_NULL_ENTROPY"))] {

        mbedtls_entropy_init(&mut ctx);

        ret = mbedtls_entropy_gather(&mut ctx);

        if ret != 0 {
            mbedtls_entropy_free(&mut ctx);
            return self_test_cleanup(verbose, ret);
        }

        ret = mbedtls_entropy_add_source(&mut ctx, entropy_dummy_source, NULL, 16, MBEDTLS_ENTROPY_SOURCE_WEAK);

        if ret != 0 {
            mbedtls_entropy_free(&mut ctx);
            return self_test_cleanup(verbose, ret);
        }

        ret = mbedtls_entropy_update_manual(&mut ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE);

        if ret != 0 {
            mbedtls_entropy_free(&mut ctx);
            return self_test_cleanup(verbose, ret);
        }

        for i in 0..8 {

            ret = mbedtls_entropy_func(&mut ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE);

            if ret != 0 {
                mbedtls_entropy_free(&mut ctx);
                return self_test_cleanup(verbose, ret);
            }

            for j in 0..MBEDTLS_ENTROPY_BLOCK_SIZE {
                acc[j] |= buf[j];
            }
        }

        for j in 0..MBEDTLS_ENTROPY_BLOCK_SIZE {
            if acc[j] == 0 {
                ret = 1;
                mbedtls_entropy_free(&mut ctx);
                return self_test_cleanup(verbose, ret);
            }
        }

        if #[cfg(feature="MBEDTLS_ENTROPY_HARDWARE_ALT")] {
            ret = mbedtls_entropy_source_self_test(0);
            if ret != 0 {
                mbedtls_entropy_free(&mut ctx);
                return self_test_cleanup(verbose, ret);
            }
        }

        mbedtls_entropy_free(&mut ctx);
    }

    return self_test_cleanup(verbose, ret);
}
