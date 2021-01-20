use std::mem;


fn mbedtls_ctr_drbg_init(ctx: &mut mbedtls_ctr_drbg_context) -> ()
{
    let siz: usize = mem::size_of::<mbedtls_ctr_drbg_context>()
    
    for i in &mut ctx { *i = 0 }
    
    /* Indicate that the entropy nonce length is not set explicitly.
     * See mbedtls_ctr_drbg_set_nonce_len(). */
    (*ctx).reseed_counter = -1;
    
    (*ctx).reseed_interval = MBEDTLS_CTR_DRBG_RESEED_INTERVAL;
    
}


fn mbedtls_ctr_drbg_set_prediction_resistance(ctx: &mut [mbedtls_ctr_drbg_context], resistance: i32)
{
    (*ctx).prediction_resistance = resistance;
}



fn mbedtls_ctr_drbg_set_entropy_len(ctx: &mut [mbedtls_ctr_drbg_context], len:usize ) -> ()
{
    (*ctx).entropy_len = len;
}


fn mbedtls_ctr_drbg_set_nonce_len(ctx: &mut [mbedtls_ctr_drbg_context], len: usize) -> i32
{
    /* If mbedtls_ctr_drbg_seed() has already been called, it's
     * too late. Return the error code that's closest to making sense. */
    if (*ctx).f_entropy != NONE 
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED ;
        
    if len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG ;
        
        
    /* This shouldn't be an issue because
     * MBEDTLS_CTR_DRBG_MAX_SEED_INPUT < INT_MAX in any sensible
     * configuration, but make sure anyway. */
    if len > std::u32::MAX
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
        
        
    /* For backward compatibility with Mbed TLS <= 2.19, store the
     * entropy nonce length in a field that already exists, but isn't
     * used until after the initial seeding. */
    /* Due to the capping of len above, the value fits in an int. */
    (*ctx).reseed_counter = len as i32;
    return 0 ;
}


fn mbedtls_ctr_drbg_set_reseed_interval(ctx: &mut [mbedtls_ctr_drbg_context], interval:i32) -> ()
{
    (*ctx).reseed_interval = interval;
}


fn fun_exit(buf: &mut [u8], tmp: &mut [u8], key: &mut [u8], chain: &mut [u8], ret: u8, output: &mut [u8], aes_ctx: &mut mbedtls_aes_context) ->i32 {
    mbedtls_aes_free( &aes_ctx );
    /*
    * tidy up the stack
    */
    mbedtls_platform_zeroize( buf, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT + MBEDTLS_CTR_DRBG_BLOCKSIZE + 16 );
    mbedtls_platform_zeroize( tmp, MBEDTLS_CTR_DRBG_SEEDLEN );
    mbedtls_platform_zeroize( key, MBEDTLS_CTR_DRBG_KEYSIZE );
    mbedtls_platform_zeroize( chain, MBEDTLS_CTR_DRBG_BLOCKSIZE );
    if( 0 != ret )
    {
        /*
        * wipe partial seed from memory
        */
        mbedtls_platform_zeroize( output, MBEDTLS_CTR_DRBG_SEEDLEN );
    }

    return ret ;
}


//line 130 static funtion
fn block_cipher_df(output: &mut u8 /*unsigned char *output*/, data: & u8 /*const unsigned char *data*/, data_len:usize ) -> i32
{
    let mut buf: [u8, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT + MBEDTLS_CTR_DRBG_BLOCKSIZE + 16];
    let mut tmp: [u8, MBEDTLS_CTR_DRBG_SEEDLEN];
    let mut key: [u8, MBEDTLS_CTR_DRBG_KEYSIZE];
    let mut chain: [u8, MBEDTLS_CTR_DRBG_BLOCKSIZE];
    //unsigned char *p, *iv;
    let mut p: &u8;
    let mut iv: &u8;
    let mut aes_ctx: mbedtls_aes_context;
    let mut ret: u8;
    ret =0;
    
    let mut i;
    let mut j;
    buf_len:usize;
    use_len:usize;
    
    if data_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT 
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG ;

    // memset( buf, 0, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT + MBEDTLS_CTR_DRBG_BLOCKSIZE + 16 );
    //mbedtls_aes_init( &aes_ctx );
    
    p = buf + MBEDTLS_CTR_DRBG_BLOCKSIZE;
    *p = ( data_len >> 24 ) & 0xff;
    p += 1;
    *p = ( data_len >> 16 ) & 0xff;
    p += 1;
    *p++ = ( data_len >> 8  ) & 0xff;
    p += 1;
    *p++ = ( data_len       ) & 0xff;
    p += 3;
    *p = MBEDTLS_CTR_DRBG_SEEDLEN;
    p += 1;
    
    //memcpy( p, data, data_len );
    
    p[data_len] = 0x80;

    buf_len = MBEDTLS_CTR_DRBG_BLOCKSIZE + 8 + data_len + 1;

    for i in 0..MBEDTLS_CTR_DRBG_KEYSIZE{
        key[i] = i;
    }

    if ( ret = mbedtls_aes_setkey_enc( &aes_ctx, key, MBEDTLS_CTR_DRBG_KEYBITS ) ) != 0 {
        ret = fun_exit(&mut buf, &mut tmp, &mut key, &mut chain, &mut aes_ctx, &mut ret, &mut output, &mut aes_ctx);
        return ret;
    }
    
    
    for j in 0..MBEDTLS_CTR_DRBG_SEEDLEN{
        j += MBEDTLS_CTR_DRBG_BLOCKSIZE - 1;
        p = buf;
        
        //memset( chain, 0, MBEDTLS_CTR_DRBG_BLOCKSIZE );
        
        use_len = buf_len;

        while use_len > 0 {
            for i in 0..MBEDTLS_CTR_DRBG_BLOCKSIZE{
                chain[i] ^= p[i];
            }
            p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
            use_len -= if use_len >= MBEDTLS_CTR_DRBG_BLOCKSIZE { MBEDTLS_CTR_DRBG_BLOCKSIZE } else { use_len };

            if ( ret = mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, chain, chain ) ) != 0 {
                ret = fun_exit(&mut buf, &mut tmp, &mut key, &mut chain, &mut aes_ctx, &mut ret, &mut output, &mut aes_ctx);
                return ret;
            }
        }

        //memcpy( tmp + j, chain, MBEDTLS_CTR_DRBG_BLOCKSIZE );

        /*
         * Update IV
         */
        buf[3] += 1;
    }
    
    
    if ( ret = mbedtls_aes_setkey_enc( &aes_ctx, tmp, MBEDTLS_CTR_DRBG_KEYBITS ) ) != 0 {
        ret = fun_exit(&mut buf, &mut tmp, &mut key, &mut chain, &mut aes_ctx, &mut ret, &mut output, &mut aes_ctx);
        return ret;
    }
    iv = tmp + MBEDTLS_CTR_DRBG_KEYSIZE;
    p = output;

    for j in 0..MBEDTLS_CTR_DRBG_SEEDLEN{
        j += MBEDTLS_CTR_DRBG_BLOCKSIZE - 1;
        if ( ret = mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, iv, iv ) ) != 0 {
            ret = fun_exit(&mut buf, &mut tmp, &mut key, &mut chain, &mut aes_ctx, &mut ret, &mut output, &mut aes_ctx);
            return ret;
        }
        
        //memcpy( p, iv, MBEDTLS_CTR_DRBG_BLOCKSIZE );
        
        p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
    }
    
    ret = fun_exit(&mut buf, &mut tmp, &mut key, &mut chain, &mut aes_ctx, &mut ret, &mut output, &mut aes_ctx);
    
    return ret;
    
}
    

    
fn func_exit(tmp: &mut [u8], tmp_size: &mut usize, ret: i32) -> i32{
    mbedtls_platform_zeroize( tmp, tmp_size ) );
    return ret ;    
}
    
//line 261 static func
fn ctr_drbg_update_internal( ctx: &mut mbedtls_ctr_drbg_context, data: & [u8, MBEDTLS_CTR_DRBG_SEEDLEN] ) -> i32
{
    let mut tmp: [u8, MBEDTLS_CTR_DRBG_SEEDLEN];
    let &mut p: u8 = tmp;
    let mut i, j;
    let mut ret: i32 = 0;
    
    //memset( tmp, 0, MBEDTLS_CTR_DRBG_SEEDLEN );

    for j in 0..MBEDTLS_CTR_DRBG_SEEDLEN{
        j += MBEDTLS_CTR_DRBG_BLOCKSIZE - 1;
        /*
         * Increase counter
         */
        i = MBEDTLS_CTR_DRBG_BLOCKSIZE
        while i>0{
            ctx += 1 ;
            if (*ctx).counter[i - 1] != 0{
                break;
            }
            i -= 1;
        }
        /*
         * Crypt counter block
         */
        if ( ret = mbedtls_aes_crypt_ecb( &mut ctx.aes_ctx, MBEDTLS_AES_ENCRYPT, (*ctx).counter, p ) ) != 0 {
            ret = func_exit(&mut tmp, &mut MBEDTLS_CTR_DRBG_SEEDLEN, ret);
            return ret;
        }

        p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
    }
    
    for i in 0..MBEDTLS_CTR_DRBG_SEEDLEN{
        tmp[i] ^= data[i];
    }

    /*
     * Update key and counter
     */
    if ( ret = mbedtls_aes_setkey_enc( &mut ctx.aes_ctx, tmp, MBEDTLS_CTR_DRBG_KEYBITS ) ) != 0 {
        ret = func_exit(&mut tmp, &mut MBEDTLS_CTR_DRBG_SEEDLEN, ret);
        return ret;
    }
    
    //memcpy( ctx->counter, tmp + MBEDTLS_CTR_DRBG_KEYSIZE, MBEDTLS_CTR_DRBG_BLOCKSIZE );
    
    ret = func_exit(&mut tmp, &mut MBEDTLS_CTR_DRBG_SEEDLEN, ret);
    return ret;

}
    

fn funct_exit( add_input: &mut [u8], add_input_size: usize, ret: i32 ) -> i32{
    mbedtls_platform_zeroize(add_input, add_input_size );
    return ret ;
}

//line 323
fn mbedtls_ctr_drbg_update_ret( ctx: &mut mbedtls_ctr_drbg_context, additional: &u8, add_len: usize ) -> i32{
    let mut add_input: [u8, MBEDTLS_CTR_DRBG_SEEDLEN];
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if add_len == 0 {
        return 0 ;
    }

    if ( ret = block_cipher_df( add_input, additional, add_len ) ) != 0 {
        ret = func_exit(add_input: &mut [u8], add_input_size: usize, ret: i32 );
        return ret ;
    }
    if ( ret = ctr_drbg_update_internal( ctx, add_input ) ) != 0 {
        ret = func_exit(add_input: &mut [u8], add_input_size: usize, ret: i32 );
        return ret ;
    }

    ret = func_exit(add_input: &mut [u8], add_input_size: usize, ret: i32 );
    return ret ;
}
    
    
//line 343    
fn mbedtls_ctr_drbg_update( ctx: &mut mbedtls_ctr_drbg_context , additional : &u8, add_len: usize) -> (){
    /* MAX_INPUT would be more logical here, but we have to match
     * block_cipher_df()'s limits since we can't propagate errors */
    if add_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT {
        add_len = MBEDTLS_CTR_DRBG_MAX_SEED_INPUT;
    }
    mbedtls_ctr_drbg_update_ret( ctx, additional, add_len ) as ();
}


fn functi_exit(seed: &mut [u8], seed_size: usize, ret: i32) -> i32{
    mbedtls_platform_zeroize( seed, seed_size );
    return ret ;
}

//line 369 static function
fn mbedtls_ctr_drbg_reseed_internal( ctx: &mut mbedtls_ctr_drbg_context , additional: &u8 , len: usize, nonce_len: usize ) -> i32{
    let mut seed: [u8, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT];
    let mut seedlen: usize = 0;
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*ctx).entropy_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG ;
    }
    if nonce_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - (*ctx).entropy_len {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG ;
    }
    if len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - (*ctx).entropy_len - nonce_len {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG ;
    }

    //memset( seed, 0, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT );

    /* Gather entropy_len bytes of entropy to seed state. */
    if 0 != (*ctx).f_entropy( (*ctx).p_entropy, seed, (*ctx).entropy_len ) {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED ;
    }
    seedlen += (*ctx).entropy_len;

    /* Gather entropy for a nonce if requested. */
    if nonce_len != 0 {
        if 0 != (*ctx).f_entropy( (*ctx).p_entropy, seed, nonce_len ) {
            return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED ;
        }
        seedlen += nonce_len;
    }

    /* Add additional data if provided. */
    if additional != NULL && len != 0 {
        
        //memcpy( seed + seedlen, additional, len );
        
        seedlen += len;
    }

    /* Reduce to 384 bits. */
    if ( ret = block_cipher_df( seed, seed, seedlen ) ) != 0 {
        ret = functi_exit(seed, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT, ret);
        return ret;
    }

    /* Update state. */
    if ( ret = ctr_drbg_update_internal( ctx, seed ) ) != 0 {
        ret = functi_exit(seed, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT, ret);
        return ret;
    }
    (*ctx).reseed_counter = 1;

    ret = functi_exit(seed, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT, ret);
    return ret;
}


//line 425
fn mbedtls_ctr_drbg_reseed( ctx: &mut mbedtls_ctr_drbg_context , additional: &u8, len: usize ) -> i32{
    return mbedtls_ctr_drbg_reseed_internal( ctx, additional, len, 0 ) ;
}
  
    
//line 436 static ffunction
fn good_nonce_len( size_t entropy_len ) -> usize{
    if entropy_len >= MBEDTLS_CTR_DRBG_KEYSIZE * 3 / 2 {
        return 0 ;
    }
    else{
        return ( entropy_len + 1 ) / 2 ;
    }
}


//line 455 function pointer
fn mbedtls_ctr_drbg_seed( ctx: &mut mbedtls_ctr_drbg_context , int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy, custom: & u8, len: usize ) -> i32{
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut key: [u8, MBEDTLS_CTR_DRBG_KEYSIZE];
    let mut nonce_len: usize;

    //memset( key, 0, MBEDTLS_CTR_DRBG_KEYSIZE );

    mbedtls_aes_init( &mut ctx.aes_ctx );

    (*ctx).f_entropy = f_entropy;
    (*ctx).p_entropy = p_entropy;

    if (*ctx).entropy_len == 0 {
        ctx->entropy_len = MBEDTLS_CTR_DRBG_ENTROPY_LEN;
    }
    /* ctx->reseed_counter contains the desired amount of entropy to
     * grab for a nonce (see mbedtls_ctr_drbg_set_nonce_len()).
     * If it's -1, indicating that the entropy nonce length was not set
     * explicitly, use a sufficiently large nonce for security. */

    nonce_len = if (*ctx).reseed_counter >= 0 { (size_t) (*ctx).reseed_counter } else {good_nonce_len( (*ctx).entropy_len ) };

    /* Initialize with an empty key. */
    if ( ret = mbedtls_aes_setkey_enc( &mut ctx.aes_ctx, key, MBEDTLS_CTR_DRBG_KEYBITS ) ) != 0 {
        return ret ;
    }

    /* Do the initial seeding. */
    if ( ret = mbedtls_ctr_drbg_reseed_internal( ctx, custom, len, nonce_len ) ) != 0 {
        return ret ;
    }
    return 0 ;
}


fn funtio_exit(add_input: &mut [u8], add_input_size: usize, ret: i32, tmp: &mut [u8], tmp_size: usize) -> i32 {
    mbedtls_platform_zeroize( add_input, add_input_size ); // MBEDTLS_CTR_DRBG_SEEDLEN
    mbedtls_platform_zeroize( tmp, tmp_size ); // MBEDTLS_CTR_DRBG_BLOCKSIZE
    return ret ;
}

// line 517
fn mbedtls_ctr_drbg_random_with_add( void *p_rng, output: &u8, output_len: usize, additional: &u8, add_len: usize ){
    let mut ret:u8 = 0;
    let &mut ctx: mbedtls_ctr_drbg_context = (mbedtls_ctr_drbg_context *) p_rng;
    let mut add_input: [u8, MBEDTLS_CTR_DRBG_SEEDLEN];
    let &mut p:u8 = output;
    let mut tmp: [u8, MBEDTLS_CTR_DRBG_BLOCKSIZE];
    let mut i: i32;
    let mut use_len: usize;

    if output_len > MBEDTLS_CTR_DRBG_MAX_REQUEST {
        return MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG ;
    }

    if add_len > MBEDTLS_CTR_DRBG_MAX_INPUT {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG ;
    }

    // memset( add_input, 0, MBEDTLS_CTR_DRBG_SEEDLEN );

    if (*ctx).reseed_counter > (*ctx).reseed_interval || (*ctx).prediction_resistance {
        if ( ret = mbedtls_ctr_drbg_reseed( ctx, additional, add_len ) ) != 0 {
            return ret ;
        }
        add_len = 0;
    }

    if add_len > 0 {
        if ( ret = block_cipher_df( add_input, additional, add_len ) ) != 0 {
            ret = funtio_exit(add_input, MBEDTLS_CTR_DRBG_SEEDLEN, tmp, MBEDTLS_CTR_DRBG_BLOCKSIZE, ret);
            return ret;
        }
        if ( ret = ctr_drbg_update_internal( ctx, add_input ) ) != 0 {
            ret = funtio_exit(add_input, MBEDTLS_CTR_DRBG_SEEDLEN, tmp, MBEDTLS_CTR_DRBG_BLOCKSIZE, ret);
            return ret;
        }
    }

    while output_len > 0 {
        /*
         * Increase counter
         */
        i = MBEDTLS_CTR_DRBG_BLOCKSIZE
        while i > 0 {
            if ++(*(ctx).counter)[i - 1] != 0 {
                break;
            }
            i -= 1 ;
        }

        /*
         * Crypt counter block
         */
        if ( ret = mbedtls_aes_crypt_ecb( &mut ctx.aes_ctx, MBEDTLS_AES_ENCRYPT, (*ctx).counter, tmp ) ) != 0  {
            ret = funtio_exit(add_input, MBEDTLS_CTR_DRBG_SEEDLEN, tmp, MBEDTLS_CTR_DRBG_BLOCKSIZE, ret);
            return ret;
        }

        use_len = if output_len > MBEDTLS_CTR_DRBG_BLOCKSIZE { MBEDTLS_CTR_DRBG_BLOCKSIZE } else { output_len };
        /*
         * Copy random block to destination
         */
        
        // memcpy( p, tmp, use_len );
        
        p += use_len;
        output_len -= use_len;
    }

    if ( ret = ctr_drbg_update_internal( ctx, add_input ) ) != 0 {
        ret = funtio_exit(add_input, MBEDTLS_CTR_DRBG_SEEDLEN, tmp, MBEDTLS_CTR_DRBG_BLOCKSIZE, ret);
        return ret;
    }

    (*ctx).reseed_counter += 1; //doubt

    ret = funtio_exit(add_input, MBEDTLS_CTR_DRBG_SEEDLEN, tmp, MBEDTLS_CTR_DRBG_BLOCKSIZE, ret);
    return ret;

}


// line 594
fn mbedtls_ctr_drbg_random( void *p_rng, output: & u8, output_len: usize ) -> i32 {
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let &mut ctx: mbedtls_ctr_drbg_context = (mbedtls_ctr_drbg_context *) p_rng; // doubt

    if ( ret = mbedtls_mutex_lock( &mut ctx.mutex ) ) != 0 {
        return ret ;
    }

    ret = mbedtls_ctr_drbg_random_with_add( ctx, output, output_len, NULL, 0 );

    if mbedtls_mutex_unlock( &mut ctx.mutex ) != 0 {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR ;
    }

    return ret ;
}


fn function_exit(buf: &mut [u8], buf_size: usize, ret: i32){
    mbedtls_platform_zeroize( buf, buf_size ) );

    fclose( f );
    return ret ;
}

// line 615
fn mbedtls_ctr_drbg_write_seed_file( ctx: &mut mbedtls_ctr_drbg_context , path: & u8 ) -> i32 {
    let mut ret: i32 = MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
    FILE *f;
    let mut buf: [u8, MBEDTLS_CTR_DRBG_MAX_INPUT ];

    if ( f = fopen( path, "wb" ) ) == NULL {
        return( MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR );
    }
    
    if ( ret = mbedtls_ctr_drbg_random( ctx, buf, MBEDTLS_CTR_DRBG_MAX_INPUT ) ) != 0 {
        ret = function_exit(buf, MBEDTLS_CTR_DRBG_MAX_INPUT , ret);
        return ret;
    }

    if fwrite( buf, 1, MBEDTLS_CTR_DRBG_MAX_INPUT, f ) != MBEDTLS_CTR_DRBG_MAX_INPUT {
        ret = MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
    }
    else{
        ret = 0;
    }
    
    ret = function_exit(buf, MBEDTLS_CTR_DRBG_MAX_INPUT , ret);
    return ret;
}


fn function_exi(buf: &mut [u8], buf_size: usize, ctx: &mut mbedtls_ctr_drbg_context, path: &u8) -> i32 { // doubt
    mbedtls_platform_zeroize( buf, buf_size );
    if f != NULL {
        fclose f ;
    }
    if ret != 0 {
        return ret ;
    }
    return mbedtls_ctr_drbg_write_seed_file( ctx, path );
}

// line 647 file return 
fn mbedtls_ctr_drbg_update_seed_file( ctx: &mut mbedtls_ctr_drbg_context, path: &u8 ) ->i32 {
    let mut ret: i32 = 0;
    FILE *f = NULL; // doubt
    let mut n: usize;
    let mut buf[u8, MBEDTLS_CTR_DRBG_MAX_INPUT ];
    let mut c: u8;

    let mut tmp: i32;
    
    if ( f = fopen( path, "rb" ) ) == NULL {
        return MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR ;
    }
    
    n = fread( buf, 1, sizeof( buf ), f );
    if fread( &c, 1, 1, f ) != 0 {
        ret = MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
        tmp = function_exi(buf, MBEDTLS_CTR_DRBG_MAX_INPUT, ctx, path);
        return tmp;
    }
    if n == 0 || ferror( f ) {
        ret = MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
        tmp = function_exi(buf, MBEDTLS_CTR_DRBG_MAX_INPUT, ctx, path);
        return tmp;
    }
    fclose( f );
    f = NULL;

    ret = mbedtls_ctr_drbg_update_ret( ctx, buf, n );
    
    tmp = function_exi(buf, MBEDTLS_CTR_DRBG_MAX_INPUT, ctx, path);
    return tmp;

/*exit:
    mbedtls_platform_zeroize( buf, sizeof( buf ) );
    if( f != NULL )
        fclose( f );
    if( ret != 0 )
        return( ret );
    return( mbedtls_ctr_drbg_write_seed_file( ctx, path ) );*/
}


// line 687
pub const entropy_source_pr:[u8;96]=[
      0xc1, 0x80, 0x81, 0xa6, 0x5d, 0x44, 0x02, 0x16,
      0x19, 0xb3, 0xf1, 0x80, 0xb1, 0xc9, 0x20, 0x02,
      0x6a, 0x54, 0x6f, 0x0c, 0x70, 0x81, 0x49, 0x8b,
      0x6e, 0xa6, 0x62, 0x52, 0x6d, 0x51, 0xb1, 0xcb,
      0x58, 0x3b, 0xfa, 0xd5, 0x37, 0x5f, 0xfb, 0xc9,
      0xff, 0x46, 0xd2, 0x19, 0xc7, 0x22, 0x3e, 0x95,
      0x45, 0x9d, 0x82, 0xe1, 0xe7, 0x22, 0x9f, 0x63,
      0x31, 0x69, 0xd2, 0x6b, 0x57, 0x47, 0x4f, 0xa3,
      0x37, 0xc9, 0x98, 0x1c, 0x0b, 0xfb, 0x91, 0x31,
      0x4d, 0x55, 0xb9, 0xe9, 0x1c, 0x5a, 0x5e, 0xe4,
      0x93, 0x92, 0xcf, 0xc5, 0x23, 0x12, 0xd5, 0x56,
      0x2c, 0x4a, 0x6e, 0xff, 0xdc, 0x10, 0xd0, 0x68 ];

pub const entropy_source_nopr:[u8;64]=[
      0x5a, 0x19, 0x4d, 0x5e, 0x2b, 0x31, 0x58, 0x14,
      0x54, 0xde, 0xf6, 0x75, 0xfb, 0x79, 0x58, 0xfe,
      0xc7, 0xdb, 0x87, 0x3e, 0x56, 0x89, 0xfc, 0x9d,
      0x03, 0x21, 0x7c, 0x68, 0xd8, 0x03, 0x38, 0x20,
      0xf9, 0xe6, 0x5e, 0x04, 0xd8, 0x56, 0xf3, 0xa9,
      0xc4, 0x4a, 0x4c, 0xbd, 0xc1, 0xd0, 0x08, 0x46,
      0xf5, 0x98, 0x3d, 0x77, 0x1c, 0x1b, 0x13, 0x7e,
      0x4e, 0x0f, 0x9d, 0x8e, 0xf4, 0x09, 0xf9, 0x2e ];

pub const nonce_pers_pr:[u8;16]=[
      0xd2, 0x54, 0xfc, 0xff, 0x02, 0x1e, 0x69, 0xd2,
      0x29, 0xc9, 0xcf, 0xad, 0x85, 0xfa, 0x48, 0x6c ];

pub const nonce_pers_nopr:[u8;16]=[
      0x1b, 0x54, 0xb8, 0xff, 0x06, 0x42, 0xbf, 0xf5,
      0x21, 0xf1, 0x5c, 0x1c, 0x0b, 0x66, 0x5f, 0x3f ];

//#if defined(MBEDTLS_CTR_DRBG_USE_128_BIT_KEY)
pub const result_pr:[u8;16]=[
      0x95, 0x3c, 0xa5, 0xbd, 0x44, 0x1, 0x34, 0xb7,
      0x13, 0x58, 0x3e, 0x6a, 0x6c, 0x7e, 0x88, 0x8a ];

pub const result_nopr:[u8;16]=[
      0x6c, 0x25, 0x27, 0x95, 0xa3, 0x62, 0xd6, 0xdb,
      0x90, 0xfd, 0x69, 0xb5, 0x42, 0x9, 0x4b, 0x84 ];
    
//#else    // MBEDTLS_CTR_DRBG_USE_128_BIT_KEY 
pub const result_pr:[u8;16]=[
      0x34, 0x01, 0x16, 0x56, 0xb4, 0x29, 0x00, 0x8f,
      0x35, 0x63, 0xec, 0xb5, 0xf2, 0x59, 0x07, 0x23 ];

pub const result_nopr:[u8;16]=[
      0xa0, 0x54, 0x30, 0x3d, 0x8a, 0x7e, 0xa9, 0x88,
      0x9d, 0x90, 0x3e, 0x07, 0x7c, 0x6f, 0x21, 0x8f ];

// line 737 both static
let mut test_offset: usize;
fn ctr_drbg_self_test_entropy( void *data, buf: &u8, len: usize ) -> i32{
    let p:&u8 = data; //const unsigned char *p = data;
    
    // memcpy( buf, p + test_offset, len );
    
    test_offset += len;
    return 0 ;
}


//line 747
#define CHK( c )    if( (c) != 0 )                          \
                    {                                       \
                        if( verbose != 0 )                  \
                            mbedtls_printf( "failed\n" );  \
                        return( 1 );                        \
                    }

/*
 * Checkup routine
 */


// line 757
fn mbedtls_ctr_drbg_self_test( verbose: i32 ) -> i32 {
    let mut ctx: mbedtls_ctr_drbg_context;
    let mut buf: [u8, 16];

    mbedtls_ctr_drbg_init( &ctx );

    /*
     * Based on a NIST CTR_DRBG test vector (PR = True)
     */
    if verbose != 0 {
        mbedtls_printf( "  CTR_DRBG (PR = TRUE) : " );
    }
    
    test_offset = 0;
    mbedtls_ctr_drbg_set_entropy_len( &ctx, 32 );
    mbedtls_ctr_drbg_set_nonce_len( &ctx, 0 );
    CHK( mbedtls_ctr_drbg_seed( &ctx, ctr_drbg_self_test_entropy, (void *) entropy_source_pr, nonce_pers_pr, 16 ) );
    mbedtls_ctr_drbg_set_prediction_resistance( &ctx, MBEDTLS_CTR_DRBG_PR_ON );
    CHK( mbedtls_ctr_drbg_random( &ctx, buf, MBEDTLS_CTR_DRBG_BLOCKSIZE ) );
    CHK( mbedtls_ctr_drbg_random( &ctx, buf, MBEDTLS_CTR_DRBG_BLOCKSIZE ) );
    CHK( memcmp( buf, result_pr, MBEDTLS_CTR_DRBG_BLOCKSIZE ) );

    mbedtls_ctr_drbg_free( &ctx );

    if verbose != 0 {
        mbedtls_printf( "passed\n" );
    }
    /*
     * Based on a NIST CTR_DRBG test vector (PR = FALSE)
     */
    if verbose != 0 {
        mbedtls_printf( "  CTR_DRBG (PR = FALSE): " );
    }
    
    mbedtls_ctr_drbg_init( &ctx );

    test_offset = 0;
    mbedtls_ctr_drbg_set_entropy_len( &ctx, 32 );
    mbedtls_ctr_drbg_set_nonce_len( &ctx, 0 );
    CHK( mbedtls_ctr_drbg_seed( &ctx, ctr_drbg_self_test_entropy, (void *) entropy_source_nopr, nonce_pers_nopr, 16 ) );
    CHK( mbedtls_ctr_drbg_random( &ctx, buf, 16 ) );
    CHK( mbedtls_ctr_drbg_reseed( &ctx, NULL, 0 ) );
    CHK( mbedtls_ctr_drbg_random( &ctx, buf, 16 ) );
    CHK( memcmp( buf, result_nopr, 16 ) );

    mbedtls_ctr_drbg_free( &ctx );

    if verbose != 0 {
        mbedtls_printf( "passed\n" );
    }

    if verbose != 0 {
            mbedtls_printf( "\n" );
    }
    
    return 0 ;
}


