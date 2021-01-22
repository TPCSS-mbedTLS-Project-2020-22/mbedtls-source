/// Diffie-Hellman-Merkle key exchange

#[path = "../bignum_dep/bignum1.rs"] mod bignum1;

#[allow(non_camel_case_types)]
#[allow(dead_code)]

use bignum1::*;
use std::ptr;
use std::mem;
use std::convert::TryInto;

/*
 * DHM Error codes
 */
pub const MBEDTLS_ERR_DHM_BAD_INPUT_DATA:            i32= -0x3080;  // Bad input parameters.
pub const MBEDTLS_ERR_DHM_READ_PARAMS_FAILED:        i32= -0x3100;  // Reading of the DHM parameters failed.
pub const MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED:        i32= -0x3180;  // Making of the DHM parameters failed.
pub const MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED:        i32= -0x3200;  // Reading of the public values failed.
pub const MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED:        i32= -0x3280;  // Making of the public value failed.
pub const MBEDTLS_ERR_DHM_CALC_SECRET_FAILED:        i32= -0x3300;  // Calculation of the DHM secret failed.
pub const MBEDTLS_ERR_DHM_INVALID_FORMAT:            i32= -0x3380;  // The ASN.1 data is not formatted correctly.
pub const MBEDTLS_ERR_DHM_ALLOC_FAILED:              i32= -0x3400;  // Allocation of memory failed.
pub const MBEDTLS_ERR_DHM_FILE_IO_ERROR:             i32= -0x3480;  // Read or write of file failed.
pub const MBEDTLS_ERR_DHM_SET_GROUP_FAILED:          i32= -0x3580; // Setting the modulus and generator failed. */

/// MBEDTLS_ERR_DHM_HW_ACCEL_FAILED is deprecated and should not be used. */
pub const MBEDTLS_ERR_DHM_HW_ACCEL_FAILED:           i32= -0x3500;  //< DHM hardware accelerator failed. */

///implementing copy trait on mbedtls_mpi structure
impl mbedtls_mpi{
    pub fn Copy(&self) -> mbedtls_mpi {
        let x = mbedtls_mpi{s:self.s, n:self.n, p:self.p[..].iter().cloned().collect()};
        return x
    }
}

///error code to be defined in error.h
pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED:     i32= -0x006E;  // This is a bug in the library */

/**
 * \brief          The DHM context structure.
 */
pub struct mbedtls_dhm_context{
    pub len: usize,          //  The size of \p P in Bytes. */
    pub P: mbedtls_mpi,      //*!<  The prime modulus. */
    pub G: mbedtls_mpi,      //*!<  The generator. */
    pub X: mbedtls_mpi,      //*!<  Our secret value. */
    pub GX: mbedtls_mpi,     //*!<  Our public key = \c G^X mod \c P. */
    pub GY: mbedtls_mpi,     //*!<  The public key of the peer = \c G^Y mod \c P. */
    pub K: mbedtls_mpi,      //*!<  The shared secret = \c G^(XY) mod \c P. */
    pub RP: mbedtls_mpi,     //*!<  The cached value = \c R^2 mod \c P. */
    pub Vi: mbedtls_mpi,     //*!<  The blinding value. */
    pub Vf: mbedtls_mpi,     //*!<  The unblinding value. */
    pub pX: mbedtls_mpi,     //*!<  The previous \c X. */
}

macro_rules! post_inc {
    ($i:ident) => { // the macro is callable with any identifier (eg. a variable)
        { // the macro evaluates to a block expression
            let old = $i; // save the old value
            $i += 1; // increment the argument
            old // the value of the block is `old`
        }
    };
}

/*
* helper to validate the mbedtls_mpi size and import it
*/
pub fn dhm_read_bignum(X: &mut mbedtls_mpi,
    p:  &mut &mut u8, 
    end: &mut u8 ) -> i32 
{
    let ret: i32;
    let n: i32;

//created to do pointer airthmetic, as it can be done only on raw pointers
unsafe{let mut ptr: *mut u8 = *p;

    if  *p == end ||  ptr.offset(1) == end
    {
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA
    }

    n = ((*(*p) << 8) | *(ptr.add(1))).into();
    *p = &mut *ptr.add(2);
    ptr = *p;//updated value in ptr to maintain consistency forward

    if ptr.offset(n.try_into().unwrap()) < *p
    {
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA
    }

    ret = mbedtls_mpi_read_binary(X, *p, n.try_into().unwrap());
    if ret != 0
    {
        return MBEDTLS_ERR_DHM_READ_PARAMS_FAILED + ret
    }

    *p = &mut *ptr.offset(n.try_into().unwrap());

    drop(ptr);

    0
    }
}
/*
 * Verify sanity of parameter with regards to P
 *
 * Parameter should be: 2 <= public_param <= P - 2
 *
 * This means that we need to return an error if
 *              public_param < 2 or public_param > P-2
 *
 * For more information on the attack, see:
 *  http://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf
 *  http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-2643
 */
pub fn dhm_check_range(param: &mut mbedtls_mpi, P: &mut mbedtls_mpi)-> i32
{
    let mut L: mbedtls_mpi= mbedtls_mpi{s: 1,n: 0, p: vec![]};
    let mut U: mbedtls_mpi= mbedtls_mpi{s: 1,n: 0, p: vec![]};
    let mut ret: i32;

    ret = mbedtls_mpi_lset(&mut L, 2);
    if ret !=0 {
        return ret
    }

    ret = mbedtls_mpi_sub_int( &mut U, P, 2 );
    if ret !=0 {
        return ret
    }


    if mbedtls_mpi_cmp_mpi(param, &mut U) > 0 || mbedtls_mpi_cmp_mpi(param, &mut L) < 0 {
        
        ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }
    ret
}

/**
 * \brief          This function initializes the DHM context.
 *
 * \param ctx      The DHM context to initialize.
 */
pub fn mbedtls_dhm_init(ctx: &mut mbedtls_dhm_context)
{
    unsafe{ptr::write_bytes(ctx, 0, mem::size_of::<mbedtls_dhm_context>());}
}

/**
 * \brief          This function parses the DHM parameters in a
 *                 TLS ServerKeyExchange handshake message
 *                 (DHM modulus, generator, and public key).
 *
 * \note           In a TLS handshake, this is the how the client
 *                 sets up its DHM context from the server's public
 *                 DHM key material.
 *
 * \param ctx      The DHM context to use. This must be initialized.
 * \param p        On input, *p must be the start of the input buffer.
 *                 On output, *p is updated to point to the end of the data
 *                 that has been read. On success, this is the first byte
 *                 past the end of the ServerKeyExchange parameters.
 *                 On error, this is the point at which an error has been
 *                 detected, which is usually not useful except to debug
 *                 failures.
 * \param end      The end of the input buffer.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
pub fn mbedtls_dhm_read_params( ctx: &mut mbedtls_dhm_context,
                                p: &mut &mut u8,
                                end: &mut u8)->i32
{
    let mut ret: i32;

    ret = dhm_read_bignum(&mut ctx.P, p, end);
    if ret != 0
    {
        return ret
    }
    ret = dhm_read_bignum(&mut ctx.G, p, end);
    if ret != 0
    {
        return ret
    }
    ret = dhm_read_bignum(&mut ctx.GY, p, end);
    if ret != 0
    {
        return ret
    }

    ret = dhm_check_range(&mut ctx.GY, &mut ctx.P);
    if ret != 0
    {
        return ret
    }
    
    ctx.len = mbedtls_mpi_size(&mut ctx.P);

    0
}

/**
 * \brief          This function generates a DHM key pair and exports its
 *                 public part together with the DHM parameters in the format
 *                 used in a TLS ServerKeyExchange handshake message.
 *
 * \note           This function assumes that the DHM parameters \c ctx->P
 *                 and \c ctx->G have already been properly set. For that, use
 *                 mbedtls_dhm_set_group() below in conjunction with
 *                 mbedtls_mpi_read_binary() and mbedtls_mpi_read_string().
 *
 * \note           In a TLS handshake, this is the how the server generates
 *                 and exports its DHM key material.
 *
 * \param ctx      The DHM context to use. This must be initialized
 *                 and have the DHM parameters set. It may or may not
 *                 already have imported the peer's public key.
 * \param x_size   The private key size in Bytes.
 * \param olen     The address at which to store the number of Bytes
 *                 written on success. This must not be \c NULL.
 * \param output   The destination buffer. This must be a writable buffer of
 *                 sufficient size to hold the reduced binary presentation of
 *                 the modulus, the generator and the public key, each wrapped
 *                 with a 2-byte length field. It is the responsibility of the
 *                 caller to ensure that enough space is available. Refer to
 *                 mbedtls_mpi_size() to computing the byte-size of an MPI.
 * \param f_rng    The RNG function. Must not be \c NULL.
 * \param p_rng    The RNG context to be passed to \p f_rng. This may be
 *                 \c NULL if \p f_rng doesn't need a context parameter.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
pub fn mbedtls_dhm_make_params( ctx: &mut mbedtls_dhm_context,
                                x_size: i32,
                                output: &mut[u8],
                                olen: &mut usize,
                                f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32,
                                p_rng: &mut Vec<u8>)->i32
{
    let mut ret;
    let mut count=0;
    let n1: usize;
    let n2: usize;
    let n3: usize;
    let mut p: &mut[u8];

    if mbedtls_mpi_cmp_int( &mut ctx.P, 0 ) == 0 {
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA
    }

    while{ 
        ret = mbedtls_mpi_fill_random( &mut ctx.X, x_size as usize, f_rng, p_rng );
        if ret !=0 {
            return MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED + ret
        }
        while mbedtls_mpi_cmp_mpi( &mut ctx.X, &mut ctx.P ) >= 0{
            ret = mbedtls_mpi_shift_r( &mut ctx.X, 1); 
            if ret !=0 {
                return MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED + ret
            }
        }

        if post_inc!(count) > 10{ 
            return MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED
        }
        dhm_check_range( &mut ctx.X, &mut ctx.P ) != 0
    } {}

    ret = mbedtls_mpi_exp_mod( &mut ctx.GX, &mut ctx.G, &mut ctx.X,
        &mut ctx.P , Some(&mut ctx.RP) ); 
    if ret !=0 {
        return MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED + ret
    }
    
    ret = dhm_check_range( &mut ctx.GX, &mut ctx.P );    
    if ret != 0{
        return ret
    }

    n1 = mbedtls_mpi_size( &mut ctx.P  );
    n2 = mbedtls_mpi_size( &mut ctx.G  );
    n3 = mbedtls_mpi_size( &mut ctx.GX );


    let op_ptr: *const [u8] = output;
    
    p = output;

    while {
        ret = mbedtls_mpi_write_binary( &mut ctx.P,&mut p[2],n1 ); 
        if ret !=0 {
            return MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED + ret
        }
        p[0] =  (( n1 as u8 )>>8); 
        p = &mut p[1..];                          
        p[0] =  n1 as u8;
        p = &mut p[1..];                           
        p = &mut p[n1..];
        false 
    } {}
    
    while {
        ret = mbedtls_mpi_write_binary( &mut ctx.G,&mut p[2],n2 ); 
        if ret !=0 {
            return MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED + ret
        }
        p[0] =  ((n2 as u8)  >> (8)); 
        p = &mut p[1..];                          
        p[0] =  n2 as u8;
        p = &mut p[1..];                           
        p = &mut p[n2..];
        false 
    } {}

    while {
        ret =  mbedtls_mpi_write_binary( &mut ctx.GX,&mut p[2],n3 ); 
        if ret !=0 {
            return MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED + ret
        }
        p[0] =  (( n3 as u8 ) >> 8); 
        p = &mut p[1..];                          
        p[0] =  n3 as u8;
        p = &mut p[1..];                           
        p = &mut p[n3..];
        false 
    } {}
    unsafe
    {
        let p_ptr: *const [u8] = p;
        *olen = *p_ptr  - *op_ptr;
    }

    let mut a: &mut[u8];
    a.clone_from_slice(&mut output);
    *olen = (&p[0]  - &a[0]) as usize;

    ctx.len = n1;
    0    
}

/**
 * \brief          This function sets the prime modulus and generator.
 *
 * \note           This function can be used to set \c ctx->P, \c ctx->G
 *                 in preparation for mbedtls_dhm_make_params().
 *
 * \param ctx      The DHM context to configure. This must be initialized.
 * \param P        The MPI holding the DHM prime modulus. This must be
 *                 an initialized MPI.
 * \param G        The MPI holding the DHM generator. This must be an
 *                 initialized MPI.
 *
 * \return         \c 0 if successful.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
pub fn mbedtls_dhm_set_group(ctx: &mut mbedtls_dhm_context,
                            P: &mut mbedtls_mpi,
                            G: &mut mbedtls_mpi) -> i32
{
    let mut ret;

    ret =  mbedtls_mpi_copy( &mut ctx.P, P );
    
    if ret !=0 {
        return MBEDTLS_ERR_DHM_SET_GROUP_FAILED + ret
    }
    
    ret =  mbedtls_mpi_copy( &mut ctx.P, G );
    if ret !=0 {
        return MBEDTLS_ERR_DHM_SET_GROUP_FAILED + ret
    }

    ctx.len = mbedtls_mpi_size(&mut ctx.P);
    0
}

/**
 * \brief          This function imports the raw public value of the peer.
 *
 * \note           In a TLS handshake, this is the how the server imports
 *                 the Client's public DHM key.
 *
 * \param ctx      The DHM context to use. This must be initialized and have
 *                 its DHM parameters set, e.g. via mbedtls_dhm_set_group().
 *                 It may or may not already have generated its own private key.
 * \param input    The input buffer containing the \c G^Y value of the peer.
 *                 This must be a readable buffer of size \p ilen Bytes.
 * \param ilen     The size of the input buffer \p input in Bytes.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
pub fn mbedtls_dhm_read_public( ctx: &mut mbedtls_dhm_context,
                                input: &mut u8,
                                ilen: usize)->i32
{
    let ret;

    if ilen < 1 || ilen > ctx.len{
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA
    }
    ret = mbedtls_mpi_read_binary( &mut ctx.GY, input, ilen );
    if ret != 0{
        return MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED + ret
    }
    0

}

/**
 * \brief          This function creates a DHM key pair and exports
 *                 the raw public key in big-endian format.
 *
 * \note           The destination buffer is always fully written
 *                 so as to contain a big-endian representation of G^X mod P.
 *                 If it is larger than \c ctx->len, it is padded accordingly
 *                 with zero-bytes at the beginning.
 *
 * \param ctx      The DHM context to use. This must be initialized and
 *                 have the DHM parameters set. It may or may not already
 *                 have imported the peer's public key.
 * \param x_size   The private key size in Bytes.
 * \param output   The destination buffer. This must be a writable buffer of
 *                 size \p olen Bytes.
 * \param olen     The length of the destination buffer. This must be at least
 *                 equal to `ctx->len` (the size of \c P).
 * \param f_rng    The RNG function. This must not be \c NULL.
 * \param p_rng    The RNG context to be passed to \p f_rng. This may be \c NULL
 *                 if \p f_rng doesn't need a context argument.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
pub fn mbedtls_dhm_make_public( ctx: &mut mbedtls_dhm_context,
                                x_size: i32,
                                output: &mut u8,
                                olen: usize,
                                f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32,
                                p_rng: &mut Vec<u8>)->i32
{
    let mut ret; 
    let mut count=0;

    if olen < 1 || olen > ctx.len{
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA
    }
    if mbedtls_mpi_cmp_int( &mut ctx.P, 0 ) == 0{
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA 
    }

    //generate X and calculate GX = G^X mod P
    while{
        ret =  mbedtls_mpi_fill_random( &mut ctx.X, x_size as usize, f_rng, p_rng ); 
        if ret !=0 {
            return MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED + ret
        }

        while mbedtls_mpi_cmp_mpi( &mut ctx.X, &mut ctx.P ) >= 0{
            ret =  mbedtls_mpi_shift_r( &mut ctx.X, 1 ); 
            if ret !=0 {
                return MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED + ret
            }
        }
        if post_inc!(count) > 10{
            return MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED
        }
        dhm_check_range( &mut ctx.X, &mut ctx.P ) != 0
    } {}

    ret =  mbedtls_mpi_exp_mod( &mut ctx.GX, &mut ctx.G, &mut ctx.X, &mut ctx.P , Some(&mut ctx.RP )); 
    if ret !=0 {
        return MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED + ret
    }

    ret = dhm_check_range( &mut ctx.GX, &mut ctx.P );
    if ret != 0{
        return ret
    }

    ret =   mbedtls_mpi_write_binary( &mut ctx.GX, output, olen ); 
    if ret !=0 {
        return MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED + ret
    }
    
    0
}

/*
 * Pick a random R in the range [2, M) for blinding purposes
 */
pub fn dhm_random_below(R: &mut mbedtls_mpi,
                        M: &mut mbedtls_mpi,
                        f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32,
                        p_rng: &mut Vec<u8>) -> i32{
    let mut ret;
    let mut count;

    count =0;

    while {
        ret =   mbedtls_mpi_fill_random( R, mbedtls_mpi_size( M ), f_rng, p_rng) ; 
        if ret !=0 {
            return ret
        }

        while mbedtls_mpi_cmp_mpi( R, M ) >= 0{
            ret =  mbedtls_mpi_shift_r( R, 1 ); 
            if ret !=0 {
                return ret
            }

        }
        
        if post_inc!(count) > 10 {
            return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE; 
        }
        mbedtls_mpi_cmp_int( R, 1 ) <= 0

    } {}

    0
}

/*
 * Use the blinding method and optimisation suggested in section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
pub fn dhm_update_blinding( ctx: &mut mbedtls_dhm_context,
                            f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32, 
                            p_rng: &mut Vec<u8>) -> i32{
    let mut ret;
    let mut R: mbedtls_mpi= mbedtls_mpi{s: 1,n: 0, p: vec![]};
    
    //Don't use any blinding the first time a particular X is used,
    //but remember it to use blinding next time.
    if mbedtls_mpi_cmp_mpi( &mut ctx.X, &mut ctx.pX ) != 0{
        ret =  mbedtls_mpi_copy( &mut ctx.pX, &mut ctx.X ); 
            if ret !=0 {
                return ret
            }
        ret = mbedtls_mpi_lset( &mut ctx.Vi, 1 ); 
        if ret !=0 {
            return ret
        }
        ret = mbedtls_mpi_lset( &mut ctx.Vf, 1 ); 
            if ret !=0 {
                return ret
            }
        
        return 0 
    }

    let mut read_ctxVi: mbedtls_mpi = (ctx.Vi).Copy();
    let mut read_ctxVf: mbedtls_mpi = (ctx.Vf).Copy();

    //Ok, we need blinding. Can we re-use existing values?
    //If yes, just update them by squaring them.
    if mbedtls_mpi_cmp_int( &mut ctx.Vi, 1 ) != 0 {
        ret = mbedtls_mpi_mul_mpi( &mut ctx.Vi,  & read_ctxVi, & read_ctxVi); 
        if ret !=0 {
            return ret
        }

        read_ctxVi = (ctx.Vi).Copy();
        ret = mbedtls_mpi_mod_mpi( &mut ctx.Vi, & read_ctxVi, &mut ctx.P ); 
        if ret !=0 {
            return ret
        }

        ret = mbedtls_mpi_mul_mpi( &mut ctx.Vf, & read_ctxVf, & read_ctxVf ); 
        if ret !=0 {
            return ret
        }

        read_ctxVf = (ctx.Vf).Copy();
        ret = mbedtls_mpi_mod_mpi( &mut ctx.Vf, & read_ctxVf, &mut ctx.P ); 
        if ret !=0 {
            return ret
        }
        return 0 
    }

    //We need to generate blinding values from scratc
    ret = dhm_random_below(&mut ctx.Vi, &mut ctx.P, f_rng, p_rng ); 
    if ret !=0 {
        return ret
    }

    ret =  dhm_random_below( &mut R, &mut ctx.P, f_rng, p_rng ); 
    if ret !=0 {
        return ret
    }

    ret =  mbedtls_mpi_mul_mpi( &mut ctx.Vf, &mut ctx.Vi, &mut R ); 
    if ret !=0 {
        return ret
    }

    read_ctxVf = (ctx.Vf).Copy();

    ret =  mbedtls_mpi_mod_mpi( &mut ctx.Vf, & read_ctxVf, &mut ctx.P ); 
    if ret !=0 {
        return ret
    }

    read_ctxVf = (ctx.Vf).Copy();
    
    ret =  mbedtls_mpi_inv_mod( &mut ctx.Vf, & read_ctxVf, &mut ctx.P ); 
    if ret !=0 {
        return ret
    }

    read_ctxVf = (ctx.Vf).Copy();
    
    ret = mbedtls_mpi_mul_mpi( &mut ctx.Vf, & read_ctxVf, &mut R ); 
    if ret !=0 {
        return ret
    }

    read_ctxVf = (ctx.Vf).Copy();
    ret = mbedtls_mpi_mod_mpi( &mut ctx.Vf, & read_ctxVf, &mut ctx.P ); 
    if ret !=0 {
        return ret
    }

    let ctxVfptr: &mut mbedtls_mpi = &mut (ctx.Vf).Copy();
    ret =  mbedtls_mpi_exp_mod( &mut ctx.Vf, ctxVfptr, &mut ctx.X, &mut ctx.P, Some(&mut ctx.RP) ); 
    if ret !=0 {
        return ret
    }

    return ret
}

/**
 * \brief          This function derives and exports the shared secret
 *                 \c (G^Y)^X mod \c P.
 *
 * \note           If \p f_rng is not \c NULL, it is used to blind the input as
 *                 a countermeasure against timing attacks. Blinding is used
 *                 only if our private key \c X is re-used, and not used
 *                 otherwise. We recommend always passing a non-NULL
 *                 \p f_rng argument.
 *
 * \param ctx           The DHM context to use. This must be initialized
 *                      and have its own private key generated and the peer's
 *                      public key imported.
 * \param output        The buffer to write the generated shared key to. This
 *                      must be a writable buffer of size \p output_size Bytes.
 * \param output_size   The size of the destination buffer. This must be at
 *                      least the size of \c ctx->len (the size of \c P).
 * \param olen          On exit, holds the actual number of Bytes written.
 * \param f_rng         The RNG function, for blinding purposes. This may
 *                      b \c NULL if blinding isn't needed.
 * \param p_rng         The RNG context. This may be \c NULL if \p f_rng
 *                      doesn't need a context argument.
 *
 * \return              \c 0 on success.
 * \return              An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
pub fn mbedtls_dhm_calc_secret( ctx: &mut mbedtls_dhm_context,
                                output: &mut u8,
                                output_size: usize,
                                olen: &mut usize,
                                f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32,
                                p_rng: &mut Vec<u8>) -> i32 {

    let mut ret;
    let mut GYb: mbedtls_mpi= mbedtls_mpi{s: 1,n: 0, p: vec![]};
    
    let read_ctxK: mbedtls_mpi = (ctx.K).Copy();
    let read_GYb: mbedtls_mpi = GYb.Copy();    

    if output_size < ctx.len{
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA
    }

    ret = dhm_check_range( &mut ctx.GY, &mut ctx.P );    
    if  ret != 0{
        return ret
    }

    ret = dhm_update_blinding( ctx, f_rng, p_rng );    
    if  ret != 0{
        return MBEDTLS_ERR_DHM_CALC_SECRET_FAILED + ret
    }

    ret = mbedtls_mpi_mul_mpi( &mut GYb, &mut ctx.GY, &mut ctx.Vi );    
    if  ret != 0{
        return MBEDTLS_ERR_DHM_CALC_SECRET_FAILED + ret
    }
    
    ret = mbedtls_mpi_mod_mpi( &mut GYb, & read_GYb, &mut ctx.P );    
    if  ret != 0{
        return MBEDTLS_ERR_DHM_CALC_SECRET_FAILED + ret
    }

    ret = mbedtls_mpi_copy( &mut GYb, &mut ctx.GY );    
    if  ret != 0{
        return MBEDTLS_ERR_DHM_CALC_SECRET_FAILED + ret
    }
    
    /* Do modular exponentiation */
    ret = mbedtls_mpi_exp_mod( &mut ctx.K, &mut GYb, &mut ctx.X,
            &mut ctx.P, Some(&mut ctx.RP) );    
    if  ret != 0{
        return MBEDTLS_ERR_DHM_CALC_SECRET_FAILED + ret
    }

    // Unblind secret value
    ret = mbedtls_mpi_mul_mpi( &mut ctx.K, & read_ctxK, &mut ctx.Vf );    
    if  ret != 0{
        return MBEDTLS_ERR_DHM_CALC_SECRET_FAILED + ret
    }

    ret = mbedtls_mpi_mod_mpi( &mut ctx.K, & read_ctxK, &mut ctx.P );    
    if  ret != 0{
        return MBEDTLS_ERR_DHM_CALC_SECRET_FAILED + ret
    }

    *olen = mbedtls_mpi_size( &mut ctx.K );

    ret = mbedtls_mpi_write_binary( &mut ctx.K, output, *olen );    
        if  ret != 0{
            return MBEDTLS_ERR_DHM_CALC_SECRET_FAILED + ret
        }

    return 0 
}

//-------------------------------------------------------------------------
//Self test values
// static const char mbedtls_test_dhm_params[] =
// "-----BEGIN DH PARAMETERS-----\r\n"
// "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh\r\n"
// "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32\r\n"
// "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC\r\n"
// "-----END DH PARAMETERS-----\r\n";
// pub const mbedtls_test_dhm_params:[u8;138] = 
// [
//     0x30, 0x81, 0x87, 0x02, 0x81, 0x81, 0x00, 0x9e, 0x35, 0xf4, 0x30, 0x44,
//     0x3a, 0x09, 0x90, 0x4f, 0x3a, 0x39, 0xa9, 0x79, 0x79, 0x7d, 0x07, 0x0d,
//     0xf5, 0x33, 0x78, 0xe7, 0x9c, 0x24, 0x38, 0xbe, 0xf4, 0xe7, 0x61, 0xf3,
//     0xc7, 0x14, 0x55, 0x33, 0x28, 0x58, 0x9b, 0x04, 0x1c, 0x80, 0x9b, 0xe1,
//     0xd6, 0xc6, 0xb5, 0xf1, 0xfc, 0x9f, 0x47, 0xd3, 0xa2, 0x54, 0x43, 0x18,
//     0x82, 0x53, 0xa9, 0x92, 0xa5, 0x68, 0x18, 0xb3, 0x7b, 0xa9, 0xde, 0x5a,
//     0x40, 0xd3, 0x62, 0xe5, 0x6e, 0xff, 0x0b, 0xe5, 0x41, 0x74, 0x74, 0xc1,
//     0x25, 0xc1, 0x99, 0x27, 0x2c, 0x8f, 0xe4, 0x1d, 0xea, 0x73, 0x3d, 0xf6,
//     0xf6, 0x62, 0xc9, 0x2a, 0xe7, 0x65, 0x56, 0xe7, 0x55, 0xd1, 0x0c, 0x64,
//     0xe6, 0xa5, 0x09, 0x68, 0xf6, 0x7f, 0xc6, 0xea, 0x73, 0xd0, 0xdc, 0xa8,
//     0x56, 0x9b, 0xe2, 0xba, 0x20, 0x4e, 0x23, 0x58, 0x0d, 0x8b, 0xca, 0x2f,
//     0x49, 0x75, 0xb3, 0x02, 0x01, 0x02
// ];
pub fn print()
{
println!("in bin/dhm.rs file");
}