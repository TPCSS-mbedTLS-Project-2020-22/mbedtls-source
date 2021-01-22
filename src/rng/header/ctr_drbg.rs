/*
 * \file ctr_drbg.h
 *
 * \brief    This file contains definitions and functions for the
 *           CTR_DRBG pseudorandom generator.
 *
 * CTR_DRBG is a standardized way of building a PRNG from a block-cipher
 * in counter mode operation, as defined in <em>NIST SP 800-90A:
 * Recommendation for Random Number Generation Using Deterministic Random
 * Bit Generators</em>.
 *
 * The Mbed TLS implementation of CTR_DRBG uses AES-256 (default) or AES-128
 * (if \c MBEDTLS_CTR_DRBG_USE_128_BIT_KEY is enabled at compile time)
 * as the underlying block cipher, with a derivation function.
 *
 * The security strength as defined in NIST SP 800-90A is
 * 128 bits when AES-128 is used (\c MBEDTLS_CTR_DRBG_USE_128_BIT_KEY enabled)
 * and 256 bits otherwise, provided that #MBEDTLS_CTR_DRBG_ENTROPY_LEN is
 * kept at its default value (and not overridden in config.h) and that the
 * DRBG instance is set up with default parameters.
 * See the documentation of mbedtls_ctr_drbg_seed() for more
 * information.
 */
<<<<<<< HEAD
=======
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
>>>>>>> 33b9568e044e9ca4c03860584b37528ad6116362


use std::ffi::c_void;


pub const MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:i32 = -0x0034;  /**< The entropy source failed. */
pub const MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:i32 = -0x0036;  /**< The requested random buffer length is too big. */
pub const MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG:i32 = -0x0038;  /**< The input (entropy + additional data) is too large. */
pub const MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR:i32 = -0x003A;  /**< Read or write error in file. */

pub const MBEDTLS_CTR_DRBG_BLOCKSIZE:i32 = 16; /**< The block size used by the cipher. */

pub const MBEDTLS_CTR_DRBG_KEYSIZE:i32 = 32;
/**< The key size in bytes used by the cipher.
 *
 * Compile-time choice: 32 bytes (256 bits)
 * because \c MBEDTLS_CTR_DRBG_USE_128_BIT_KEY is disabled.
 */

pub const MBEDTLS_CTR_DRBG_KEYBITS:i32 = ( MBEDTLS_CTR_DRBG_KEYSIZE * 8 ); /**< The key size for the DRBG operation, in bits. */
pub const MBEDTLS_CTR_DRBG_SEEDLEN:i32 = ( MBEDTLS_CTR_DRBG_KEYSIZE + MBEDTLS_CTR_DRBG_BLOCKSIZE ); /**< The seed length, calculated as (counter + AES key). */


pub const MBEDTLS_CTR_DRBG_ENTROPY_LEN: i32 = 48;
/** This is 48 bytes because the entropy module uses SHA-512
 * (\c MBEDTLS_ENTROPY_FORCE_SHA256 is disabled).
 */

pub const MBEDTLS_CTR_DRBG_RESEED_INTERVAL:i32 = 10000;
/**< The interval before reseed is performed by default. */

pub const MBEDTLS_CTR_DRBG_MAX_INPUT:i32 = 256;
/**< The maximum number of additional input Bytes. */

pub const MBEDTLS_CTR_DRBG_MAX_REQUEST:i32 = 1024;
/**< The maximum number of requested Bytes per call. */

pub const MBEDTLS_CTR_DRBG_MAX_SEED_INPUT:i32 = 384;
/**< The maximum size of seed or reseed buffer in bytes. */

pub const MBEDTLS_CTR_DRBG_PR_OFF:i32 = 0;
/**< Prediction resistance is disabled. */
pub const MBEDTLS_CTR_DRBG_PR_ON:i32 = 1;
/**< Prediction resistance is enabled. */

pub const MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN:i32 = 0;
/**< Prediction resistance is disabled. */

<<<<<<< HEAD
pub fn f_entropy(data: Option<*mut c_void>, output: &mut [u8], len: usize, olen: usize) -> i32; 
pub type mbedtls_entropy_f_source_ptr = fn(data: Option<*mut c_void>, output: &mut [u8], len: usize, olen: usize)->i32;
pub f_ptr:mbedtls_entropy_f_source_ptr = f_entropy;

pub struct mbedtls_ctr_drbg_context{
=======
pub struct {
>>>>>>> 33b9568e044e9ca4c03860584b37528ad6116362

    pub counter[u8, 16];  /*!< The counter (V). */
    pub reseed_counter:i32 ;         /*!< The reseed counter.
                                 * This is the number of requests that have
                                 * been made since the last (re)seeding,
                                 * minus one.
                                 * Before the initial seeding, this field
                                 * contains the amount of entropy in bytes
                                 * to use as a nonce for the initial seeding,
                                 * or -1 if no nonce length has been explicitly
                                 * set (see mbedtls_ctr_drbg_set_nonce_len()).
                                 */
    pub prediction_resistance:i32;  /*!< This determines whether prediction
                                     resistance is enabled, that is
                                     whether to systematically reseed before
                                     each random generation. */
    pub entropy_len: usize;         /*!< The amount of entropy grabbed on each
                                     seed or reseed operation, in bytes. */
    pub reseed_interval: i32;        /*!< The reseed interval.
                                 * This is the maximum number of requests
                                 * that can be made between reseedings. */

    pub aes_ctx: mbedtls_aes_context;        /*!< The AES context. */

    /*
     * Callbacks (Entropy)
     */
<<<<<<< HEAD
    //int (*f_entropy)(void *, unsigned char *, size_t);   
    pub fptr = f_ptr(data: Option<*mut c_void>, output: &mut [u8], len: usize, olen: usize)->i32;
=======
    fn (*f_entropy)(void *, unsigned char *, usize) -> i32;
>>>>>>> 33b9568e044e9ca4c03860584b37528ad6116362
                                /*!< The entropy callback function. */

    pub p_entropy: *mut c_void;           /*!< The context for the entropy function. */
   
<<<<<<< HEAD
};
=======
}mbedtls_ctr_drbg_context;
>>>>>>> 33b9568e044e9ca4c03860584b37528ad6116362


