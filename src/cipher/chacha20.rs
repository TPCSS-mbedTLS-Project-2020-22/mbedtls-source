#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused)]
#![allow(unused_imports)]

//importing the variables and functions required from other files
use crate::cipher::chacha20_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
use crate::cipher::chacha20_header::CHACHA20_CTR_INDEX;
use crate::cipher::chacha20_header::MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;
use crate::cipher::blowfish_header::MODULU32;
use std::ptr::write_bytes;
use crate::cipher::chacha20_header::CHACHA20_BLOCK_SIZE_BYTES;
use crate::cipher::chacha20_header::mbedtls_chacha20_context;


//helper functions
pub fn ROTL32(value:u32,amount:usize)->u32{
    let ret:u32;
    ret=(((value as u64)<<amount)|((value as u64)>>(32-amount))) as u32;
    return ret;
}

pub fn BYTES_TO_U32_LE(data:[u8;32],offset:usize)->u32{
    let ret:u32;
    ret=(data[offset] as u32)
        |((data[offset+1] as u32 )<<8)
        |((data[offset+2] as u32 )<<16)
        |((data[offset+3] as u32 )<<24);
    return ret;
}
pub fn BYTES_TO_U32_LE2(data:[u8;12],offset:usize)->u32{
    let ret:u32;
    ret=(data[offset] as u32)
        |((data[offset+1] as u32 )<<8)
        |((data[offset+2] as u32 )<<16)
        |((data[offset+3] as u32 )<<24);
    return ret;
}

/* *
 * \brief           ChaCha20 quarter round operation.
 *
 *                  The quarter round is defined as follows (from RFC 7539):
 *                      1.  a += b; d ^= a; d <<<= 16;
 *                      2.  c += d; b ^= c; b <<<= 12;
 *                      3.  a += b; d ^= a; d <<<= 8;
 *                      4.  c += d; b ^= c; b <<<= 7;
 *
 * \param state     ChaCha20 state to modify.
 * \param a         The index of 'a' in the state.
 * \param b         The index of 'b' in the state.
 * \param c         The index of 'c' in the state.
 * \param d         The index of 'd' in the state.
 */

pub fn chacha20_quarter_round(state:&mut [u32;16],a:usize,b:usize,c:usize,d:usize)
{
    state[a] = (((state[a]as u64) +  (state[b] as u64))%MODULU32)as u32;
    state[d] ^= state[a];
    state[d] = ROTL32( state[d], 16 );

    /* c += d; b ^= c; b <<<= 12 */
    state[c] = (((state[c]as u64) +  (state[d] as u64))%MODULU32)as u32;
    state[b] ^= state[c];
    state[b] = ROTL32( state[b], 12 );

    /* a += b; d ^= a; d <<<= 8; */
    state[a] =(((state[a]as u64) +  (state[b] as u64))%MODULU32)as u32;
    state[d] ^= state[a];
    state[d] = ROTL32( state[d], 8 );

    /* c += d; b ^= c; b <<<= 7; */
    state[c] = (((state[c]as u64) +  (state[d] as u64))%MODULU32)as u32;
    state[b] ^= state[c];
    state[b] = ROTL32( state[b], 7 );
}
/* *
 * \brief           Perform the ChaCha20 inner block operation.
 *
 *                  This function performs two rounds: the column round and the
 *                  diagonal round.
 *
 * \param state     The ChaCha20 state to update.
 */
pub fn chacha20_inner_block(  state:&mut [u32;16] )
{
    chacha20_quarter_round( state, 0, 4, 8,  12 );
    chacha20_quarter_round( state, 1, 5, 9,  13 );
    chacha20_quarter_round( state, 2, 6, 10, 14 );
    chacha20_quarter_round( state, 3, 7, 11, 15 );

    chacha20_quarter_round( state, 0, 5, 10, 15 );
    chacha20_quarter_round( state, 1, 6, 11, 12 );
    chacha20_quarter_round( state, 2, 7, 8,  13 );
    chacha20_quarter_round( state, 3, 4, 9,  14 );
}
/* *
 * \brief               Generates a keystream block.
 *
 * \param initial_state The initial ChaCha20 state (key, nonce, counter).
 * \param keystream     Generated keystream bytes are written to this buffer.
 */
pub fn chacha20_block( initial_state:&mut [u32;16], keystream:&mut [u8;64] )
{
    let mut working_state:[u32;16]=[0;16];
    for i in 0..16{
        working_state[i]=initial_state[i];
    }
    let mut i:usize;
    for i in 0..10{
        chacha20_inner_block(&mut working_state);
    }
    working_state[ 0] =((working_state[0]as u64)+ (initial_state[ 0]as u64)%MODULU32)as u32;
    working_state[ 1] = ((working_state[1]as u64)+ (initial_state[ 1]as u64)%MODULU32)as u32;
    working_state[ 2] = ((working_state[2]as u64)+ (initial_state[ 2]as u64)%MODULU32)as u32;
    working_state[ 3] = ((working_state[3]as u64)+ (initial_state[ 3]as u64)%MODULU32)as u32;
    working_state[ 4] = ((working_state[4]as u64)+ (initial_state[ 4]as u64)%MODULU32)as u32;
    working_state[ 5] = ((working_state[5]as u64)+ (initial_state[ 5]as u64)%MODULU32)as u32;
    working_state[ 6] = ((working_state[6]as u64)+ (initial_state[ 6]as u64)%MODULU32)as u32;
    working_state[ 7] = ((working_state[7]as u64)+ (initial_state[ 7]as u64)%MODULU32)as u32;
    working_state[ 8] =((working_state[8]as u64)+ (initial_state[ 8]as u64)%MODULU32)as u32 ;
    working_state[ 9] = ((working_state[9]as u64)+ (initial_state[ 9]as u64)%MODULU32)as u32;
    working_state[10] = ((working_state[10]as u64)+ (initial_state[ 10]as u64)%MODULU32)as u32;
    working_state[11] = ((working_state[11]as u64)+ (initial_state[ 11]as u64)%MODULU32)as u32;
    working_state[12] = ((working_state[12]as u64)+ (initial_state[ 12]as u64)%MODULU32)as u32 ;
    working_state[13] = ((working_state[13]as u64)+ (initial_state[ 13]as u64)%MODULU32)as u32;
    working_state[14] =((working_state[14]as u64)+ (initial_state[ 14]as u64)%MODULU32)as u32;
    working_state[15] = ((working_state[15]as u64)+ (initial_state[ 15]as u64)%MODULU32)as u32;

    for i in 0..16{
        let offset:usize=i*4;
        keystream[offset     ] = ( working_state[i]       ) as u8 ;
        keystream[offset + 1] = ( working_state[i] >>  8 ) as u8 ;
        keystream[offset + 2] = ( working_state[i] >> 16 ) as u8 ;
        keystream[offset + 3] = ( working_state[i] >> 24 ) as u8 ;
    }
    working_state=[0;16];
}
pub fn mbedtls_chacha20_init(ctx:&mut mbedtls_chacha20_context){
    (*ctx).state=[0;16];
    (*ctx).keystream8=[0;64];
    (*ctx).keystream_bytes_used=CHACHA20_BLOCK_SIZE_BYTES;
}
pub fn mbedtls_chacha20_free(ctx:&mut mbedtls_chacha20_context){
    unsafe{
        write_bytes(ctx,0,1);
        }
}
pub fn mbedtls_chacha20_setkey(ctx:&mut mbedtls_chacha20_context,key:[u8;32])->i32{
    
    /* ChaCha20 constants - the string "expand 32-byte k" */
    (*ctx).state[0] = 0x61707865;
    (*ctx).state[1] = 0x3320646e;
    (*ctx).state[2] = 0x79622d32;
    (*ctx).state[3] = 0x6b206574;

    (*ctx).state[4]  = BYTES_TO_U32_LE( key, 0 );
    (*ctx).state[5]  = BYTES_TO_U32_LE( key, 4 );
    (*ctx).state[6]  = BYTES_TO_U32_LE( key, 8 );
    (*ctx).state[7]  = BYTES_TO_U32_LE( key, 12 );
    (*ctx).state[8]  = BYTES_TO_U32_LE( key, 16 );
    (*ctx).state[9]  = BYTES_TO_U32_LE( key, 20 );
    (*ctx).state[10] = BYTES_TO_U32_LE( key, 24 );
    (*ctx).state[11] = BYTES_TO_U32_LE( key, 28 );
    return 0;

}

pub fn mbedtls_chacha20_starts(ctx:&mut mbedtls_chacha20_context,nonce:[u8;12],counter:u32)->i32{
    (*ctx).state[12] = counter;

    /* Nonce */
    (*ctx).state[13] = BYTES_TO_U32_LE2( nonce, 0 );
    (*ctx).state[14] = BYTES_TO_U32_LE2( nonce, 4 );
    (*ctx).state[15] = BYTES_TO_U32_LE2( nonce, 8 );

    (*ctx).keystream8=[0;64];

    /* Initially, there's no keystream bytes available */
    (*ctx).keystream_bytes_used = CHACHA20_BLOCK_SIZE_BYTES;

    return 0 ;
}

pub fn mbedtls_chacha20_update(ctx:&mut mbedtls_chacha20_context,mut size:usize,
            input:Vec<u8>,output:&mut Vec<u8>)->i32
{
    if size==0 || size!=input.len(){
        return MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;
    }
    let mut offset:usize=0;
    //let mut res:Vec[u8]=String::from("");
    //let mut inpchars=input.chars();
    while size>0 && (*ctx).keystream_bytes_used < CHACHA20_BLOCK_SIZE_BYTES {
        let out:u8;
        let inp:u8=input[offset];
        out=inp ^((*ctx).keystream8[(*ctx).keystream_bytes_used]);
        output.push(out);
        offset+=1;
        size-=1;
    }

    while size >= CHACHA20_BLOCK_SIZE_BYTES
    {
        /* Generate new keystream block and increment counter */
        chacha20_block( &mut (*ctx).state, &mut (*ctx).keystream8 );
        (*ctx).state[CHACHA20_CTR_INDEX]+=1;
        for i in (0..64).step_by(8){
            let mut out:u8;
            out=input[offset + i  ] ^ (*ctx).keystream8[i  ];
            output.push(out);
            out=input[offset + i +1 ] ^ (*ctx).keystream8[i+1  ];
            output.push(out);
            out=input[offset + i + 2 ] ^ (*ctx).keystream8[i +2 ];
            output.push(out);
            out=input[offset + i +3 ] ^ (*ctx).keystream8[i + 3 ];
            output.push(out);
            out=input[offset + i +4 ] ^ (*ctx).keystream8[i +4 ];
            output.push(out);
            out=input[offset + i  +5] ^ (*ctx).keystream8[i+5  ];
            output.push(out);
            out=input[offset + i +6 ] ^ (*ctx).keystream8[i +6 ];
            output.push(out);
            out=input[offset + i+7  ] ^ (*ctx).keystream8[i+7  ];
            output.push(out);
        }
        offset += CHACHA20_BLOCK_SIZE_BYTES;
        size   -= CHACHA20_BLOCK_SIZE_BYTES;
    }
    if size > 0{
        /* Generate new keystream block and increment counter */
        chacha20_block( &mut (*ctx).state, &mut (*ctx).keystream8 );
        (*ctx).state[CHACHA20_CTR_INDEX]+=1;
        for i in 0..size{
            let out:u8;
            out=input[offset + i] ^ (*ctx).keystream8[i];
            output.push(out);
        }
        (*ctx).keystream_bytes_used = size;
    }
    //*output=res;
    return 0;
}

/*
 * \brief           This function encrypts or decrypts data with ChaCha20 and
 *                  the given key and nonce.
 *
 *                  Since ChaCha20 is a stream cipher, the same operation is
 *                  used for encrypting and decrypting data.
 *
 * \warning         You must never use the same (key, nonce) pair more than
 *                  once. This would void any confidentiality guarantees for
 *                  the messages encrypted with the same nonce and key.
 *
 * \note            The \p input and \p output references must either be equal or
 *                  point to non-overlapping buffers.
 *
 * \param key       The encryption/decryption key.
 *                  This must be \c 32 Bytes in length.
 * \param nonce     The nonce. This must be \c 12 Bytes in size.
 * \param counter   The initial counter value. This is usually \c 0.
 * \param size      The length of the input data in Bytes.
 * \param input     The buffer holding the input data.
 *                  This pointer can be \c NULL if `size == 0`.
 * \param output    The buffer holding the output data.
 *                  This must be able to hold \p size Bytes.
 *                  This pointer can be \c NULL if `size == 0`.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */

pub fn mbedtls_chacha20_crypt(key:[u8;32],
    nonce:[u8;12],counter:u32,data_len:usize,
    input:Vec<u8>,output:&mut Vec<u8>)->i32
{

    let mut ctx:mbedtls_chacha20_context=mbedtls_chacha20_context{
        state:[0;16],
        keystream8:[0;64],
        keystream_bytes_used:0
    };
    let mut ret:i32=MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if data_len==0 || data_len!=input.len(){
        return MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;
    }
    mbedtls_chacha20_init( &mut ctx );
    ret = mbedtls_chacha20_setkey( &mut ctx, key );
    if ret !=0 {
        mbedtls_chacha20_free( &mut ctx );
        return ret;
    }
    ret=mbedtls_chacha20_starts(&mut ctx, nonce, counter);
    if ret !=0 {
        mbedtls_chacha20_free( &mut ctx );
        return ret;
    }
    ret = mbedtls_chacha20_update( &mut ctx, data_len, input, output );
    mbedtls_chacha20_free( &mut ctx );
    return ret;
}

//self test
const test_keys:[[u8;32];2] = [
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ]
];

const test_nonces:[[u8;12];2]=[
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02
    ]
];

const test_counters:[u32;2]=[0,1];

 

const test_lengths:[usize;2]=[64,375];

fn mbedtls_chacha20_self_test(verbose:i32)->i32{
    let test_input:[Vec<u8>;2]=[
    vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ],
    vec![
        0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d,
        0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x74,
        0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45,
        0x54, 0x46, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x6e,
        0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72,
        0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x20, 0x66,
        0x6f, 0x72, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61,
        0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x72,
        0x20, 0x70, 0x61, 0x72, 0x74, 0x20, 0x6f, 0x66,
        0x20, 0x61, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46,
        0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
        0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x20,
        0x6f, 0x72, 0x20, 0x52, 0x46, 0x43, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x73,
        0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74,
        0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x77, 0x69,
        0x74, 0x68, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
        0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49,
        0x45, 0x54, 0x46, 0x20, 0x61, 0x63, 0x74, 0x69,
        0x76, 0x69, 0x74, 0x79, 0x20, 0x69, 0x73, 0x20,
        0x63, 0x6f, 0x6e, 0x73, 0x69, 0x64, 0x65, 0x72,
        0x65, 0x64, 0x20, 0x61, 0x6e, 0x20, 0x22, 0x49,
        0x45, 0x54, 0x46, 0x20, 0x43, 0x6f, 0x6e, 0x74,
        0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e,
        0x22, 0x2e, 0x20, 0x53, 0x75, 0x63, 0x68, 0x20,
        0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
        0x74, 0x73, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
        0x64, 0x65, 0x20, 0x6f, 0x72, 0x61, 0x6c, 0x20,
        0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
        0x74, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x49, 0x45,
        0x54, 0x46, 0x20, 0x73, 0x65, 0x73, 0x73, 0x69,
        0x6f, 0x6e, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x20,
        0x77, 0x65, 0x6c, 0x6c, 0x20, 0x61, 0x73, 0x20,
        0x77, 0x72, 0x69, 0x74, 0x74, 0x65, 0x6e, 0x20,
        0x61, 0x6e, 0x64, 0x20, 0x65, 0x6c, 0x65, 0x63,
        0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x20, 0x63,
        0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61,
        0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x6d, 0x61,
        0x64, 0x65, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e,
        0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x6f,
        0x72, 0x20, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x2c,
        0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x61,
        0x72, 0x65, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65,
        0x73, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f
    ]
];

    let test_output:[Vec<u8>;2]=[
    vec![
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
        0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
        0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
        0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
    ],
    vec![
        0xa3, 0xfb, 0xf0, 0x7d, 0xf3, 0xfa, 0x2f, 0xde,
        0x4f, 0x37, 0x6c, 0xa2, 0x3e, 0x82, 0x73, 0x70,
        0x41, 0x60, 0x5d, 0x9f, 0x4f, 0x4f, 0x57, 0xbd,
        0x8c, 0xff, 0x2c, 0x1d, 0x4b, 0x79, 0x55, 0xec,
        0x2a, 0x97, 0x94, 0x8b, 0xd3, 0x72, 0x29, 0x15,
        0xc8, 0xf3, 0xd3, 0x37, 0xf7, 0xd3, 0x70, 0x05,
        0x0e, 0x9e, 0x96, 0xd6, 0x47, 0xb7, 0xc3, 0x9f,
        0x56, 0xe0, 0x31, 0xca, 0x5e, 0xb6, 0x25, 0x0d,
        0x40, 0x42, 0xe0, 0x27, 0x85, 0xec, 0xec, 0xfa,
        0x4b, 0x4b, 0xb5, 0xe8, 0xea, 0xd0, 0x44, 0x0e,
        0x20, 0xb6, 0xe8, 0xdb, 0x09, 0xd8, 0x81, 0xa7,
        0xc6, 0x13, 0x2f, 0x42, 0x0e, 0x52, 0x79, 0x50,
        0x42, 0xbd, 0xfa, 0x77, 0x73, 0xd8, 0xa9, 0x05,
        0x14, 0x47, 0xb3, 0x29, 0x1c, 0xe1, 0x41, 0x1c,
        0x68, 0x04, 0x65, 0x55, 0x2a, 0xa6, 0xc4, 0x05,
        0xb7, 0x76, 0x4d, 0x5e, 0x87, 0xbe, 0xa8, 0x5a,
        0xd0, 0x0f, 0x84, 0x49, 0xed, 0x8f, 0x72, 0xd0,
        0xd6, 0x62, 0xab, 0x05, 0x26, 0x91, 0xca, 0x66,
        0x42, 0x4b, 0xc8, 0x6d, 0x2d, 0xf8, 0x0e, 0xa4,
        0x1f, 0x43, 0xab, 0xf9, 0x37, 0xd3, 0x25, 0x9d,
        0xc4, 0xb2, 0xd0, 0xdf, 0xb4, 0x8a, 0x6c, 0x91,
        0x39, 0xdd, 0xd7, 0xf7, 0x69, 0x66, 0xe9, 0x28,
        0xe6, 0x35, 0x55, 0x3b, 0xa7, 0x6c, 0x5c, 0x87,
        0x9d, 0x7b, 0x35, 0xd4, 0x9e, 0xb2, 0xe6, 0x2b,
        0x08, 0x71, 0xcd, 0xac, 0x63, 0x89, 0x39, 0xe2,
        0x5e, 0x8a, 0x1e, 0x0e, 0xf9, 0xd5, 0x28, 0x0f,
        0xa8, 0xca, 0x32, 0x8b, 0x35, 0x1c, 0x3c, 0x76,
        0x59, 0x89, 0xcb, 0xcf, 0x3d, 0xaa, 0x8b, 0x6c,
        0xcc, 0x3a, 0xaf, 0x9f, 0x39, 0x79, 0xc9, 0x2b,
        0x37, 0x20, 0xfc, 0x88, 0xdc, 0x95, 0xed, 0x84,
        0xa1, 0xbe, 0x05, 0x9c, 0x64, 0x99, 0xb9, 0xfd,
        0xa2, 0x36, 0xe7, 0xe8, 0x18, 0xb0, 0x4b, 0x0b,
        0xc3, 0x9c, 0x1e, 0x87, 0x6b, 0x19, 0x3b, 0xfe,
        0x55, 0x69, 0x75, 0x3f, 0x88, 0x12, 0x8c, 0xc0,
        0x8a, 0xaa, 0x9b, 0x63, 0xd1, 0xa1, 0x6f, 0x80,
        0xef, 0x25, 0x54, 0xd7, 0x18, 0x9c, 0x41, 0x1f,
        0x58, 0x69, 0xca, 0x52, 0xc5, 0xb8, 0x3f, 0xa3,
        0x6f, 0xf2, 0x16, 0xb9, 0xc1, 0xd3, 0x00, 0x62,
        0xbe, 0xbc, 0xfd, 0x2d, 0xc5, 0xbc, 0xe0, 0x91,
        0x19, 0x34, 0xfd, 0xa7, 0x9a, 0x86, 0xf6, 0xe6,
        0x98, 0xce, 0xd7, 0x59, 0xc3, 0xff, 0x9b, 0x64,
        0x77, 0x33, 0x8f, 0x3d, 0xa4, 0xf9, 0xcd, 0x85,
        0x14, 0xea, 0x99, 0x82, 0xcc, 0xaf, 0xb3, 0x41,
        0xb2, 0x38, 0x4d, 0xd9, 0x02, 0xf3, 0xd1, 0xab,
        0x7a, 0xc6, 0x1d, 0xd2, 0x9c, 0x6f, 0x21, 0xba,
        0x5b, 0x86, 0x2f, 0x37, 0x30, 0xe3, 0x7c, 0xfd,
        0xc4, 0xfd, 0x80, 0x6c, 0x22, 0xf2, 0x21
    ]

];

    let mut output:Vec<u8>;
    let mut ret:i32=MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    for i in 0..2{
        output=vec![];
        if verbose != 0{
            println!("Chacha20 test {}",i);
        }
        ret=mbedtls_chacha20_crypt(
            test_keys[i],
            test_nonces[i],
            test_counters[i],
            test_lengths[i],
            test_input[i].clone(),
            &mut output
        );
        if ret!=0{
            println!("error code {}",ret);
        }
        println!("{:02X?}",output);
        if output==test_output[i]{
            println!("yes");
        }
    }
    return ret;
}

pub fn run()
-> i32 {
    let l=mbedtls_chacha20_self_test(1);
    return l;
}