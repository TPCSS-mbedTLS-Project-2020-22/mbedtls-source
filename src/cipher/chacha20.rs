use crate::cipher::chacha20::chacha20_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
use crate::cipher::chacha20::chacha20_header::CHACHA20_CTR_INDEX;
use crate::cipher::chacha20::chacha20_header::MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;
use std::ptr::write_bytes;
use crate::cipher::chacha20::chacha20_header::CHACHA20_BLOCK_SIZE_BYTES;
use crate::cipher::chacha20::chacha20_header::mbedtls_chacha20_context;

pub mod chacha20_header;

pub fn ROTL32(value:u32,amount:usize)->u32{
    let ret:u32;
    ret=(((value as u64)<<amount)|((value as u64)>>(32-amount))) as u32;
    return ret;
}

pub fn BYTES_TO_U32_LE(data:[char;32],offset:usize)->u32{
    let ret:u32;
    ret=(data[offset] as u32)
        |((data[offset+1] as u32 )<<8)
        |((data[offset+2] as u32 )<<16)
        |((data[offset+3] as u32 )<<24);
    return ret;
}
pub fn BYTES_TO_U32_LE2(data:[char;12],offset:usize)->u32{
    let ret:u32;
    ret=(data[offset] as u32)
        |((data[offset+1] as u32 )<<8)
        |((data[offset+2] as u32 )<<16)
        |((data[offset+3] as u32 )<<24);
    return ret;
}

/**
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
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32( state[d], 16 );

    /* c += d; b ^= c; b <<<= 12 */
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32( state[b], 12 );

    /* a += b; d ^= a; d <<<= 8; */
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32( state[d], 8 );

    /* c += d; b ^= c; b <<<= 7; */
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32( state[b], 7 );
}
/**
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
/**
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
    working_state[ 0] += initial_state[ 0];
    working_state[ 1] += initial_state[ 1];
    working_state[ 2] += initial_state[ 2];
    working_state[ 3] += initial_state[ 3];
    working_state[ 4] += initial_state[ 4];
    working_state[ 5] += initial_state[ 5];
    working_state[ 6] += initial_state[ 6];
    working_state[ 7] += initial_state[ 7];
    working_state[ 8] += initial_state[ 8];
    working_state[ 9] += initial_state[ 9];
    working_state[10] += initial_state[10];
    working_state[11] += initial_state[11];
    working_state[12] += initial_state[12];
    working_state[13] += initial_state[13];
    working_state[14] += initial_state[14];
    working_state[15] += initial_state[15];

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
pub fn mbedtls_chacha20_setkey(ctx:&mut mbedtls_chacha20_context,key:[char;32])->i32{
    
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

pub fn mbedtls_chacha20_starts(ctx:&mut mbedtls_chacha20_context,nonce:[char;12],counter:u32)->i32{
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
            input:String,output:&mut String)->i32
{
    if size==0 || size!=input.chars().count(){
        return MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;
    }
    let mut offset:usize=0;
    let mut res:String=String::from("");
    let mut inpchars=input.chars();
    while size>0 && (*ctx).keystream_bytes_used < CHACHA20_BLOCK_SIZE_BYTES {
        let out:char;
        let inp:char=inpchars.nth(offset).unwrap();
        out=((inp as u8)^((*ctx).keystream8[(*ctx).keystream_bytes_used] as u8))as char;
        res.push(out);
        offset+=1;
        size-=1;
    }

    while size >= CHACHA20_BLOCK_SIZE_BYTES
    {
        /* Generate new keystream block and increment counter */
        chacha20_block( &mut (*ctx).state, &mut (*ctx).keystream8 );
        (*ctx).state[CHACHA20_CTR_INDEX]+=1;
        for i in (0..64).step_by(8){
            let mut out:char;
            out=((inpchars.nth(offset+i).unwrap() as u8)^((*ctx).keystream8[i] as u8))as char;
            res.push(out);
            out=((inpchars.nth(offset+i+1).unwrap() as u8)^((*ctx).keystream8[i+1] as u8))as char;
            res.push(out);
            out=((inpchars.nth(offset+i+2).unwrap() as u8)^((*ctx).keystream8[i+2] as u8))as char;
            res.push(out);
            out=((inpchars.nth(offset+i+3).unwrap() as u8)^((*ctx).keystream8[i+3] as u8))as char;
            res.push(out);
            out=((inpchars.nth(offset+i+4).unwrap() as u8)^((*ctx).keystream8[i+4] as u8))as char;
            res.push(out);
            out=((inpchars.nth(offset+i+5).unwrap() as u8)^((*ctx).keystream8[i+5] as u8))as char;
            res.push(out);
            out=((inpchars.nth(offset+i+6).unwrap() as u8)^((*ctx).keystream8[i+6] as u8))as char;
            res.push(out);
            out=((inpchars.nth(offset+i+7).unwrap() as u8)^((*ctx).keystream8[i+7] as u8))as char;
            res.push(out);
        }
        offset += CHACHA20_BLOCK_SIZE_BYTES;
        size   -= CHACHA20_BLOCK_SIZE_BYTES;
    }
    if size > 0{
        /* Generate new keystream block and increment counter */
        chacha20_block( &mut (*ctx).state, &mut (*ctx).keystream8 );
        (*ctx).state[CHACHA20_CTR_INDEX]+=1;
        for i in 0..size{
            let out:char;
            out=((inpchars.nth(offset+i).unwrap() as u8)^((*ctx).keystream8[i] as u8))as char;
            res.push(out);
        }
        (*ctx).keystream_bytes_used = size;
    }
    *output=res;
    return 0;
}

pub fn mbedtls_chacha20_crypt(key:[char;32],
    nonce:[char;12],counter:u32,data_len:usize,
    input:String,output:&mut String)->i32
{

    let mut ctx:mbedtls_chacha20_context=mbedtls_chacha20_context{
        state:[0;16],
        keystream8:[0;64],
        keystream_bytes_used:0
    };
    let mut ret:i32=MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if data_len==0 || data_len!=input.chars().count(){
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


pub fn test1(mut k:u32){
    k=k+1;
}
pub fn run()
{
    println!("hmm");
    let k:u32=100;
    println!("{}",ROTL32(k, 2));
    println!("{}",k);
    test1(k);
    println!("{}",k);
}