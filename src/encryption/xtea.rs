#![allow(dead_code)]
use crate::encryption::MBEDTLS_XTEA_ENCRYPT;
use crate::encryption::MbedtlsXteaContext;
use crate::encryption::MBEDTLS_XTEA_DECRYPT;
use crate::encryption::MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH;
use std::convert::TryFrom;


fn get_uint32_be(n: &mut Wrapping<u32>, b: &[u8], i:usize){    
    *n= Wrapping(u32::from(b[i])<<24 |
            u32::from(b[i+1])<<16 |
            u32::from(b[i+2])<<8 |
            u32::from(b[i+3]));
}   
 
fn put_uint32_be(n: &mut Wrapping<u32>, b: &mut[u8], i:usize){
    b[i] = u8::try_from((*n>>24).0 & 0xFF).unwrap();
    b[i+1] = u8::try_from((*n>>16).0 & 0xFF).unwrap();
    b[i+2] = u8::try_from((*n>>8).0 & 0xFF).unwrap();
    b[i+3] = u8::try_from(n.0 & 0xFF).unwrap();
}

pub fn mbedtls_xtea_init(ctx: &mut MbedtlsXteaContext )
{
    ctx.k = [0u32; 4];
}

// was part of plaform_utils.c 
fn mbedtls_platfrom_zeroize(v:&mut [u32]){
    for i in &mut v.iter_mut(){
        *i=0u32;
    }
}

pub fn mbedtls_xtea_free(ctx: &mut MbedtlsXteaContext){
    mbedtls_platfrom_zeroize(&mut ctx.k);
}

/*
 * XTEA key schedule
 */
pub fn mbedtls_xtea_setup(ctx: &mut MbedtlsXteaContext, key: &[u8])
{
    // let mut i: i32=0;

    ctx.k = [0u32; 4];

    for i in 0..4
    {
        get_uint32_be(&mut Wrapping(ctx.k[i]),  key, i<<2);
    }
}

use std::num::Wrapping;

pub fn mbedtls_xtea_crypt_ecb(ctx:&mut MbedtlsXteaContext, mode: i32,
                    mut  input: &mut [u8], mut output: &mut [u8])->i32
{
    // let (mut k, mut v0, mut v1, mut i):(&u32, u32, u32, u32);
    let ( mut v0, mut v1)=(Wrapping(0u32), Wrapping(0u32));
    let k = [Wrapping(ctx.k[0]), Wrapping(ctx.k[1]), Wrapping(ctx.k[2]), Wrapping(ctx.k[3])];

    get_uint32_be(&mut v0, &mut input, 0);
    
    get_uint32_be(&mut v1, &mut input, 4);

    use std::convert::TryInto;
    if mode == super::MBEDTLS_XTEA_ENCRYPT.try_into().unwrap()
    {
        let mut sum =Wrapping(0u32);
        let delta:Wrapping<u32> = Wrapping(0x9E3779B9);

        for _i in 0..32
        {
            // let mut val=;
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[(sum.0 & 3) as usize]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[((sum.0>>11) & 3) as usize]);
        }
    }
    else /* MBEDTLS_XTEA_DECRYPT */
    {
        let delta:Wrapping<u32> = Wrapping(0x9E3779B9);
        let num_rounds=Wrapping(32);
        let mut sum =delta*num_rounds;
        
        for _i in 0..32
        {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[((sum.0>>11) & 3) as usize]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[(sum.0 & 3) as usize]);
        }
    }

    put_uint32_be(&mut v0, &mut output, 0);
    put_uint32_be( &mut v1, &mut output, 4);

    return 0 ;
}
/*
 * XTEA-CBC buffer encryption/decryption
 */
fn mbedtls_xtea_crypt_cbc( ctx : &mut MbedtlsXteaContext, 
                           mode : i32, 
                           mut length : usize,
                           iv : &mut [u8;8], 
                           input : &[u8], 
                           output : &mut [u8]) -> i32
{
    let mut temp = [0u8; 8];
    if length % 8 != 0{ 
        return MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH;
    }

    if mode == MBEDTLS_XTEA_DECRYPT {
        let mut j:u32=0;
        let mut a:u32;
        let mut b:u32;
        while length > 0 
            //memcpy( temp, input, 8 );
        {   
            a=8*j;
            b=8*(j+1);
            temp.copy_from_slice(&input[a as usize..b as usize]);

            let mut input_bytes =[0u8;16];
            let mut output_bytes =[0u8;16];
            input_bytes.copy_from_slice(&input[a as usize..b as usize]);
            output_bytes.copy_from_slice(&output[a as usize..b as usize]);
            
            mbedtls_xtea_crypt_ecb( ctx, mode, &mut input_bytes, &mut output_bytes );
            output[a as usize..b as usize].copy_from_slice(&output_bytes);

            for i in 0..8 {
                { output[i as usize] = u8::try_from( output[i as usize] ^ iv[i as usize] ).unwrap(); }


            iv.copy_from_slice(&temp);

            length = length - 8;
            j += 1;
            }
        }
    }
    else
    {
        let mut j:u32=0;
        let mut a:u32;
        let mut b:u32;
        while length > 0 {
            for i in 0..8 {
                 output[i as usize] = u8::try_from( input[i as usize] ^ iv[i as usize] ).unwrap();
            }

            //mbedtls_xtea_crypt_ecb( ctx, mode, output, output );
            //memcpy( iv, output, 8 );
            a=8*j;
            b=8*(j+1);

            let mut output_bytes1 =[0u8;16];
            let mut output_bytes2 =[0u8;16];
            output_bytes1.copy_from_slice(&output[a as usize..b as usize]);
            output_bytes2.copy_from_slice(&output[a as usize..b as usize]);
            mbedtls_xtea_crypt_ecb( ctx, mode, &mut output_bytes1, &mut output_bytes2 );
            output[a as usize..b as usize].copy_from_slice(&output_bytes2);
            iv.copy_from_slice(&output[a as usize..b as usize]);

            j += 1;
            length = length - 8;
        }
    }

    return 0 ;
}
/*
 * XTEA tests vectors (non-official)
 */

pub const XTEA_TEST_KEY:[[u8;16];6] =
[
   [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
     0x0c, 0x0d, 0x0e, 0x0f ],
   [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f ],
   [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f ],
   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00 ],
   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00 ],
   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00 ]
];

pub const XTEA_TEST_PT:[[u8;8];6] =
[
    [ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 ],
    [ 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 ],
    [ 0x5a, 0x5b, 0x6e, 0x27, 0x89, 0x48, 0xd7, 0x7f ],
    [ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 ],
    [ 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 ],
    [ 0x70, 0xe1, 0x22, 0x5d, 0x6e, 0x4e, 0x76, 0x55 ]
];

pub const XTEA_TEST_CT:[[u8;8];6] =
[
    [ 0x49, 0x7d, 0xf3, 0xd0, 0x72, 0x61, 0x2c, 0xb5 ],
    [ 0xe7, 0x8f, 0x2d, 0x13, 0x74, 0x43, 0x41, 0xd8 ],
    [ 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 ],
    [ 0xa0, 0x39, 0x05, 0x89, 0xf8, 0xb8, 0xef, 0xa5 ],
    [ 0xed, 0x23, 0x37, 0x5a, 0x82, 0x1a, 0x8c, 0x2d ],
    [ 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 ]
];

/*
 * Checkup routine
 */
 #[test]
pub fn mbedtls_xtea_self_test(  )
{
    let _i:usize;
    let _ret:i32 = 0;
    let mut buf =[0u8;8];
    let mut ctx=MbedtlsXteaContext{
        k: [0u32; 4]
    };

    mbedtls_xtea_init( &mut ctx );
    
    for i in 0..6
    {
        buf.copy_from_slice(&XTEA_TEST_PT[i]);

        mbedtls_xtea_setup( &mut ctx, &XTEA_TEST_KEY[i] );
        use std::convert::TryInto;
        let mut dummy_buf =[0u8;8];
        mbedtls_xtea_crypt_ecb( &mut ctx, MBEDTLS_XTEA_ENCRYPT.try_into().unwrap(), &mut buf, &mut dummy_buf );
        buf.copy_from_slice(&dummy_buf[0..]);
    }
}
