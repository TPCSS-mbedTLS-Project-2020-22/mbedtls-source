use std::convert::TryInto;
use std::convert::TryFrom;
use std::ptr;

use crate::poly1305h::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
use crate::poly1305h::MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA; 
use crate::poly1305h::MBEDTLS_ERR_POLY1305_FEATURE_UNAVAILABLE; 
use crate::poly1305h::MBEDTLS_ERR_POLY1305_HW_ACCEL_FAILED; 
use crate::poly1305h::POLY1305_BLOCK_SIZE_BYTES;
use crate::poly1305h::mbedtls_poly1305_context;

pub fn BYTES_TO_U32_LE(data:[u8;32], offset:usize) -> u32 {
    let mut ret : u32 =0;
    ret =  u32::from((data)[offset])|                               
        u32::from(data[( offset ) + 1])  << 8  |
        u32::from(data[( offset ) + 2])  << 16  |
        u32::from(data[( offset ) + 3])  << 24 ;
    return ret;
  
}

pub fn BYTES_TO_U32_LE2(data:&mut [u8], offset:usize) -> u32 {
    let mut ret : u32 =0;
    ret =  u32::from((data)[offset])|                               
        u32::from(data[( offset ) + 1])  << 8  |
        u32::from(data[( offset ) + 2])  << 16  |
        u32::from(data[( offset ) + 3])  << 24 ;
    return ret;
  
}

pub fn mul64( a:u32, b: u32 ) -> u64
{
   let mut ret :u64 =  u32::wrapping_mul(a,b) as u64;
   return ret;
}


pub fn poly1305_process(ctx:&mut mbedtls_poly1305_context, nblocks:usize, mut input:&mut [u8], needs_padding:u32 , k:usize)
{
  let mut d0: u64;
  let mut d1: u64;
  let mut d2: u64;
  let mut d3: u64;
  let mut acc0: u32;
  let mut acc1: u32;
  let mut acc2: u32;
  let mut acc3: u32;
  let mut acc4: u32;
  let mut r0: u32;
  let mut r1: u32;
  let mut r2: u32;
  let mut r3: u32;
  let mut rs1: u32;
  let mut rs2: u32;
  let mut rs3: u32;
  let mut offset :usize = 0;
  let mut i: usize = 0;

  r0 = (*ctx).r[0];
  r1 = (*ctx).r[1];
  r2 = (*ctx).r[2];
  r3 = (*ctx).r[3];

  rs1 = r1 + ( r1 >> 2);
  rs2 = r2 + ( r2 >> 2);
  rs3 = r3 + ( r3 >> 2);

  acc0 = (*ctx).acc[0];
  acc1 = (*ctx).acc[1];
  acc2 = (*ctx).acc[2];
  acc3 = (*ctx).acc[3];
  acc4 = (*ctx).acc[4];

  for i in 0..nblocks{
      d0   = BYTES_TO_U32_LE2(&mut input, (offset +k + 0)) as u64;
      d1   = BYTES_TO_U32_LE2(&mut input, (offset +k + 4)) as u64;
      d2   = BYTES_TO_U32_LE2(&mut input, (offset +k + 8)) as u64;
      d3   = BYTES_TO_U32_LE2(&mut input, (offset +k + 12)) as u64;

      d0  +=  acc0 as u64;
      d1  += (acc1 as u64) +  d0 >> 32 ;
      d2  += (acc2 as u64) +  d1 >> 32 ;
      d3  += (acc3 as u64) +  d2 >> 32;
      acc0 = d0 as u32;
      acc1 = d1 as u32;
      acc2 = d2 as u32;
      acc3 = d3 as u32;
      acc4 += ( d3 >> 32 ) as u32 + needs_padding;

      d0 = mul64( acc0, r0  ) + mul64( acc1, rs3 ) + mul64( acc2, rs2 ) + mul64( acc3, rs1 );
      d1 = mul64( acc0, r1  ) + mul64( acc1, r0  ) + mul64( acc2, rs3 ) + mul64( acc3, rs2 ) + mul64( acc4, rs1 );
      d2 = mul64( acc0, r2  ) + mul64( acc1, r1  ) + mul64( acc2, r0  ) + mul64( acc3, rs3 ) + mul64( acc4, rs2 );
      d3 = mul64( acc0, r3  ) + mul64( acc1, r2  ) + mul64( acc2, r1  ) + mul64( acc3, r0  ) + mul64( acc4, rs3 );
      acc4 *= r0;

      d1 +=  d0 >> 32 ;
      d2 +=  d1 >> 32 ;
      d3 +=  d2 >> 32 ;
      acc0 = d0 as u32;
      acc1 = d1 as u32;
      acc2 = d2 as u32;
      acc3 = d3 as u32;
      acc4 = ( d3 >> 32 ) as u32 + acc4;

      d0 = acc0 as u64 + ( acc4 >> 2 ) as u64 + ( acc4 & 0xFFFFFFFC ) as u64;
      acc4 &= 3;
      acc0 = d0 as u32;
      d0 = acc1 as u64 +  d0 >> 32 ;
      acc1 =  d0 as u32;
      d0 = acc2  as u64 + d0 >> 32;
      acc2 = d0 as u32;
      d0 = acc3 as u64 +  d0 >> 32 ;
      acc3 = d0 as u32;
      d0 = acc4 as u64 +  d0 >> 32 ;
      acc4 = d0 as u32;

      offset    += POLY1305_BLOCK_SIZE_BYTES;
  }

  (*ctx).acc[0] = acc0;
  (*ctx).acc[1] = acc1;
  (*ctx).acc[2] = acc2;
  (*ctx).acc[3] = acc3;
  (*ctx).acc[4] = acc4;
}



pub fn poly1305_compute_mac(ctx: &mut mbedtls_poly1305_context, mut mac: &mut [u8;16] )
{
  let mut d: u64;
  let mut g0:u32;
  let mut g1:u32;
  let mut g2:u32;
  let mut g3:u32;
  let mut g4:u32;
  let mut acc0:u32;
  let mut acc1:u32;
  let mut acc2:u32;
  let mut acc3:u32;
  let mut acc4:u32;
  let mut mask: u32;
  let mut mask_inv:u32;

  acc0 = (*ctx).acc[0];
  acc1 = (*ctx).acc[1];
  acc2 = (*ctx).acc[2];
  acc3 = (*ctx).acc[3];
  acc4 = (*ctx).acc[4];


  d  = (acc0 as u64 + 5 as u64 );
  g0 = d as u32; 
  d  = (acc1 as u64 +  d >> 32 );
  g1 = d as u32;
  d  = (acc2 as u64 +  d >> 32 );
  g2 = d as u32;
  d  = (acc3 as u64 +  d >> 32 );
  g3 = d as u32;
  g4 = acc4 + ( d >> 32 ) as u32;

  mask = 0 as u32 - ( g4 >> (2 as u32));
  mask_inv = !mask;


  acc0 = ( acc0 & mask_inv ) | ( g0 &mask );
  acc1 = ( acc1 & mask_inv ) | ( g1 & mask );
  acc2 = ( acc2 & mask_inv ) | ( g2 & mask );
  acc3 = ( acc3 & mask_inv ) | ( g3 & mask );

  d = acc0 as u64 + (*ctx).s[0] as u64;
  acc0 = d as u32;
  d = acc1 as u64 + (*ctx).s[1] as u64 + ( d >> (32 as u64));
  acc1 = d as u32;
  d = acc2  as u64 + (*ctx).s[2] as u64 + ( d >> (32 as u64 ));
  acc2 = d as u32;
  acc3 += (*ctx).s[3] + ( d >> 32 ) as u32;


  mac[ 0] =  acc0 as u8;
  mac[ 1] = ( acc0 >> 8 ) as u8;
  mac[ 2] = ( acc0 >> 16 ) as u8;
  mac[ 3] = ( acc0 >> 24 ) as u8;
  mac[ 4] = ( acc1       ) as u8;
  mac[ 5] = ( acc1 >>  8 ) as u8;
  mac[ 6] = ( acc1 >> 16 ) as u8;
  mac[ 7] = ( acc1 >> 24 ) as u8;
  mac[ 8] = ( acc2       ) as u8;
  mac[ 9] = ( acc2 >>  8 ) as u8;
  mac[10] = ( acc2 >> 16 ) as u8;
  mac[11] = ( acc2 >> 24 ) as u8;
  mac[12] = ( acc3       ) as u8;
  mac[13] = ( acc3 >>  8 ) as u8;
  mac[14] = ( acc3 >> 16 ) as u8;
  mac[15] = ( acc3 >> 24 ) as u8;
}


pub fn  mbedtls_poly1305_init(ctx: &mut mbedtls_poly1305_context)
{
  unsafe{
      ptr::write_bytes(ctx, 0, 1);
  }
}

pub fn mbedtls_poly1305_free(ctx: &mut mbedtls_poly1305_context)
{
  unsafe{
      ptr::write_bytes(ctx, 0, 1);
  }
}


pub fn mbedtls_poly1305_starts( ctx: &mut mbedtls_poly1305_context, key:[u8;32] ) -> i32
{

  (*ctx).r[0] = BYTES_TO_U32_LE( key, 0 )  & 0x0FFFFFFF;
  (*ctx).r[1] = BYTES_TO_U32_LE( key, 4 )  & 0x0FFFFFFC;
  (*ctx).r[2] = BYTES_TO_U32_LE( key, 8 )  & 0x0FFFFFFC;
  (*ctx).r[3] = BYTES_TO_U32_LE( key, 12 ) & 0x0FFFFFFC;

  (*ctx).s[0] = BYTES_TO_U32_LE( key, 16 );
  (*ctx).s[1] = BYTES_TO_U32_LE( key, 20 );
  (*ctx).s[2] = BYTES_TO_U32_LE( key, 24 );
  (*ctx).s[3] = BYTES_TO_U32_LE( key, 28 );

  (*ctx).acc[0] = 0 as u32;
  (*ctx).acc[1] = 0 as u32;
  (*ctx).acc[2] = 0 as u32;
  (*ctx).acc[3] = 0 as u32;
  (*ctx).acc[4] = 0 as u32;

  (*ctx).queue = [0;16];
  (*ctx).queue_len = 0 as usize;
  return( 0 );
}


pub fn mbedtls_poly1305_update(ctx: &mut mbedtls_poly1305_context,mut input: &mut [u8], ilen:u8 )-> i32
{
  let mut offset	: usize = 0;
  let mut remaining:usize  = ilen as usize;
  let mut queue_free_len: usize;
  let mut nblocks: usize;
  let mut dummy:[u8;16] = [0;16];
  for i in 0..16{
    dummy[i as usize] = (*ctx).queue[i as usize];
  }

  if(  remaining > 0 &&  (*ctx).queue_len > 0 )
  {
      queue_free_len = ( POLY1305_BLOCK_SIZE_BYTES - (*ctx).queue_len );

      if( (ilen as usize) < queue_free_len )
      {
          for i in 0..ilen{
            (*ctx).queue[(*ctx).queue_len+i as usize] = input[i as usize];

          } 
          (*ctx).queue_len += ilen as usize;

          remaining = 0;
      }
      else
      {
          for i in 0..queue_free_len{
            (*ctx).queue[(*ctx).queue_len+i as usize] = input[i as usize];

          } 

          (*ctx).queue_len = 0;

          poly1305_process(  ctx, 1, &mut dummy, 1 ,offset);

          offset    += queue_free_len;
          remaining -= queue_free_len;
      }
  }

  if( remaining >= POLY1305_BLOCK_SIZE_BYTES )
  {
      nblocks = remaining / POLY1305_BLOCK_SIZE_BYTES;

      poly1305_process(ctx, nblocks, &mut input, 1 , offset);

      offset += nblocks * POLY1305_BLOCK_SIZE_BYTES;
      remaining %= POLY1305_BLOCK_SIZE_BYTES;
  }

  if( remaining > 0 )
  {
      (*ctx).queue_len = remaining;
      unsafe{
        ptr::write_bytes( &mut (*ctx).queue, input[offset], remaining );
      }
      
  }

  return( 0 );
}


pub fn mbedtls_poly1305_finish(ctx: &mut mbedtls_poly1305_context , mut mac:&mut [u8;16] )-> i32
{
  let mut borrow_ctx:[u8;16] = [0;16];
  for i in 0..16{
      borrow_ctx[i as usize] = (*ctx).queue[i as usize];
  }
  if( (*ctx).queue_len > 0 )
  {
      (*ctx).queue[(*ctx).queue_len] = 1;
      (*ctx).queue_len = (*ctx).queue_len + 1;

      unsafe{
          ptr::write_bytes(&mut (*ctx).queue[(*ctx).queue_len-1], 0, POLY1305_BLOCK_SIZE_BYTES - (*ctx).queue_len );
      }
      poly1305_process( ctx, 1, &mut borrow_ctx, 0, 0 ); 

  }
  poly1305_compute_mac( ctx, &mut mac );
  return( 0 );
}

pub fn mbedtls_poly1305_mac( key:[u8;32], mut input:& mut[u8], ilen : u8,mut  mac: &mut [u8;16])->i32
{
  let mut ctx: mbedtls_poly1305_context = mbedtls_poly1305_context{
        r:[0; 4],     
        s:[0; 4],     
        acc:[0; 5],   
        queue:[0; 16], 
        queue_len:0  
  };
  let mut ret:i32  = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

  mbedtls_poly1305_init( &mut ctx );
  ret = mbedtls_poly1305_starts( &mut ctx, key );
  if ret!= 0{
	  mbedtls_poly1305_free( &mut ctx );
	  return ret;
  }
  println!("{}", " ");
  ret = mbedtls_poly1305_update( &mut ctx, &mut input, ilen );
  if ret!= 0{
	  mbedtls_poly1305_free( &mut ctx );
	  return ret;
  }
  ret = mbedtls_poly1305_finish( &mut ctx, &mut mac );
  println!("{}", " ");

  mbedtls_poly1305_free( &mut ctx );

  return( ret );
}


pub const test_keys:[[u8; 32];2] =
[
  [
      0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
      0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
      0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
      0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
  ],
  [
      0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
      0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
      0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
      0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0
  ]
];


pub const test_data:[[u8;127];2] =
[
  [
      0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
      0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
      0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
      0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
      0x75, 0x70, 0x77, 0x61, 0x73, 0x20, 0x62, 0x72,
      0x69, 0x6c, 0x6c, 0x69, 0x67, 0x2c, 0x20, 0x61,
      0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
      0x6c, 0x69, 0x74, 0x68, 0x79, 0x20, 0x74, 0x6f,
      0x76, 0x65, 0x73, 0x0a, 0x44, 0x69, 0x64, 0x20,
      0x67, 0x79, 0x72, 0x65, 0x20, 0x61, 0x6e, 0x64,
      0x20, 0x67, 0x69, 0x6d, 0x62, 0x6c, 0x65, 0x20,
      0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77,
      0x61, 0x62, 0x65, 0x3a, 0x0a, 0x41, 0x6c, 0x6c,
      0x20, 0x6d, 0x69, 0x6d, 0x73, 0x79, 0x20, 0x77,
      0x65, 0x72, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
      0x62, 0x6f, 0x72, 0x6f, 0x67, 0x6f, 0x76
  ],
  [
      0x27, 0x54, 0x77, 0x61, 0x73, 0x20, 0x62, 0x72,
      0x69, 0x6c, 0x6c, 0x69, 0x67, 0x2c, 0x20, 0x61,
      0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
      0x6c, 0x69, 0x74, 0x68, 0x79, 0x20, 0x74, 0x6f,
      0x76, 0x65, 0x73, 0x0a, 0x44, 0x69, 0x64, 0x20,
      0x67, 0x79, 0x72, 0x65, 0x20, 0x61, 0x6e, 0x64,
      0x20, 0x67, 0x69, 0x6d, 0x62, 0x6c, 0x65, 0x20,
      0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77,
      0x61, 0x62, 0x65, 0x3a, 0x0a, 0x41, 0x6c, 0x6c,
      0x20, 0x6d, 0x69, 0x6d, 0x73, 0x79, 0x20, 0x77,
      0x65, 0x72, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
      0x62, 0x6f, 0x72, 0x6f, 0x67, 0x6f, 0x76, 0x65,
      0x73, 0x2c, 0x0a, 0x41, 0x6e, 0x64, 0x20, 0x74,
      0x68, 0x65, 0x20, 0x6d, 0x6f, 0x6d, 0x65, 0x20,
      0x72, 0x61, 0x74, 0x68, 0x73, 0x20, 0x6f, 0x75,
      0x74, 0x67, 0x72, 0x61, 0x62, 0x65, 0x2e
  ]
];

pub const test_data_len:[u8;2] =[127, 127];

pub const test_mac:[[u8;16]; 2] =
[
  [
      0x3a, 0x97, 0xfa, 0xcd, 0xfb, 0xd, 0xb2, 0xfd, 
      0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
  ],
  [
      0x85, 0xe6, 0xa9, 0xa5, 0x42, 0x2b, 0x80, 0x9, 
      0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0
  ]
];

pub fn run(){
    let mut ret : i32 = 0;
    let mut mac: [u8; 16] = [0; 16];
    for i in 0..2{
      mac = [0; 16];
      ret = mbedtls_poly1305_mac( test_keys[i], &mut test_data[i], test_data_len[i], &mut  mac );
      if ret!=0{
        println!("error code {}", ret);
      }
      println!("Calculated mac is {:x?}", mac);
      if mac == test_mac[i]{
          println!("passed");
      }
      else{
          println!("failed");
      }
    }
}