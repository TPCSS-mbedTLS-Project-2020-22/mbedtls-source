pub mod padlock;

use padlock::MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED;
use padlock::MBEDTLS_PADLOCK_ALIGN16;
use padlock::mbedtls_aes_context;

// pub const MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED: i32= -0x0030;
// pub const MBEDTLS_PADLOCK_RNG: usize= 0x000C;
// pub const MBEDTLS_PADLOCK_ACE: usize= 0x00C0;
// pub const MBEDTLS_PADLOCK_PHE: usize= 0x0C00;
// pub const MBEDTLS_PADLOCK_PMM: usize= 0x3000;
//use std::ptr;

use std::convert::TryInto;

fn main(){
    unimplemented!();
}
pub fn padlock_has_support(feature: i32 )->i32
{
    let flags: i32 = -1;
    let ebx: i32 = 0;
    let edx: i32 = 0;

    if flags == -1 
    {
        //#![feature(asm)]
        unsafe{
        asm!( "movl  %%ebx, %0           \n\t",
             "movl  $0xC0000000, %%eax  \n\t",
             "cpuid                     \n\t",
             "cmpl  $0xC0000001, %%eax  \n\t",
             "movl  $0, %%edx           \n\t",
             "jb    1f                  \n\t",
             "movl  $0xC0000001, %%eax  \n\t",
             "cpuid                     \n\t",
             "1:                        \n\t",
             "movl  %%edx, %1           \n\t",
             "movl  %2, %%ebx           \n\t",
             :"=m" (ebx), "=m" (edx)
               "m" (ebx)
              "eax", "ecx", "edx" );

            }   flags = edx;
    }

    return flags & feature ;
}

pub fn mbedtls_padlock_xcryptecb( ctx: &mut mbedtls_aes_context,
    mode: i32,
    mut input: [u8;16], mut output : &mut [u8;16] ) -> i32
{
let mut ebx: i32 = 0;
let rk: &mut u32;
let blk: *mut u32;
let ctrl: *mut u32;
let mut iptr : usize = 0;
let mut buf: &mut [u8;256];

rk  = &mut ctx.rk;
blk = MBEDTLS_PADLOCK_ALIGN16( buf);
//memcpy( blk, input, 16 );
let mut ptr: usize;

    for i in 0..16
    {
        unsafe
        {
             *blk.offset(i) = input[i as usize].into();

        }
    
    }

     ctrl = blk.add(4);
    *ctrl = 0x80 | ctx.nr | ( ( ctx.nr + ( mode^1 ) - 10 ) << 9  as u32).try_into().unwrap();

    asm!(   "pushfl                        \n\t",
            "popfl                         \n\t",
            "movl    %%ebx, %0             \n\t",
            "movl    $1, %%ecx             \n\t",
            "movl    %2, %%edx             \n\t",
            "movl    %3, %%ebx             \n\t",
            "movl    %4, %%esi             \n\t",
            "movl    %4, %%edi             \n\t",
            ".byte  0xf3,0x0f,0xa7,0xc8    \n\t",
            "movl    %1, %%ebx             \n\t"
            : "=m" (ebx)
            :  "m" (ebx), "m" (ctrl), "m" (rk), "m" (blk)
            : "memory", "ecx", "edx", "esi", "edi" );


    for i in 0..16
    {
        unsafe
        {
            output[i] = *blk.offset(i.try_into().unwrap()) as u8;

        }
    
    }

    return 0 ;
}


pub fn padlock_xcryptcbc( mut ctx : &mut mbedtls_aes_context,
                        mode:i32,
                        iv:&mut [u8;16],
                        mut length :usize,
                        mut input: &[u8], 
                        mut output :&mut [u8])->i32
{
    let mut ebx: i32 = 0;
    let rk: &mut u32;
    let iw: *mut u32;
    let blk: *mut u32;
    let ctrl: *mut u32;
    let count: usize;
    let mut iptr : usize = 0;
    let mut buf:&mut [u8;256];

    if ( input as &mut _ as  i64 & 15 ) != 0 || ( (output as &mut _ as  i64 & 15 ) != 0 )
        {
            return MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED; 
        }


    rk = &mut ctx.rk;
    iw = MBEDTLS_PADLOCK_ALIGN16( buf );

    for i in 0..16
    {
        unsafe
        {
             *iw.offset(i) = iv[i as usize].into();

        }
    
    }

    ctrl = iw.add(4);
    *ctrl = 0x80 | ctx.nr | ( ( ctx.nr + ( mode ^ 1 ) - 10 ) << 9 as u32).try_into().unwrap();

    count =( length + 15 ) >> 4;

    asm!( "pushfl                        \n\t",
         "popfl                         \n\t",
         "movl    %%ebx, %0             \n\t",
         "movl    %2, %%ecx             \n\t",
         "movl    %3, %%edx             \n\t",
         "movl    %4, %%ebx             \n\t",
         "movl    %5, %%esi             \n\t",
         "movl    %6, %%edi             \n\t",
         "movl    %7, %%eax             \n\t",
         ".byte  0xf3,0x0f,0xa7,0xd0    \n\t",
         "movl    %1, %%ebx             \n\t"
         : "=m" (ebx)
         :  "m" (ebx), "m" (count), "m" (ctrl),
            "m"  (rk), "m" (input), "m" (output), "m" (iw)
         : "memory", "eax", "ecx", "edx", "esi", "edi" );


         for i in 0..16
    {
        unsafe
        {
             iv[i] = *iw.offset(i.try_into().unwrap()) as u8;

        }
    
    }
    return 0;
}

