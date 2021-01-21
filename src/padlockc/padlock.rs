use std::convert::TryFrom;

pub const MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED: i32= -0x0030;
pub const MBEDTLS_PADLOCK_RNG: usize= 0x000C;
pub const MBEDTLS_PADLOCK_ACE: usize= 0x00C0;
pub const MBEDTLS_PADLOCK_PHE: usize= 0x0C00;
pub const MBEDTLS_PADLOCK_PMM: usize= 0x3000;

pub fn MBEDTLS_PADLOCK_ALIGN16(x: &mut [u8;256])-> &mut u32 
{
    let mut y: i32;
    let mut r: &mut u32;
    y = 16 + (&x as *const _ as i32) & !15;
   
    r = &mut u32::try_from(y).unwrap() ;
     //y= 16 + (*x & !15);
     //x= &mut [u8..]
     return r;
}     


pub struct mbedtls_aes_context
{
    pub nr: i32,                    
    pub rk:  u32,              
    pub buf: [char;68],          
}                                   

