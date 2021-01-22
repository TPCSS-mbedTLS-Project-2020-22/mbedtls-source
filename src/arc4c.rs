pub mod arc4;

//use std::ptr::copy_nonoverlapping;
use crate::arc4::MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED;
//use std::convert::TryInto;
use std::ptr::write_bytes;
//use std::convert::TryFrom;
use arc4::mbedtls_arc4_context;





pub fn mbedtls_arc4_init(ctx : &mut mbedtls_arc4_context)
{
   unsafe
   {
    write_bytes(ctx,0,1);
   }
}
pub fn mbedtls_arc4_free(ctx: &mut mbedtls_arc4_context){
    unsafe
    {
     write_bytes(ctx,0,1);
    }
}
 
pub fn mbedtls_arc4_setup( ctx : &mut mbedtls_arc4_context, key:&[u8],keylen: u32)
{
 
    let mut j;
    let mut a : u32;
    let mut k;
   
    let m : &mut [u8;256];
    ctx.x = 0;
    ctx.y = 0;

    m=&mut ctx.m;
     for i in 0..256 
    {
       m[i] = i as u8; 
       
    }
    let mut i: usize =0 ;
    j = 0;
    k=0;
    while i < 256 {
        if  k >= keylen {k = 0;}
         
        a =m[i] as u32;
        
       j = (j + a + key[k as usize]as u32) & 0xFF;
         
        m[i] = m[j as usize];
        m[j as usize] = a as u8;
        i+=1;
        k+=1;
        
        }

}
 pub fn mbedtls_arc4_crypt(ctx : &mut mbedtls_arc4_context,length : usize,input:&mut [u8], output :&mut [u8] ) -> i32{
 
     let mut x;
     let mut y;
     let mut a;
     let mut b;
     let  m :&mut [u8];
    
     x = ctx.x ;
     y = ctx.y ;
     m = &mut ctx.m;
     
     for i in 0..length
     {
         x = ( x + 1 ) & 0xFF; 
         a  =m[x as usize] as i32;
         y = ( y + a ) & 0xFF; 
         b =m[y as usize] as i32;
         m[x as usize] =b as u8;
         m[y as usize] = a as u8;
         output [i] = (input[i] ^ m[((a + b)as u8) as usize ])as u8;
        
     }
     ctx.x = x ;
     ctx.y = y;
     return 0;
 }

