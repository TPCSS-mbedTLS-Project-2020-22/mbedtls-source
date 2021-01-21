use crate::hashing;
use crate::error;
use hashing::hmac;
use hashing::setup;
use hashing::get_size;
use hashing:: free;
use std::io::Write;
use std::convert::TryInto;


fn zeroize(a: &mut Vec<u8>){
    for i in &mut a.iter_mut(){
        *i = 0;
    }
}

pub fn hkdf( md: &'static hashing:: MdInfoT , salt :&Vec<u8>, salt_len: usize, ikm :&Vec<u8>, ikm_len: usize, info :&Vec<u8>, info_len: usize, mut okm :&mut Vec<u8>, okm_len: usize) -> i32 {

    let mut ret:i32 = error:: ERR_ERROR_CORRUPTION_DETECTED;
    let mut prk = vec![0; hashing::MD_MAX_SIZE] ;

    ret = hkdf_extract(md, salt, salt_len, ikm,  ikm_len, &mut prk);

    if ret == 0 {
        ret = hkdf_expand(md, &mut prk, md.size as usize, info, info_len, &mut okm, okm_len);
    }
    zeroize(&mut prk);
    return ret;
}

fn hkdf_extract( md: &'static hashing:: MdInfoT , salt :&Vec<u8>, salt_len: usize, ikm :&Vec<u8>, ikm_len: usize,mut prk :&mut Vec<u8> )-> i32{
    
    let null_salt = vec![0; hashing:: MD_MAX_SIZE];

    if salt.is_empty() {
        
        let hash_len: usize;

        if salt_len != 0 {
            return hashing::ERR_MD_BAD_INPUT_DATA; }
         
        hash_len = md.size as usize;

        if hash_len == 0 {
            return hashing::ERR_MD_BAD_INPUT_DATA; }

        let salt = &null_salt;
        let salt_len = hash_len;
        
    }

    
    return hmac(md, salt, salt_len, ikm, ikm_len, &mut prk);

}


fn hkdf_expand( md: &'static hashing:: MdInfoT , prk :&Vec<u8>, prk_len: usize, info :&Vec<u8>, info_len: usize, okm :&mut Vec<u8>, okm_len :usize)->i32{

    let hash_len: usize;
    let mut where_ : usize = 0;
    let mut n :usize ;
    let mut t_len :usize = 0;
    let i : usize;
    let mut ret: i32 = 0;
    let mut ctx: Box<hashing:: Context>;
    let mut t :Vec<u8> = vec![0; hashing::MD_MAX_SIZE] ;

    if okm.is_empty(){
        return hashing::ERR_MD_BAD_INPUT_DATA;
    }

    hash_len = md.size as usize;

    if prk_len < hash_len || hash_len == 0 {
        return hashing::ERR_MD_BAD_INPUT_DATA; }

    if info.is_empty() {
        let info = vec![0; 0];
        let info_len = 0; 
    }

    n = okm_len / hash_len ;

    if okm_len % hash_len != 0 {
        n = n+1;
    }

    /*
     * Per RFC 5869 Section 2.3, okm_len must not exceed
     * 255 times the hash length
    */

    if n> 255 {
        return hashing::ERR_MD_BAD_INPUT_DATA; }

    ctx = hashing::create_context();

    ret = setup(&mut ctx, md, true);
    if ret != 0 {
        zeroize(&mut t);
        free(&mut ctx);  
        return ret ;
    }

    for i in 0..hash_len{
        t[i] = 0;
    }

     /*
     * Compute T = T(1) | T(2) | T(3) | ... | T(N)
     * Where T(N) is defined in RFC 5869 Section 2.3
     */
    for i in 1..(n+1) {
        let num_to_copy: usize;
        let mut c : Vec<u8> = vec![0; 1];
        c[0] = i as u8 & 0xff  ;

        ret = hashing::hmac_starts(&mut ctx, prk, prk_len);
        if ret!= 0 {
            zeroize(&mut t);
            free(&mut ctx);  
            return ret;
        }

        ret = hashing::hmac_update(&mut ctx, &t, t_len);
        if ret!=0 {
            zeroize(&mut t);
            free(&mut ctx); 
            return ret; 
        }

        ret = hashing::hmac_update(&mut ctx, info, info_len);
        if ret!=0 {
            zeroize(&mut t);
            free(&mut ctx);  
            return ret ; } 

        ret = hashing::hmac_update(&mut ctx, &c, 1);
        if ret!=0 {
            zeroize(&mut t);
            free(&mut ctx);  
            return ret ; }

        ret = hashing::hmac_finish(&mut ctx, &mut t);
        if ret!=0 {
            zeroize(&mut t);
            free(&mut ctx);  
            return ret ; }
       
        if i!=n { num_to_copy = hash_len; }
        else { num_to_copy = okm_len - where_; }

        for i in where_..num_to_copy+where_{
            okm[i] = t[i-where_];
        }

        where_ += hash_len;
        t_len = hash_len; 
    }

free(&mut ctx);  
zeroize(&mut t);
return ret ; 

} 

#[cfg(test)]
pub mod test{
    use crate :: hashing;  
    const test_hash : hashing:: MdInfoT = hashing:: MdInfoT{
        name: ("SHA1"),
        md_type: hashing::MdTypeT::SHA1,
        size: 20,
        block_size: 64,
    };
    
    const test_salt : &str = "a" ;
    const test_salt_len: usize = 1;

    const test_ikm: &str = "hello";
    const test_ikm_len: usize = 5;

    const test_info: &str = "a";
    const test_info_len: usize = 1;

    const test_okm: [u8; 32] = [0xdd, 0x5d, 0x66, 0xe2, 0x0d, 0xc3, 0x37, 0xfb, 0xc2, 0xf5, 0xb9, 0xc0, 0x98, 0xc4, 0x09, 0x1a, 0xd6, 0xa5, 0xb4, 0xe8, 0x2b, 0x8d, 0x93, 0x33, 0x0e, 0x6a, 0x0d, 0x8e, 0xf4, 0x6d, 0xbb, 0xf0];
    const test_okm_len: usize = 32;
    
    //Credit for compare(): https://codereview.stackexchange.com/a/233878
    use std::cmp;
    fn compare(a: &Vec<u8> , b: &Vec<u8>) -> cmp::Ordering {
        a.iter()
            .zip(b)
            .map(|(x, y)| x.cmp(y))
            .find(|&ord| ord != cmp::Ordering::Equal)
            .unwrap_or(a.len().cmp(&b.len()))
    }

    use super::hkdf;
     #[test]
     pub fn self_test(){
         let mut okm_pred : Vec<u8> = vec![0xff; 32];
         for i in 0..1{
             let out_ = hkdf(&test_hash, &test_salt.as_bytes().to_vec(), test_salt_len, &test_ikm.as_bytes().to_vec(), test_ikm_len, &test_info.as_bytes().to_vec(), test_info_len, &mut okm_pred, test_okm_len);
             println!("the result is {:x?}", okm_pred);
             assert_eq!(0, out_ );
             assert_eq!(cmp::Ordering::Equal, compare(&okm_pred, &test_okm.to_vec()));
         }
     }
}