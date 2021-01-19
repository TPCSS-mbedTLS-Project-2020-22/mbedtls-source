

use chrono::{Datelike, Timelike, Utc};
use std::mem::size_of;


#[path = "../x509/x509_header.rs"]  mod x509_header;

#[path = "../x509/pk_header.rs"] mod pk_header;

#[path = "../x509/md_header.rs"] mod md_header;

#[path = "../x509/asn1parse.rs"] mod asn1parse;

fn nop() {}


pub struct p
{
    pub ptr: Vec<u8>,
    pub iptr: usize,
}

impl p{
    pub fn copy(&self) -> p {
        let x = p{ptr: self.ptr[..].iter().cloned().collect(), iptr: self.iptr};
        return x
    }
}

pub struct mbedtls_md_info_t
{
    pub name: String,

    pub type_t : md_header::mbedtls_md_type_t,

    pub size: u8,

    pub block_size: u8,
}

impl md_header::mbedtls_md_type_t {
    pub fn copy(&self) -> md_header::mbedtls_md_type_t {
        match &self {
            MBEDTLS_MD_NONE => return md_header::mbedtls_md_type_t::MBEDTLS_MD_NONE,
            MBEDTLS_MD_MD2 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_MD2,
            MBEDTLS_MD_MD4 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_MD4,
            MBEDTLS_MD_MD5 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_MD5,
            MBEDTLS_MD_SHA1 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA1,
            MBEDTLS_MD_SHA224 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA224,
            MBEDTLS_MD_SHA256 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA256,
            MBEDTLS_MD_SHA384 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA384,
            MBEDTLS_MD_SHA512 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA512,
            MBEDTLS_MD_RIPEMD160 => return md_header::mbedtls_md_type_t::MBEDTLS_MD_RIPEMD160,
        };
    }
}

pub struct mbedtls_x509_buf
{
    pub len: usize,
    pub tag: u8,
    pub p: p,
}

impl mbedtls_x509_buf{
    pub fn copy(&self) -> mbedtls_x509_buf {
        let x = mbedtls_x509_buf{len: self.len, tag: self.tag, p: self.p.copy()};
        return x
    }
}

pub struct mbedtls_x509_name
{
    pub oid: mbedtls_x509_buf,
    pub val: mbedtls_x509_buf,
    pub next: Option<Box<mbedtls_x509_name>>,
    pub next_merged: u8,
}

impl mbedtls_x509_name{
    fn new() -> Box<mbedtls_x509_name> {
        return Box::new(mbedtls_x509_name{
            oid: mbedtls_x509_buf{
                len: 0, 
                tag: 0, 
                p: p{
                    ptr: Vec::new(), 
                    iptr: 0, }
            },
            val: mbedtls_x509_buf{
                len: 0, 
                tag: 0, 
                p: p{
                    ptr: Vec::new(), 
                    iptr: 0, }
            },
            next: None,
            next_merged: 0,
        });
    }
}

pub struct mbedtls_pk_rsassa_pss_options
{
    pub mgf1_hash_id: md_header::mbedtls_md_type_t,
    pub expected_salt_len: i32,
}


pub struct tm
{
  pub tm_sec: i32,
  pub tm_min: i32,
  pub tm_hour: i32,
  pub tm_mday: i32,	
  pub tm_mon: i32,
  pub tm_year: i32,	
  pub tm_wday: i32,
  pub tm_yday: i32,
  pub tm_isdst: i32,
  pub tm_gmtoff: i32,
  pub tm_zone: p,

  pub __tm_gmtoff: i32,
  pub __tm_zone: p,
}

pub struct mbedtls_x509_time
{
    pub year: i32, pub mon: i32, pub day: i32,
    pub hour: i32, pub min: i32, pub sec: i32,
}

//========================================================================================================================================

pub fn prnt(){
    println!("In x509/x509.rs");
}


//external fucntions
pub fn mbedtls_asn1_get_len(p: &mut p, end: &usize, y: &mut usize ) -> i32 {
    return asn1parse::mbedtls_asn1_get_len(p, end, y) }


pub fn mbedtls_asn1_get_tag( p: &mut p, end: &usize, y: &mut usize, z: u8) -> i32 {
    return asn1parse::mbedtls_asn1_get_tag( p, end, y, z) }


pub fn mbedtls_asn1_get_int( p: &mut p, end: &usize, y: &mut i32 ) -> i32 {
    return asn1parse::mbedtls_asn1_get_int( p, end, y ) }


pub fn  mbedtls_asn1_get_bitstring_null(p: &mut p, end: &usize, z: &mut usize ) -> i32 {
    return asn1parse::mbedtls_asn1_get_bitstring_null( p, end, z ) }

pub fn mbedtls_asn1_get_alg( p: &mut p, end: &mut usize, y: &mut mbedtls_x509_buf, z: &mut mbedtls_x509_buf ) -> i32 {
    return asn1parse::mbedtls_asn1_get_alg( p, end, y, z ) }


pub fn mbedtls_asn1_get_alg_null( p: &mut p, end: &mut usize, y: &mut mbedtls_x509_buf ) -> i32 {
    return asn1parse::mbedtls_asn1_get_alg_null( p, end, y ) }








pub fn mbedtls_oid_get_md_alg( x: &mut mbedtls_x509_buf, y: &mut md_header::mbedtls_md_type_t ) -> i32 {
    return 0 }
    

pub fn  mbedtls_oid_get_sig_alg(sig_oid: &mut mbedtls_x509_buf, md_alg: &mut md_header::mbedtls_md_type_t, pk_alg: &mut pk_header::mbedtls_pk_type_t ) -> i32 {
    return 0 }

pub fn  mbedtls_oid_get_sig_alg_desc(sig_oid: &mut mbedtls_x509_buf, desc: &mut p) -> i32 {
    return 0 }

pub fn mbedtls_oid_get_attr_short_name( x: &mut mbedtls_x509_buf, y: &mut String ) -> i32 {
    return 0 }    



pub fn mbedtls_md_info_from_type( md_type : md_header::mbedtls_md_type_t ) -> mbedtls_md_info_t {
    match md_type {
        MBEDTLS_MD_NONE => return mbedtls_md_info_t{
            name        : String::from("NONE"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_NONE,
            size        : 0,
            block_size  : 0,
        },

        MBEDTLS_MD_MD2 => return mbedtls_md_info_t{
            name        : String::from("MD2"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_MD2,
            size        : 16,
            block_size  : 16,
        },

        MBEDTLS_MD_MD4 => return mbedtls_md_info_t{
            name        : String::from("MD4"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_MD4,
            size        : 16,
            block_size  : 64,
        },

        MBEDTLS_MD_MD5 => return mbedtls_md_info_t{
            name        : String::from("MD5"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_MD5,
            size        : 16,
            block_size  : 64,
        },

        MBEDTLS_MD_SHA1 => return mbedtls_md_info_t{
            name        : String::from("SHA1"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA1,
            size        : 20,
            block_size  : 64,
        },

        MBEDTLS_MD_SHA224 => return mbedtls_md_info_t{
            name        : String::from("SHA224"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA224,
            size        : 28,
            block_size  : 64,
        },

        MBEDTLS_MD_SHA256 => return mbedtls_md_info_t{
            name        : String::from("SHA256"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA256,
            size        : 32,
            block_size  : 64,
        },

        MBEDTLS_MD_SHA384 => return mbedtls_md_info_t{
            name        : String::from("SHA384"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA384,
            size        : 48,
            block_size  : 128,
        },

        MBEDTLS_MD_SHA512 => return mbedtls_md_info_t{
            name        : String::from("SHA512"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA512,
            size        : 64,
            block_size  : 128,
        },

        MBEDTLS_MD_RIPEMD160 => return mbedtls_md_info_t{
            name        : String::from("RIPEMD160"),
            type_t      : md_header::mbedtls_md_type_t::MBEDTLS_MD_RIPEMD160,
            size        : 20,
            block_size  : 64,
        },

    };      
}

//1========================================================================================================================================

pub fn mbedtls_x509_get_serial(p: &mut p, end: &usize, serial: &mut mbedtls_x509_buf) -> i32 {
    
    let ret: i32; 

    if (*end - p.iptr) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    if p.ptr[p.iptr] != ( x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_PRIMITIVE | 2 ) && p.ptr[p.iptr] !=   x509_header::MBEDTLS_ASN1_INTEGER {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL + x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL
    }

    serial.tag = p.ptr[p.iptr];
    p.iptr = p.iptr + 1;

    ret = mbedtls_asn1_get_len( p, end, &mut serial.len );                                                      
    if ret != 0 {                                              
        return ret + x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL     
    }

    serial.p = p.copy();

    p.iptr = p.iptr + serial.len;

    return 0;
}

//2========================================================================================================================================

pub fn mbedtls_x509_get_alg_null(p: &mut p, end: &mut usize, serial: &mut mbedtls_x509_buf) -> i32 {

    let ret: i32;

    ret = mbedtls_asn1_get_alg_null( p, end, serial );
    if ret != 0 {                                               
        return ret + x509_header::MBEDTLS_ERR_X509_INVALID_ALG        
    }

    return 0;
}

//3========================================================================================================================================

pub fn mbedtls_x509_get_alg(p: &mut p, end: &mut usize, alg: &mut mbedtls_x509_buf, params: &mut mbedtls_x509_buf) -> i32 {

    let ret: i32;

    ret = mbedtls_asn1_get_alg( p, end, alg, params );
    if ret != 0 {                                              
        return ret + x509_header::MBEDTLS_ERR_X509_INVALID_ALG        
    }

    return 0;
}

//4========================================================================================================================================

pub fn x509_get_hash_alg(alg: &mut mbedtls_x509_buf, md_alg: &mut md_header::mbedtls_md_type_t) -> i32{               
    
    let mut ret: i32;
    let mut p : p;
    let end: usize;
    let mut md_oid = mbedtls_x509_buf{tag: 0, len: 0, p: p{ptr: Vec::new(), iptr: 0}};
    let mut len: usize = 0;

    if alg.tag != ( x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE ) {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    p = alg.p.copy();

    end = p.iptr + alg.len;

    if p.iptr >= end {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA }

    md_oid.tag = p.ptr[p.iptr];

    ret = mbedtls_asn1_get_tag(&mut p, &end, &mut md_oid.len, x509_header::MBEDTLS_ASN1_OID);
    if ret !=0 {                                
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret }

    md_oid.p = p.copy();

    p.iptr = p.iptr + md_oid.len;

    ret = mbedtls_oid_get_md_alg(&mut md_oid, md_alg);
    if ret !=0 {                                                                        
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    } 

    if p.iptr == end {return 0 }

    ret = mbedtls_asn1_get_tag( &mut p, &end, &mut len, x509_header::MBEDTLS_ASN1_NULL );
    if ret != 0 || len != 0 {                              
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p.iptr != end { return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH }

    return 0;

}

//5========================================================================================================================================

pub fn mbedtls_x509_get_rsassa_pss_params(params: &mbedtls_x509_buf, md_alg: &mut md_header::mbedtls_md_type_t, 
    mgf_md: &mut md_header::mbedtls_md_type_t, salt_len: &mut i32) -> i32 {

    let mut ret: i32;
    let mut p : p;
    let mut end: usize; let mut end2: usize;
    let mut len: usize = 0;
    let mut alg_id = mbedtls_x509_buf{tag: 0, len: 0, p: p{ptr: Vec::new(), iptr: 0}};
    let mut alg_params = mbedtls_x509_buf{tag: 0, len: 0, p: p{ptr: Vec::new(), iptr: 0}};

    *md_alg = md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA1;
    *mgf_md = md_header::mbedtls_md_type_t::MBEDTLS_MD_SHA1;
    *salt_len = 20;

    if params.tag != (x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE) {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    p = params.p.copy();

    end = p.iptr + params.len;

    if p.iptr == end { return 0; }
    
    ret = mbedtls_asn1_get_tag( &mut p, &end, &mut len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 0 );
    if ret == 0 {
        end2 = p.iptr + len;

        ret = mbedtls_x509_get_alg_null( &mut p, &mut end, &mut alg_id );
        if  ret != 0 {
            return ret }

        ret = mbedtls_oid_get_md_alg( &mut alg_id, md_alg );
        if ret != 0 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret }

        if p.iptr != end2 { return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p.iptr == end { return 0; }

    
    ret = mbedtls_asn1_get_tag( &mut p, &end, &mut len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 1 );
    if ret == 0 {
        end2 = p.iptr + len;

        ret = mbedtls_x509_get_alg( &mut p, &mut end, &mut alg_id, &mut alg_params );
        if ret  != 0 {
            return ret }
                                   

        ret = x509_get_hash_alg( &mut alg_params, mgf_md );
        if ret !=0 { return ret }

        if p.iptr != end2 { return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }
    if p.iptr == end { return 0; }

    
    ret = mbedtls_asn1_get_tag( &mut p, &end, &mut len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 2 );
    if ret == 0 {
        end2 = p.iptr + len;

        ret = mbedtls_asn1_get_int( &mut p, &end, salt_len );
        if ret != 0 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
        }
        if p.iptr != end2 { return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH  }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p.iptr == end { return 0; }


    ret = mbedtls_asn1_get_tag( &mut p, &end, &mut len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 3 );
    if ret == 0 {
        let mut trailer_field: i32 = 0;
        end2 = p.iptr + len;

        ret = mbedtls_asn1_get_int( &mut p, &end, &mut trailer_field );
        if ret != 0 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret }

        if p.iptr != end2 { return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH }

        if trailer_field != 1 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p.iptr != end { return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH }

    return 0;

}

//6========================================================================================================================================

pub fn x509_get_attr_type_value(p: &mut p, end: &mut usize, cur: &mut mbedtls_x509_name) -> i32 {

    let mut ret:i32; 
    let mut len: usize = 0;
    let mut oid: mbedtls_x509_buf;
    let mut val: mbedtls_x509_buf;
    
    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + ret }

    *end = p.iptr + len;
    
    if (*end - p.iptr) < 1 { return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA }

    oid = cur.oid.copy();
    oid.tag = p.ptr[p.iptr];

    ret = mbedtls_asn1_get_tag( p, end, &mut oid.len, x509_header::MBEDTLS_ASN1_OID );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + ret }

    oid.p.ptr = p.ptr[p.iptr..(p.iptr+oid.len)].iter().cloned().collect();
    oid.p.iptr = 0; 
    p.iptr = p.iptr + oid.len;

    if (*end - p.iptr) < 1 { return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA }

    if  p.ptr[p.iptr] != x509_header::MBEDTLS_ASN1_BMP_STRING && p.ptr[p.iptr] != x509_header::MBEDTLS_ASN1_UTF8_STRING         &&
        p.ptr[p.iptr] != x509_header::MBEDTLS_ASN1_T61_STRING && p.ptr[p.iptr] != x509_header::MBEDTLS_ASN1_PRINTABLE_STRING    &&
        p.ptr[p.iptr] != x509_header::MBEDTLS_ASN1_IA5_STRING && p.ptr[p.iptr] != x509_header::MBEDTLS_ASN1_UNIVERSAL_STRING    &&
        p.ptr[p.iptr] != x509_header::MBEDTLS_ASN1_BIT_STRING {

            return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    val = cur.val.copy();
    val.tag = p.ptr[p.iptr];
    p.iptr = p.iptr + 1;

    ret = mbedtls_asn1_get_len( p, end, &mut val.len );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + ret }

    val.p.ptr = p.ptr[p.iptr..(p.iptr+val.len)].iter().cloned().collect(); 
    val.p.iptr = 0;

    p.iptr = p.iptr + val.len;

    if *end != p.iptr { return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH }


    cur.next = None;
    return 0;
}

//7========================================================================================================================================

pub fn mbedtls_x509_get_name(p: &mut p, end: &usize, mut cur: &mut mbedtls_x509_name) -> i32 {

    let mut ret: i32;
    let mut set_len: usize = 0;
    let mut end_set: usize;

    loop {

        ret = mbedtls_asn1_get_tag( p, end, &mut set_len, x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SET );
        if ret != 0 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + ret }

        end_set = p.iptr + set_len;

        loop {
            ret = x509_get_attr_type_value( p, &mut end_set, cur );
            if ret != 0 {
                return ret }

            if p.iptr == end_set {
                break }
        
            cur.next_merged = 1;  
            
            cur.next = Some(mbedtls_x509_name::new());
            match &mut cur.next{
                None => return x509_header::MBEDTLS_ERR_X509_ALLOC_FAILED,
                Some(x) => cur = x,
           };
        }

        if p.iptr == *end {
            return 0 }


        cur.next = Some(mbedtls_x509_name::new());
        match &mut cur.next{
            None => return x509_header::MBEDTLS_ERR_X509_ALLOC_FAILED,
            Some(x) => cur = x,
        }

    }

}

//8========================================================================================================================================

pub fn x509_parse_int(p: &mut p, n: usize, res: &mut i32) -> i32 {

    *res = 0;

    while n > 0 {
        if p.ptr[p.iptr] < 48 || p.ptr[p.iptr] > 57 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_DATE
        }

        *res = *res * 10;
        *res = *res + (p.ptr[p.iptr] as i32) - 48;
        p.iptr = p.iptr + 1;
    }

    return 0;
}

//9========================================================================================================================================

pub fn x509_date_is_valid(t: &mbedtls_x509_time) -> i32 {

    let ret = x509_header::MBEDTLS_ERR_X509_INVALID_DATE;
    let month_len: i32;

    if t.year < 0 || t.year > 9999 { return ret };
    
    if t.hour < 0 || t.hour > 23 { return ret };
    
    if t.min < 0 || t.min > 59 { return ret };
    
    if t.sec < 0 || t.sec > 59 { return ret };

    match t.mon {

        1 | 3 | 5 | 7 | 8 | 10 | 12 => month_len = 31,

        4 | 6 |  9 | 11 => month_len = 30,

        2 => {
            if ( ( t.year % 4 ==0 ) && (t.year % 100 != 0 )) || ( t.year % 400 == 0)  {
                month_len = 29;
            }
                
            else {
                month_len = 28;
            }
        },

        _ => return ret,

    };

    if t.day < 1 || t.day > month_len { return ret };

    return 0;
}

//10========================================================================================================================================


pub fn x509_parse_time(p: &mut p, mut len: usize, yearlen: usize, tm: &mut mbedtls_x509_time) -> i32 {


    let mut ret: i32;

    if len < (yearlen + 8) {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE }
    len = len - yearlen + 8;

    ret = x509_parse_int( p, yearlen, &mut tm.year );
    if ret != 0 { return ret};

    if yearlen == 2 {
        if tm.year < 50 {
            tm.year  = tm.year + 100; }
        tm.year  = tm.year + 1900;
    }

    ret = x509_parse_int( p, 2, &mut tm.mon );
    if ret != 0 { return ret};

    ret = x509_parse_int( p, 2, &mut tm.day );
    if ret != 0 { return ret};

    ret = x509_parse_int( p, 2, &mut tm.hour );
    if ret != 0 { return ret};

    ret = x509_parse_int( p, 2, &mut tm.min );
    if ret != 0 { return ret};

    if len >=2 {
        ret = x509_parse_int( p, 2, &mut tm.sec );
        if ret != 0 { return ret};

        len = len-2;
    }
    else {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE }

    if (1 == len) && ( p.ptr[p.iptr] == 90) {
        p.iptr = p.iptr + 1;
        len = len-1;
    }

    if len != 0 { return x509_header::MBEDTLS_ERR_X509_INVALID_DATE }

    ret = x509_date_is_valid( tm );
    if ret != 0 { return ret };

    return 0;
}

//11========================================================================================================================================

pub fn mbedtls_x509_get_time(p: &mut p, end: &usize, tm: &mut mbedtls_x509_time) -> i32 {

    let ret: i32;
    let mut len : usize = 0;
    let year_len : usize;
    let tag : u8;

    if (*end - p.iptr) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA }

    tag = p.ptr[p.iptr];

    if tag == x509_header::MBEDTLS_ASN1_UTC_TIME { year_len = 2;}

    else if tag == x509_header::MBEDTLS_ASN1_GENERALIZED_TIME { year_len = 4;}

    else {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG }

    p.iptr = p.iptr + 1;

    ret = mbedtls_asn1_get_len( p, end, &mut len );

    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE + ret }

    return x509_parse_time( p, len, year_len, tm )

}

//12========================================================================================================================================

pub fn mbedtls_x509_get_sig(p: &mut p, end: &usize, sig: &mut mbedtls_x509_buf) -> i32 {

    let ret: i32;
    let mut len : usize = 0;
    let tag_type: u8;

    if ( *end - p.iptr ) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SIGNATURE + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA }

    tag_type = p.ptr[p.iptr];

    ret = mbedtls_asn1_get_bitstring_null( p, end, &mut len );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SIGNATURE + ret
    }

    sig.tag = tag_type;
    sig.len = len;
    sig.p.ptr = p.ptr[p.iptr..(p.iptr + len)].iter().cloned().collect();

    p.iptr = p.iptr + len;

    return 0;
}

//13========================================================================================================================================

pub fn mbedtls_x509_get_sig_alg( sig_oid: &mut mbedtls_x509_buf, sig_params: &mut mbedtls_x509_buf,
    md_alg: &mut md_header::mbedtls_md_type_t, pk_alg: &mut pk_header::mbedtls_pk_type_t, sig_opts: &mut mbedtls_pk_rsassa_pss_options) -> i32 {

    let mut ret: i32;

    ret = mbedtls_oid_get_sig_alg( sig_oid, md_alg, pk_alg );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + ret
    }


    match *pk_alg {
		pk_header::mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS => {
            
            let mut pss_opts = mbedtls_pk_rsassa_pss_options{ mgf1_hash_id: md_header::mbedtls_md_type_t::MBEDTLS_MD_MD2, expected_salt_len: 0};

            ret = mbedtls_x509_get_rsassa_pss_params( sig_params,
                md_alg,
                &mut pss_opts.mgf1_hash_id,
                &mut pss_opts.expected_salt_len );
            
            if ret != 0 { return ret;}

            *sig_opts = mbedtls_pk_rsassa_pss_options{mgf1_hash_id: pss_opts.mgf1_hash_id, expected_salt_len: pss_opts.expected_salt_len};
        },
		_ => {
           
            if ( sig_params.tag != x509_header::MBEDTLS_ASN1_NULL  && sig_params.tag !=0 ) || sig_params.len != 0  {
                return x509_header::MBEDTLS_ERR_X509_INVALID_ALG }
        },
    };
    
    return 0;
}

//14========================================================================================================================================

pub fn mbedtls_x509_get_ext(p: &mut p, end: &mut usize, ext: &mut mbedtls_x509_buf, tag: u8) -> i32 {

    let mut ret: i32;
    let mut len : usize = 0;

    ret = mbedtls_asn1_get_tag( p, end, &mut ext.len,
        x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | tag );

    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret }

    ext.tag = x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | tag;
    ext.p.ptr = p.ptr[p.iptr..(p.iptr+ext.len)].iter().cloned().collect(); 
    *end  = p.iptr + ext.len;

    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret }

    if *end != (p.iptr + len) {
        return x509_header::MBEDTLS_ERR_X509_INVALID_EXTENSIONS + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH }

    return 0
}

//15========================================================================================================================================

pub fn mbedtls_x509_dn_gets(buf : &mut p, size: usize, dn: &mut mbedtls_x509_name) -> i32 {

    let mut ret :i32;
    let mut i: i32;
    let mut n: usize;

    let mut c: u8;
    let mut merge: u8 = '\0' as u8;

    let mut name = dn;

    let mut short_name = String::new();

    let mut s: [u8; x509_header::MBEDTLS_X509_MAX_DN_NAME_SIZE as usize] = ['0' as u8; x509_header::MBEDTLS_X509_MAX_DN_NAME_SIZE as usize];


    let mut p = buf.copy();
    let mut temp: usize = 0;
    n = size;
    let mut flag = false;
    loop {
        if name.oid.len == 0{
            flag = true;
            match &mut name.next{
                None => break,
                Some(x) => {
                    name = x; 
                    continue
                },
            }
        }
        if flag {
            let bytes : Vec<u8>;
            if merge == '\0' as u8 {
                bytes = (format!("{}==", short_name)).into_bytes();
            }
            else {
                bytes = (format!("??",)).into_bytes();
            }
            let mut count : usize = 0;
            for i in bytes {
                p.ptr.push(i);
                count += 1;
            }
            p.iptr = p.iptr + count;
            ret = count as i32;





            if (ret < 0) || ((ret as usize) >= n ) {
                return x509_header::MBEDTLS_ERR_X509_BUFFER_TOO_SMALL }
            n = n - (ret as usize);
            p.iptr = p.iptr + (ret as usize);
        }
        ret = mbedtls_oid_get_attr_short_name( &mut name.oid, &mut short_name );

        let bytes : Vec<u8>;
        if ret == 0 {
            bytes = (format!("{}==", short_name)).into_bytes();
        }
        else {
            bytes = (format!("??",)).into_bytes();
        }
        let mut count : usize = 0;
        for i in bytes {
            p.ptr.push(i);
            count += 1;
        }
        p.iptr = p.iptr + count;
        ret = count as i32;


        if (ret < 0) || ((ret as usize) >= n ) {
                return x509_header::MBEDTLS_ERR_X509_BUFFER_TOO_SMALL }
        n = n - (ret as usize);
        p.iptr = p.iptr + (ret as usize);

        for i in 0..name.val.len {
            if i >= (size_of::<[u8; x509_header::MBEDTLS_X509_MAX_DN_NAME_SIZE as usize]>() - 1) {
                break } 
                    
            c = name.val.p.ptr[i];
            s[i] = if c < 32 || c > 127 { '?' as u8 } else {c};
            temp = i + 1;
        }
        
        s[temp] = '\0' as u8;


        let mut pri = String::new();
        for &i in &s { pri.push(i as char)};
        let bytes = (format!("{}",pri)).into_bytes();
        let mut count : usize = 0;
        for i in bytes {
            p.ptr.push(i);
            count += 1;
        }
        p.iptr = p.iptr + count;
        ret = count as i32;

        if (ret < 0) || ((ret as usize) >= n ) {
            return x509_header::MBEDTLS_ERR_X509_BUFFER_TOO_SMALL }

        n = n - (ret as usize);
        p.iptr = p.iptr + (ret as usize);

        merge = name.next_merged;
        match &mut name.next{
            None => break,
            Some(x) => {
                name = x;
            },
        }
        flag = true;

        
    }
                                                                   

    return (size - n) as i32
}


//16========================================================================================================================================

pub fn mbedtls_x509_serial_gets(buf: &mut p, size: usize, serial: &mut mbedtls_x509_buf) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut n: usize;
    let nr: usize;

    let mut p = buf.copy();
    n = size;

    nr = if serial.len <= 32 { serial.len } else { 28 };

    for i in 0..nr {
        if (i == 0) && (nr > 1) && (serial.p.ptr[i as usize] == 0x0) { continue;}


        let bytes = (format!("{}{}", serial.p.ptr[serial.p.iptr], if i < (nr - 1) {":"} else {""})).into_bytes();
        let mut count : usize = 0;
        for i in bytes {
            p.ptr.push(i);
            count += 1;
        }
        p.iptr = p.iptr + count;
        ret = count as i32;

        if (ret < 0) || ((ret as usize) >= n ) {
            return x509_header::MBEDTLS_ERR_X509_BUFFER_TOO_SMALL }

        n = n - (ret as usize);
        p.iptr = p.iptr + (ret as usize);
    }

    if nr != serial.len {


        let bytes = (format!("....")).into_bytes();
        let mut count : usize = 0;
        for i in bytes {
            p.ptr.push(i);
            count += 1;
        }
        p.iptr = p.iptr + count;
        ret = count as i32;

        if (ret < 0) || ((ret as usize) >= n ) {
            return x509_header::MBEDTLS_ERR_X509_BUFFER_TOO_SMALL }

        n = n - (ret as usize);
        p.iptr = p.iptr + (ret as usize);
    }


    return (size - n) as i32
}

//17==========================================================================================================================================

pub fn mbedtls_x509_sig_alg_gets(buf: &mut p, size: usize, sig_oid: &mut mbedtls_x509_buf, 
    pk_alg: &mut pk_header::mbedtls_pk_type_t, md_alg: &mut md_header::mbedtls_md_type_t, sig_opts: &mbedtls_pk_rsassa_pss_options) -> i32 {

    let mut ret: i32; 


    let mut p = buf.copy();
    let mut n = size;
    let mut desc: p = p.copy();

    ret = mbedtls_oid_get_sig_alg_desc( sig_oid, &mut desc ); 

    if ret != 0 { 
        let bytes = (format!("???")).into_bytes();
        let mut count : usize = 0;
        for i in bytes {
            p.ptr.push(i);
            count += 1;
        }
        p.iptr = p.iptr + count;
        ret = count as i32;
    }

    else {
        let bytes: Vec<u8> = desc.ptr[..].iter().cloned().collect();
        let mut count : usize = 0;
        for i in bytes {
            p.ptr.push(i);
            count += 1;
        }
        p.iptr = p.iptr + count;
        ret = count as i32;
    }
    if (ret < 0) || ((ret as usize) >= n ) {
        return x509_header::MBEDTLS_ERR_X509_BUFFER_TOO_SMALL }

    n = n - (ret as usize);
    p.iptr = p.iptr + (ret as usize);

    match *pk_alg {
        pk_header::mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS => {
            
            let mut pss_opts = mbedtls_pk_rsassa_pss_options{mgf1_hash_id: sig_opts.mgf1_hash_id.copy(), expected_salt_len: sig_opts.expected_salt_len};
            let mut md_info : mbedtls_md_info_t;
            let mut mgf_md_info : mbedtls_md_info_t;

            md_info = mbedtls_md_info_from_type( md_alg.copy() );

            mgf_md_info = mbedtls_md_info_from_type( pss_opts.mgf1_hash_id );


            let bytes = (format!("({}, MGF1-{}, 0x{})","???","???",pss_opts.expected_salt_len)).into_bytes();
            let mut count : usize = 0;
            for i in bytes {
                p.ptr.push(i);
                count += 1;
            }
            p.iptr = p.iptr + count;
            ret = count as i32;



            if (ret < 0) || ((ret as usize) >= n ) {
                return x509_header::MBEDTLS_ERR_X509_BUFFER_TOO_SMALL }

            n = n - (ret as usize);
            p.iptr = p.iptr + (ret as usize);
        },

        _ => { nop() },
    };

    return (size - n) as i32
}

//18==========================================================================================================================================

pub fn mbedtls_x509_key_size_helper(buf: &mut p, buf_size: usize, name: &mut p) -> i32 {

    let mut p = buf.copy();
    let mut n = buf_size;

    let ret: i32;

    let bytes: Vec<u8> = name.ptr[..].iter().cloned().collect();
    let mut count : usize = 0;
    for i in bytes {
        p.ptr.push(i);
        count += 1;
    }
    p.iptr = p.iptr + count;
    ret = count as i32;
    
    if (ret < 0) || ((ret as usize) >= n ) {
        return x509_header::MBEDTLS_ERR_X509_BUFFER_TOO_SMALL }

    n = n - (ret as usize);
    p.iptr = p.iptr + (ret as usize);

    return 0
}

//19==========================================================================================================================================

pub fn x509_get_current_time(now: &mut mbedtls_x509_time) -> i32 {


    let now_t = Utc::now();                                                                     //time in UTC
    let (is_pm, hour) = now_t.hour12();
    let ( is_common_era , year) = now_t.year_ce();

    now.year = year as i32;
    now.mon = now_t.month() as i32;
    now.day = now_t.day() as i32;
    now.hour = if is_pm { (hour as i32) + 12 } else { hour as i32 };
    now.min = now_t.minute() as i32;
    now.sec = now_t.second() as i32;
    return 0

}

//20==========================================================================================================================================

pub fn x509_check_time( before: &mbedtls_x509_time , after: &mbedtls_x509_time ) -> i32 {

    if before.year  > after.year  {
        return 1 }

    if before.year == after.year &&
        before.mon   > after.mon {
        return 1 }

    if before.year == after.year &&
        before.mon  == after.mon  &&
        before.day   > after.day {
        return 1 }

    if before.year == after.year &&
        before.mon  == after.mon  &&
        before.day  == after.day  &&
        before.hour  > after.hour {
        return 1 }

    if before.year == after.year &&
        before.mon  == after.mon  &&
        before.day  == after.day  &&
        before.hour == after.hour &&
        before.min   > after.min  {
        return 1 }

    if before.year == after.year &&
        before.mon  == after.mon  &&
        before.day  == after.day  &&
        before.hour == after.hour &&
        before.min  == after.min  &&
        before.sec   > after.sec  {
        return 1 }

    return 0 
}

//21==========================================================================================================================================

pub fn mbedtls_x509_time_is_past( to: &mbedtls_x509_time ) -> i32 {

    let mut now = mbedtls_x509_time{..*to};

    if x509_get_current_time( &mut now ) != 0  {
        return 1 }

    return x509_check_time( &now, to ) ;
}

//22==========================================================================================================================================

pub fn mbedtls_x509_time_is_future( from: &mbedtls_x509_time ) -> i32 {

    let mut now = mbedtls_x509_time{..*from};

    if x509_get_current_time( &mut now ) != 0  {
        return 1 }

    return x509_check_time( from, &now ) ;
}
