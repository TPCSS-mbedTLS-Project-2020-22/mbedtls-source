
#[path = "../x509/x509_header.rs"]  mod x509_header;



use crate::x509::x509::p;
use crate::x509::x509::mbedtls_x509_buf;
use crate::x509::x509::mbedtls_x509_name;
use crate::x509::x509::mbedtls_pk_rsassa_pss_options;
use crate::x509::x509::tm;
use crate::x509::x509::mbedtls_x509_time;


//========================================================================================================================================
pub fn print(){
    println!("In x509/asn1parse.rs");
}

//asn1.h

pub struct mbedtls_asn1_sequence
{
    pub buf: mbedtls_x509_buf,                 
    pub next: Option<Box<mbedtls_asn1_sequence>>,
}



//========================================================================================================================================
//========================================================================================================================================


pub fn mbedtls_asn1_get_len(p: &mut p, end: &usize, len: &mut usize ) -> i32 {

    if (*end - p.iptr) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    if p.ptr[p.iptr] & 0x80 == 0 {
        *len = p.ptr[p.iptr] as usize;
        p.iptr = p.iptr + 1;
    }
    else {
        match p.ptr[p.iptr] & 0x7F {
            1 => {
                if *end - p.iptr < 2 {
                    return x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
                }

                *len = p.ptr[p.iptr + 1] as usize;
                p.iptr = p.iptr + 2;
            },

            2 => {
                if *end - p.iptr < 3 {
                    return x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
                }

                *len = ((p.ptr[p.iptr + 1] as usize) << 8 ) | p.ptr[p.iptr + 2] as usize;
                p.iptr = p.iptr + 3;
            }, 

            3 => {
                if *end - p.iptr < 4 {
                    return x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
                }

                *len = ((p.ptr[p.iptr + 1] as usize) << 16 ) | ((p.ptr[p.iptr + 2] as usize) << 8 ) | p.ptr[p.iptr + 3] as usize;
                p.iptr = p.iptr + 4;
            },

            4 => {
                if *end - p.iptr < 5 {
                    return x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
                }

                *len = ((p.ptr[p.iptr + 1] as usize) << 24 ) | ((p.ptr[p.iptr + 2] as usize) << 16 ) | ((p.ptr[p.iptr + 3] as usize) << 8 ) | p.ptr[p.iptr + 4] as usize;
                p.iptr = p.iptr + 5;
            },

            _ => return x509_header::MBEDTLS_ERR_ASN1_INVALID_LENGTH
        }
    }

    if *len > (*end - p.iptr) as usize {
        return x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }
    return 0;
}

//========================================================================================================================================

pub fn mbedtls_asn1_get_tag( p: &mut p, end: &usize, len: &mut usize, tag: u8) -> i32 {
    
    if (*end - p.iptr) < 1 {
        return x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    if p.ptr[p.iptr] != tag {
        return x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }
    p.iptr = p.iptr + 1;

    return mbedtls_asn1_get_len( p, end, len )
}

//========================================================================================================================================

pub fn mbedtls_asn1_get_bool( p: &mut p, end: &usize, val: &mut usize) -> i32 {
    
    let mut len : usize = 0;
    let ret : i32;

    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_BOOLEAN);
    if ret != 0 {
        return ret;
    }

    if len != 1 {
        return x509_header::MBEDTLS_ERR_ASN1_INVALID_LENGTH
    }

    *val = if p.ptr[p.iptr] != 0 {1} else {0};
    p.iptr = p.iptr + 1;

    return 0
}

//========================================================================================================================================

pub fn asn1_get_tagged_int( p: &mut p, end: &usize, tag: u8, val: &mut i32) -> i32 {

    let mut len : usize = 0;
    let ret : i32;

    ret = mbedtls_asn1_get_tag( p, end, &mut len, tag);
    if ret != 0 {
        return ret;
    }

    if len == 0 {
        return x509_header::MBEDTLS_ERR_ASN1_INVALID_LENGTH
    }

    if p.ptr[p.iptr] & 0x80 != 0 {
        return x509_header::MBEDTLS_ERR_ASN1_INVALID_LENGTH
    }

    while (len > 0 )&& (p.ptr[p.iptr] == 0) {
        p.iptr = p.iptr + 1;
        len = len - 1;
    }

    *val = 0;
    while len > 0 {
        *val = (*val << 8) | (p.ptr[p.iptr] as i32);
        p.iptr = p.iptr + 1;
        len = len - 1;
    }
    return 0;
}

//========================================================================================================================================

pub fn mbedtls_asn1_get_int( p: &mut p, end: &usize, val: &mut i32) -> i32 {

    return asn1_get_tagged_int(p, end, x509_header::MBEDTLS_ASN1_INTEGER, val);
}

//========================================================================================================================================

pub fn mbedtls_asn1_get_enum( p: &mut p, end: &usize, val: &mut i32) -> i32 {

    return asn1_get_tagged_int(p, end, x509_header::MBEDTLS_ASN1_ENUMERATED, val);
}

//========================================================================================================================================

pub fn mbedtls_asn1_get_bitstring_null( p: &mut p, end: &usize, len : &mut usize ) -> i32 {
    let ret : i32;

    ret = mbedtls_asn1_get_tag( p, end, len, x509_header::MBEDTLS_ASN1_BIT_STRING );
    if ret != 0 {
        return ret
    }

    if *len == 0 {
        return x509_header::MBEDTLS_ERR_ASN1_INVALID_DATA
    }
    *len = *len - 1;

    if p.ptr[p.iptr] != 0 {
        return x509_header::MBEDTLS_ERR_ASN1_INVALID_DATA
    }
        
    p.iptr = p.iptr + 1;

    return 0 ;
}

//========================================================================================================================================

pub fn mbedtls_asn1_get_alg( p: &mut p, end: &mut usize, alg: &mut mbedtls_x509_buf, params: &mut mbedtls_x509_buf ) -> i32 {
    let mut ret : i32;
    let mut len : usize = 0;

    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE );
    if ret != 0 {
        return ret
    }

    if *end - p.iptr < 1 {
        return x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA 
    }

    alg.tag = p.ptr[p.iptr];
    *end = p.iptr + len;

    ret = mbedtls_asn1_get_tag( p, end, &mut alg.len, x509_header::MBEDTLS_ASN1_OID );
    if ret != 0 { 
        return ret
    }

    alg.p = p.copy();
    p.iptr = p.iptr + alg.len;

    if p.iptr == *end {
        return 0 ;
    }

    params.tag = p.ptr[p.iptr];
    p.iptr = p.iptr + 1;

    ret = mbedtls_asn1_get_len( p, end, &mut params.len );
    if ret != 0 {
        return ret
    }
    
    params.p = p.copy();
    p.iptr = p.iptr + params.len;

    if p.iptr != *end {
        return x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH
    }

    return 0
}

//========================================================================================================================================

pub fn mbedtls_asn1_get_alg_null(  p: &mut p, end: &mut usize, alg: &mut mbedtls_x509_buf ) -> i32 {

    let ret : i32;
    let mut params = alg.copy();

    ret = mbedtls_asn1_get_alg( p, end, alg, &mut params );
    if ret != 0 {
        return ret
    }
    
    if (params.tag != x509_header::MBEDTLS_ASN1_NULL && params.tag != 0 ) || params.len != 0 {
        return x509_header::MBEDTLS_ERR_ASN1_INVALID_DATA
    }
    
    return 0
}

//========================================================================================================================================


