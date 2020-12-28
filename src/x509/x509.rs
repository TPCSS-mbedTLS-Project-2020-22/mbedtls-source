//TO DO:
//asn1.h
mod x509_header;
mod md_header;
mod pk_header;

fn nop() {}

pub struct mbedtls_x509_buf
{
    pub tag: i32,                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    pub len: i32,             /**< ASN1 length, in octets. */
    pub p: char,      
}

pub struct mbedtls_x509_name
{
    pub oid: mbedtls_x509_buf,                   /**< The object identifier. */
    pub val: mbedtls_x509_buf,                   /**< The named value. */
    pub next: struct mbedtls_x509_name,  /**< The next entry in the sequence. */                    //pointer????????
    pub next_merged: char,      /**< Merge next item into the current one? */
}

pub struct mbedtls_x509_time
{
    pub year: i32; pub mon: i32; pub day: i32,          /**< Date. */
    pub hour: i32; pub min: i32; pub sec: i32,          /**< Time. */        
}

pub struct mbedtls_pk_rsassa_pss_options
{
    pub mgf1_hash_id: md_header::mbedtls_md_type_t,
    pub expected_salt_len: i32,

}

//========================================================================================================================================


pub fn mbedtls_x509_get_serial(p: &mut char, end: &mut char, serial: &mut mbedtls_x509_buf) -> i32 {
    
    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (end - p) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    if p != ( x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_PRIMITIVE | 2 ) && p !=   x509_header::MBEDTLS_ASN1_INTEGER {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL + x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL +
    }

    serial.tag = p;
    p = p + 1;                                                                                            //???????????/

    if mbedtls_asn1_get_len( p, end, serial->len ) != 0 {                                              //yet to implement
        return mbedtls_asn1_get_len( p, end, serial->len ) + x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL     
    }

    serial.p = p;
     
    p = p + serial.len;

    return 0;
}

pub fn mbedtls_x509_get_alg_null(p: &mut char, end: &mut char, serial: &mut mbedtls_x509_buf) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if mbedtls_asn1_get_alg_null( p, end, serial ) != 0 {                                               //yet to implement
        return mbedtls_asn1_get_alg_null( p, end, serial ) + x509_header::MBEDTLS_ERR_X509_INVALID_ALG        
    }

    return 0;
}

pub fn mbedtls_x509_get_alg(p: &mut char, end: &mut char, alg: &mut mbedtls_x509_buf, params: &mut mbedtls_x509_buf) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if mbedtls_asn1_get_alg( p, end, alg, params ) != 0 {                                               //yet to implement
        return mbedtls_asn1_get_alg( p, end, alg, params ) + x509_header::MBEDTLS_ERR_X509_INVALID_ALG        
    }

    return 0;
}

pub fn x509_get_hash_alg(alg: &mut mbedtls_x509_buf, md_alg: &mut mbedtls_md_type_t) -> i32{                //defined in md.h
    
    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut p = 'A';
    let mut end = 'A';
    let mut md_oid = mbedtls_x509_buf{tag: 0, len: 0, p: 'A'};
    let mut len = 0i32;

    if alg.tag != ( x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE ) {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    p = alg.p;

    end = p + alg.len;

    if p >= end {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    md_oid.tag = p;

    if mbedtls_asn1_get_tag(p, end, md_oid.len, x509_header::MBEDTLS_ASN1_OID) !=0 {                                        //yet to implement
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + mbedtls_asn1_get_tag(p, end, md_oid.len, x509_header::MBEDTLS_ASN1_OID)
    }

    md_oid.p = p;
    p = p + md_oid.len;

    if mbedtls_oid_get_md_alg(md_oid, md_alg) !=0 {                                                                         //yet to implement
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + mbedtls_oid_get_md_alg(md_oid, md_alg)
    } 

    if p==end {
        return 0;
    }

    if mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_NULL ) != 0 || len != 0 {                               //yet to implement
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_NULL )
    }

    if p!=end {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH
    }

    return 0;

}

pub fn mbedtls_x509_get_rsassa_pss_params(params: &mbedtls_x509_buf, md_alg: &mut mbedtls_md_type_t, 
    mgf_md: &mut mbedtls_md_type_t, salt_len: &mut i32) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut p = 'A';
    let mut end = 'A';
    let mut end2 = 'A';
    let mut len = 0i32;
    let mut alg_id = mbedtls_x509_buf{tag: 0, len: 0, p: 'A'};
    let mut alg_params = mbedtls_x509_buf{tag: 0, len: 0, p: 'A'};

    *md_alg = md_header::MBEDTLS_MD_SHA1;
    *mgf_md = md_header::MBEDTLS_MD_SHA1;
    *salt_len = 20;

    if params.tag != (x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE) {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    p = params.p;
    end = p + params.len;

    if p==end {
        return 0;
    }

    /*
     * HashAlgorithm
     */
    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 0 );
    if ret == 0 {
        end2 = p + len;

        ret = mbedtls_x509_get_alg_null( p, end2, alg_id );
        if  ret != 0 {
            return ret
        }

        ret = mbedtls_oid_get_md_alg( alg_id, md_alg );
        if ret != 0 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
        }

        if p != end2 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH 
        }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p == end {
        return 0;
    }

    /*
     * MaskGenAlgorithm
     */
    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 1 );
    if ret == 0 {
        end2 = p + len;

        ret mbedtls_x509_get_alg( p, end2, alg_id, alg_params );
        if ret  != 0 {
            return ret
        }

        if MBEDTLS_OID_CMP( MBEDTLS_OID_MGF1, &alg_id ) != 0 {                                   //not defined
            return x509_header::MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE + x509_header::MBEDTLS_ERR_OID_NOT_FOUND
        }                                    

        ret = x509_get_hash_alg( alg_params, mgf_md );
        if ret !=0 {    
            return ret
        }

        if p != end2 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH 
        }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p == end {
        return 0;
    }

    /*
     * salt_len
    */
    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 2 );
    if ret == 0 {
        end2 = p + len;

        ret = mbedtls_x509_get_int( p, end2, &mut salt_len );
        if ret != 0 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
        }

        if p != end2 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH 
        }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p == end {
        return 0;
    }


    /*
     * trailer_field (if present, must be 1)
     */

    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 3 );
    if ret == 0 {
        let trailer_field: i32;

        end2 = p + len;

        ret = mbedtls_asn1_get_int( &p, &end2, &mut trailer_field );
        if ret != 0 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
        }

        if p != end2 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH 
        }

        if trailer_field != 1 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_ALG;
        }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p != end {
        return x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH
    }

    return 0;

}

pub fn x509_get_attr_type_value(p: &mut char, end: &mut char, cur: &mut mbedtls_x509_name) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: i32;
    let mut oid = mbedtls_x509_buf{tag: 0, len: 0, p: 'A'};
    let mut val = mbedtls_x509_buf{tag: 0, len: 0, p: 'A'};
    
    ret = mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE )
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + ret
    }

    end = p + len;                                                                              //???
    
    if (end - p) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    oid = cur.oid;
    oid.tag = p;

    ret = mbedtls_asn1_get_tag( p, end, &mut oid.len, x509_header::MBEDTLS_ASN1_OID )
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + ret
    }

    oid.p = p;
    p = p + lid.len;

    if (end - p) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    if  p != x509_header::MBEDTLS_ASN1_BMP_STRING && p != x509_header::MBEDTLS_ASN1_UTF8_STRING         &&
        p != x509_header::MBEDTLS_ASN1_T61_STRING && p != x509_header::MBEDTLS_ASN1_PRINTABLE_STRING    &&
        p != x509_header::MBEDTLS_ASN1_IA5_STRING && p != x509_header::MBEDTLS_ASN1_UNIVERSAL_STRING    &&
        p != x509_header::MBEDTLS_ASN1_BIT_STRING {

            return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    val = cur.val;
    val.tag = p;
    p = p + 1;                                                                                            //??????

    ret = mbedtls_asn1_get_len( p, end, &mut val.len )
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + ret
    }

    val.p = p;
    p = p + val.len;

    if end != p {
        return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH
    }


    cur.next = NULL;                                                                                        //????????

    return 0;
}

pub fn mbedtls_x509_get_name(p: &mut char, end: &mut char, cur: &mut mbedtls_x509_name) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut set_len = 0i32;
    let mut end_set = 'A';

    while 1 {

        ret = mbedtls_asn1_get_tag( &p, &end, &set_len, x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SET )
        if ret != 0 {
            return x509_header::MBEDTLS_ERR_X509_INVALID_NAME + ret
        }

        end_set = p + set_len;                                                                              //????????????????

        while 1 {
            ret = x509_get_attr_type_value( p, end_set, cur )
            if ret != 0 {
                return ret
            }

            if p == end_set {
                break;
            }
        
            cur.next_merged = 1;                                                                           //???
        
//            cur.next = calloc( 1, sizeof(mbedtls_x509_name));
//
//           if cur.next == NULL {
//                x509_header::MBEDTLS_ERR_X509_ALLOC_FAILED;
//            }
            
            cur = cur.next                                                                                 //??????
        }

        if p == end {
            return 0;
        }

 //       cur.next = calloc( 1, sizeof(mbedtls_x509_name));                                               //?????????

        if cur.next == NULL {
            return x509_header::MBEDTLS_ERR_X509_ALLOC_FAILED;
        }
        
        cur = cur.next
    }
    return 0;                                                                                             //?
}

pub fn x509_parse_int(p: &mut char, mut n: i32, res: &mut i32) -> i32 {

    *res = 0;

    while n > 0 {
        if p < '0' || p > '9' {
            return x509_header::MBEDTLS_ERR_X509_INVALID_DATE
        }

        *res = *res*10;
        p = p - 1;
        *res = *res + p - '0';
    }

    return 0;
}

pub fn x509_date_is_valid(t: &mbedtls_x509_time) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_X509_INVALID_DATE;
    let mut month_len: i32;

    if *t.year < 0 || *t.year > 9999 { return ret };
    
    if *t.hour < 0 || *t.hour > 23 { return ret };
    
    if *t.min < 0 || *t.min > 59 { return ret };
    
    if *t.sec < 0 || *t.sec > 59 { return ret };

    match *t.mon {

        1 | 3 | 5 | 7 | 8 | 10 | 12 => month_len = 31,

        4 | 6 |  9 | 11 => month_len = 30,

        2 => {
            if ( ( *t.year % 4 ==0 ) && (*t.year % 100 != 0 )) || ( *t.year % 400 == 0)  {
                month_len = 29;
            }
                
            else {
                month_len = 28;
            }
        },

        _ => return ret,

    };

    if *t.dat < 1 || *t.sec > month_len { return ret };

    return 0;
}

pub fn x509_parse_time(p: &mut char, mut len: i32, mut yearlen: i32, tm: &mut mbedtls_x509_time) -> i32 {


    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if len < (yearlen + 8) {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE
    }
    len = len - yearlen + 8;

    ret = x509_parse_int( p, yearlen, &tm->year );
    if ret != 0 { return ret};

    if yearlen == 2 {
        if tm.year < 50 {
            tm.year  = tm.year + 100;
        }
        tm.year  = tm.year + 1900;
    }

    ret = x509_parse_int( &mut p, 2, &mut *tm.mon );
    if ret != 0 { return ret};

    ret = x509_parse_int( &mut p, 2, &mut *tm.day );
    if ret != 0 { return ret};

    ret = x509_parse_int( &mut p, 2, &mut *tm.hour );
    if ret != 0 { return ret};

    ret = x509_parse_int( &mut p, 2, &mut *tm.min );
    if ret != 0 { return ret};

    if len >=2 {
        ret = x509_parse_int( &mut p, 2, &mut *tm.sec );
        if ret != 0 { return ret};

        len = len-2;
    }
    else {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE
    }

    if (1 == len) && ( p == 'Z') {
        p = p + 1;
        len = len-1;
    }

    if len != 0 { return x509_header::MBEDTLS_ERR_X509_INVALID_DATE }

    ret = x509_date_is_valid( tm );
    if ret != 0 { return ret };

    return 0;
}

pub fn mbedtls_x509_get_time(p: &mut char, end: &mut char, tm: &mut mbedtls_x509_time) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut len : i32;
    let mut year_len : i32;
    let mut tag : char;

    if (end - *p) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    tag = **p;

    if tag == x509_header::MBEDTLS_ASN1_UTC_TIME { year_len = 2;}

    else if tag == x509_header::MBEDTLS_ASN1_GENERALIZED_TIME { year_len = 4;}

    else {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    (*p) = *p + 1;

    ret = mbedtls_asn1_get_len( p, end, &mut len );

    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_DATE + ret
    }

    return x509_parse_time( p, len, year_len, tm )

}

pub fn mbedtls_x509_get_sig(p: &mut char, end: &mut char, sig: &mut mbedtls_x509_buf) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut len : i32;
    let mut tag_type: i32;

    if ( end - *p ) < 1 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SIGNATURE + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA 
    }

    tag_type = **p;

    ret = mbedtls_asn1_get_bitstring_null( p, end, &mut len );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_SIGNATURE + ret
    }

    sig.type = tag_type;
    sig.len = len;
    sig.p = *p;

    *p = *p + len;

    return 0;
}

pub fn mbedtls_x509_get_sig_alg( sig_oid: &mut mbedtls_x509_buf, sig_params: &mut md_header::mbedtls_md_type_t, 
    md_alg: &mut md_header::mbedtls_md_type_t, pk_alg: &mut pk_header::mbedtls_pk_type_t, void **sig_opts) -> i32 {

    let mut ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if *sig_opts != NULL {
        x509_header::MBEDTLS_ERR_X509_BAD_INPUT_DATA
    }

    ret = mbedtls_oid_get_sig_alg( sig_oid, md_alg, pk_alg );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + ret
    }

//#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    match *pk_alg {
		pk_header::mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS => {
            
            let mut pss_opts = mbedtls_pk_rsassa_pss_options{ mgf1_hash_id: md_header::mbedtls_md_type_t::MBEDTLS_MD_MD2, expected_salt_len: 0};

            ret = mbedtls_x509_get_rsassa_pss_params( sig_params,
                md_alg,
                &mut pss_opts->mgf1_hash_id,
                &mut pss_opts->expected_salt_len );
            
            if ret != 0 { return ret;}

            *sig_opts = (void *) pss_opts;                                                      //???????????????
        },
		_ => {
//#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */            
            if (*sig_params.tag != x509_header::MBEDTLS_ASN1_NULL  && *sig_params.tag !=0 ) || *sig_params.len != 0 ) {
                return x509_header::MBEDTLS_ERR_X509_INVALID_ALG ;
            }
        },
    };
    
    return 0;
}

pub fn mbedtls_x509_get_ext(p: &mut char, end: &mut char, ext: &mut mbedtls_x509_buf, mut tag: i32) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut len : i32;

    ret = mbedtls_asn1_get_tag( p, end, &mut ext->len,
        x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | tag );

    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret
    }

    ext.tag = x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | tag;
    ext.p = *p;
    end  = *p + ext.len;

    ret = mbedtls_asn1_get_tag( p, end, &mut len, x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE );
    if ret != 0 {
        return x509_header::MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret
    }

    if end != (*p + len) {
        return x509_header::MBEDTLS_ERR_X509_INVALID_EXTENSIONS + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH
    }

    return 0
}

pub fn mbedtls_x509_dn_gets(buf : &mut char, mut size: i32, dn: &mbedtls_x509_name) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut i: i32;
    let mut n: i32;

    let mut c: char;
    let mut merge: char;

    let mut name = mbedtls_x509_name{..*dn);

    let mut short_name : char;

    let mut s: [char; x509_header:MBEDTLS_X509_MAX_DN_NAME_SIZE] = ['0'; x509_header:MBEDTLS_X509_MAX_DN_NAME_SIZE];
    let mut p: char;

    p = *buf;
    n = size;



}
