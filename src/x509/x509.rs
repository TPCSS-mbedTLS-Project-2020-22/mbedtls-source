//TO DO:
//asn1.h
mod x509_header;
mod md;


pub struct mbedtls_x509_buf
{
    tag: i32,                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    len: i32,             /**< ASN1 length, in octets. */
    p: char,      
};

pub fn mbedtls_x509_get_serial(p: &mut char, end: &mut char, serial: &mut mbedtls_x509_buf) -> i32 {
    
    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (end - p) < 1 {
        x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    if p != ( x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_PRIMITIVE | 2 ) && p !=   x509_header::MBEDTLS_ASN1_INTEGER {
        x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL + x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL +
    }

    serial.tag = p++;

    if mbedtls_asn1_get_len( &p, &end, &serial->len ) != 0 {                                              //yet to implement
        mbedtls_asn1_get_len( &p, &end, &serial->len ) + x509_header::MBEDTLS_ERR_X509_INVALID_SERIAL     
    }

    serial.p = p;
     
    p = p + serial.len;

    0
}

pub fn mbedtls_x509_get_alg_null(p: &mut char, end: &mut char, serial: &mut mbedtls_x509_buf) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if mbedtls_asn1_get_alg_null( &p, &end, &serial ) != 0 {                                               //yet to implement
        mbedtls_asn1_get_alg_null( &p, &end, &serial ) + x509_header::MBEDTLS_ERR_X509_INVALID_ALG        
    }

    0
}

pub fn mbedtls_x509_get_alg(p: &mut char, end: &mut char, alg: &mut mbedtls_x509_buf, params: &mut mbedtls_x509_buf) -> i32 {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if mbedtls_asn1_get_alg( &p, &end, &alg, &params ) != 0 {                                               //yet to implement
        mbedtls_asn1_get_alg( &p, &end, &alg, &params ) + x509_header::MBEDTLS_ERR_X509_INVALID_ALG        
    }

    0
}

pub fn x509_get_hash_alg(alg: &mut mbedtls_x509_buf, md_alg: &mut mbedtls_md_type_t) -> i32{                //defined in md.h
    
    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut p = 'A';
    let mut end = 'A';
    let mut md_oid = mbedtls_x509_buf{tag: 0, len: 0, p: 'A'};
    let mut len = 0i32;

    if alg.tag != ( x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE ) {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    p = alg.p;

    end = p + alg.len;

    if p >= end {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_OUT_OF_DATA
    }

    md_oid.tag = p;

    if mbedtls_asn1_get_tag(&p, &end, &md_oid.len, x509_header::MBEDTLS_ASN1_OID) !=0 {                                        //yet to implement
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + mbedtls_asn1_get_tag(&p, &end, &md_oid.len, x509_header::MBEDTLS_ASN1_OID)
    }

    md_oid.p = p;
    p = p + md_oid.len;

    if mbedtls_oid_get_md_alg(&md_oid, &md_alg) !=0 {                                                                         //yet to implement
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + mbedtls_oid_get_md_alg(&md_oid, &md_alg)
    } 

    if p==end {
        0
    }

    if mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_NULL ) != 0 || len != 0 {                               //yet to implement
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_NULL )
    }

    if p!=end {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH
    }

    0

}

pun fn mbedtls_x509_get_rsassa_pss_params(params: &mut mbedtls_x509_buf, md_alg: &mut mbedtls_md_type_t, 
    mgf_md: &mut mbedtls_md_type_t, salt_len: &mut i32) {

    let mut ret = x509_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut p = 'A';
    let mut end = 'A';
    let mut end2 = 'A';
    let mut len = 0i32;
    let mut alg_id = mbedtls_x509_buf{tag: 0, len: 0, p: 'A'};
    let mut alg_params = mbedtls_x509_buf{tag: 0, len: 0, p: 'A'};

    md_alg = md::MBEDTLS_MD_SHA1;
    mgf_md = md::MBEDTLS_MD_SHA1;
    salt_len = 20;

    if params.tag != (x509_header::MBEDTLS_ASN1_CONSTRUCTED | x509_header::MBEDTLS_ASN1_SEQUENCE) {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG
    }

    p = params.p;
    end = p + params.len;

    if p==end {
        0
    }

    /*
     * HashAlgorithm
     */
    ret = mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 0 );
    if ret == 0 {
        end2 = p + len;

        ret = mbedtls_x509_get_alg_null( &p, &end2, &alg_id );
        if  ret != 0 {
            ret
        }

        ret = mbedtls_oid_get_md_alg( &alg_id, &md_alg );
        if ret != 0 {
            x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
        }

        if p != end2 {
            x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH 
        }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p == end {
        0
    }

    /*
     * MaskGenAlgorithm
     */
    ret = mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 1 );
    if ret == 0 {
        end2 = p + len;

        ret mbedtls_x509_get_alg( &p, &end2, &alg_id, &alg_params );
        if ret  != 0 {
            ret
        }

        if MBEDTLS_OID_CMP( MBEDTLS_OID_MGF1, &alg_id ) != 0 {                                   //not defined
            x509_header::MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE + x509_header::MBEDTLS_ERR_OID_NOT_FOUND
        }                                    

        ret = x509_get_hash_alg( &alg_params, &mgf_md );
        if ret !=0 {    
            ret
        }

        if p != end2 {
            x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH 
        }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p == end {
        0
    }

    /*
     * salt_len
    */
    ret = mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 2 );
    if ret == 0 {
        end2 = p + len;

        ret = mbedtls_x509_get_int( &p, &end2, &salt_len );
        if ret != 0 {
            x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
        }

        if p != end2 {
            x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH 
        }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p == end {
        0
    }


    /*
     * trailer_field (if present, must be 1)
     */

    ret = mbedtls_asn1_get_tag( &p, &end, &len, x509_header::MBEDTLS_ASN1_CONTEXT_SPECIFIC | x509_header::MBEDTLS_ASN1_CONSTRUCTED | 3 );
    if ret == 0 {
        let trailer_field = 0i32;

        end2 = p + len;

        ret = mbedtls_asn1_get_int( &p, &end2, &mut trailer_field );
        if ret != 0 {
            x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
        }

        if p != end2 {
            x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH 
        }

        if trailer_field != 1 {
            x509_header::MBEDTLS_ERR_X509_INVALID_ALG;
        }
    }

    else if ret != x509_header::MBEDTLS_ERR_ASN1_UNEXPECTED_TAG {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + ret
    }

    if p != end {
        x509_header::MBEDTLS_ERR_X509_INVALID_ALG + x509_header::MBEDTLS_ERR_ASN1_LENGTH_MISMATCH
    }

    return 0

}

