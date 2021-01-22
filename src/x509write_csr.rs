use std::{array, usize};
use std::mem;


use std::ptr::write_bytes;
pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED : i32 =  -0x006E ;
pub const MBEDTLS_OID_KEY_USAGE: i32 = 15;
pub const MBEDTLS_OID_NS_CERT_TYPE: Vec<i32> = vec![1];
pub const PSA_HASH_OPERATION_INIT:psa_hash_operation_t = psa_hash_operation_t {};
pub const MBEDTLS_ASN1_CONSTRUCTED: i32 = 0x20 ;
pub const MBEDTLS_OID_PKCS9_CSR_EXT_REQ: i32 = 0x0e;
pub const MBEDTLS_ASN1_SEQUENCE: i32 =0x10 ;
pub const MBEDTLS_ASN1_SET: i32 = 0x11 ;
pub const MBEDTLS_ASN1_CONTEXT_SPECIFIC: i32 = 0x80;
pub const MBEDTLS_ERR_X509_FATAL_ERROR: i32 = -0x3000;
pub const PSA_SUCCESS: i32 = 0;
pub const MBEDTLS_PK_RSA: mbedtls_pk_type_t = mbedtls_pk_type_t{};
pub const MBEDTLS_PK_ECDSA: mbedtls_pk_type_t = mbedtls_pk_type_t{};
pub const MBEDTLS_ERR_X509_INVALID_ALG: i32 = -0x2300;
pub const MBEDTLS_PK_SIGNATURE_MAX_SIZE: i32 = 10;
pub const MBEDTLS_ERR_X509_ALLOC_FAILED: i32 = -0x2880;

pub struct psa_algorithm_t{

}
pub struct mbedtls_md5_context{

}


pub struct mbedtls_pk_context{

}
pub struct mbedtls_md_type_t{

}
pub struct psa_hash_operation_s
{
    alg:psa_algorithm_t,
    md5:mbedtls_md5_context,
}
pub struct mbedtls_asn1_named_data {
    oid: Buf,
    val: Buf,
    next: Option<Box<NamedData>>,
    next_merged: u8,
}
pub struct mbedtls_x509write_csr
{
    key: mbedtls_pk_context,
    subject: mbedtls_asn1_named_data,
    md_alg: mbedtls_md_type_t ,
    extensions:mbedtls_asn1_named_data,
}

pub struct SBuffer {
    /// Buffer holding data
    buf: Vec<u8>,
    /// index for keeping track of location to be read
    ptr: usize,
}

pub struct Buf {
    /// ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING.
    tag: i32,
    /// ASN1 length, in octets.
    len: usize,
    /// ASN1 data, e.g. in ASCII.
    p: Vec<u8>,
}

pub struct NamedData {
    /// The object identifier.
    oid: Buf,
    /// The named value.
    val: Buf,
    /// The next entry in the sequence.
    next: Option<Box<NamedData>>,
    /// Merge next item into the current one?
    next_merged: u8,
}
pub struct mbedtls_pk_type_t{

}
pub struct psa_hash_operation_t{

}


macro_rules! MBEDTLS_ASN1_CHK_ADD {
    ($g:expr, $f:expr) => {
        let ret:i32=$f;
        if ret < 0 {
            return (ret as i32);
        } else {
            ($g) = ($g) + ret as usize;
        }
        
    };
}
fn main() {
    
}

fn mbedtls_asn1_write_len(c2:&mut[u8],  buf:&mut Vec<u8>, len:  usize) -> i32 {
    0
}
pub fn mbedtls_asn1_free_named_data_list(head: &mbedtls_asn1_named_data){

}
pub fn mbedtls_x509_string_to_names(mut head :&mbedtls_asn1_named_data, subject_name:Vec<u8>)->i32{
0
}

pub fn mbedtls_x509_set_extension(mut head :&mbedtls_asn1_named_data,oid:i32,  oid_len:i32,
    size:usize,val:&mut[u8],  val_len:usize)->i32{
0
}

pub fn mbedtls_x509_write_extensions(mut c:&mut[u8],buf:&mut Vec<u8>,head: &mbedtls_asn1_named_data)->i32{
0
}
fn mbedtls_asn1_write_named_bitstring( mut ctx :&mut[u8],mut buf: &mut Vec<u8>,key_usage: &&mut u8, mut bits: usize) -> i32 {
    0
}
fn mbedtls_psa_translate_md(head: &mbedtls_md_type_t) -> psa_algorithm_t {
    psa_algorithm_t{}
}

pub fn mbedtls_asn1_write_tag(mut c:&mut[u8],buf:&mut Vec<u8>,l:i32)->i32{
0
}


pub fn mbedtls_pk_write_pubkey_der(head: &mbedtls_pk_context,buf:&mut Vec<u8>,dif:usize)->i32{
    0
}
pub fn mbedtls_x509_write_names(mut c:&mut[u8],buf:&mut Vec<u8>,head: &mbedtls_asn1_named_data)->i32{
0
}
pub fn MBEDTLS_OID_SIZE(i:i32)->i32{
0
}
pub fn mbedtls_asn1_write_oid(mut c:&mut[u8],buf:&mut Vec<u8>,ch:i32,ch2:i32)->i32{
    0
}
pub fn mbedtls_asn1_write_int(mut c:&mut[u8],buf:&mut Vec<u8>,mut len:i32)->i32{
0
}
pub fn mbedtls_x509_write_sig(mut c:&mut[u8],mut c2:&mut[u8],sig_oid:Vec<i8>,sig_oid_len:usize,sig:&mut Vec<u8>,sig_len:usize)->i32{
    0
}

pub fn psa_hash_setup(mut ho:&psa_hash_operation_t,mut hash_alg:psa_algorithm_t)->i32{
    0
}
pub fn psa_hash_update(mut ho:&psa_hash_operation_t,mut c: &mut[u8],len:usize)->i32{
    0
}
pub fn psa_hash_finish(mut ho:&psa_hash_operation_t,hash:[u8;64],size:i32,hash_len:&mut usize)->i32{
    0
}

pub fn mbedtls_md(r:i32,  mut c:&mut[u8], mut len:usize, mut hash:[u8;64])->i32{
    0
}

pub fn mbedtls_md_info_from_type(head: &mbedtls_md_type_t)->i32{
    0
}

pub fn mbedtls_pk_sign(head: &mbedtls_pk_context,head2: &mbedtls_md_type_t,hash:[u8;64],s:usize,sig:&mut Vec<u8>,sig_len:&mut usize,f_rng : fn ( &mut Vec <u8>, &mut [u8], usize ) -> i32, p_rng:&mut Vec <u8>)->i32{
    0
}
pub fn mbedtls_pk_can_do(head: &mbedtls_pk_context,k:mbedtls_pk_type_t)->i32{
    0
}
pub fn mbedtls_oid_get_oid_by_sig_alg(pk_alg:mbedtls_pk_type_t,head: &mbedtls_md_type_t,sig_oid:&Vec<i8>,sig_oid_len:&usize)->i32{
    0
}

  
pub fn mbedtls_pem_write_buffer(bg:&str,en:&str,buf:[u8],mut ret:i32,buf2:&mut Vec<u8>,mut size :usize,mut olen:&usize)->i32{
0
}

pub fn mbedtls_x509write_csr_free(mut ctx :&mut mbedtls_x509write_csr )
{
    mbedtls_asn1_free_named_data_list( &((*ctx).subject));
    mbedtls_asn1_free_named_data_list( &((*ctx).extensions));

    unsafe{
        write_bytes(ctx,0,1);
    }
   
}

pub fn mbedtls_x509write_csr_set_md_alg( mut ctx :&mut mbedtls_x509write_csr, md_alg : mbedtls_md_type_t  )
{
    (*ctx).md_alg = md_alg;
}

pub fn mbedtls_x509write_csr_set_key( mut ctx :&mut mbedtls_x509write_csr,mut key :  mbedtls_pk_context)
{
    (*ctx).key = key;
}

pub fn mbedtls_x509write_csr_set_subject_name( mut ctx :&mut mbedtls_x509write_csr, subject_name:Vec<u8> )->i32
{
    return mbedtls_x509_string_to_names( &mut((*ctx).subject), subject_name );
}

pub fn mbedtls_x509write_csr_set_extension( mut ctx :&mut mbedtls_x509write_csr,
                                 oid:i32,  oid_len:i32,
                                 val:&mut[u8],  val_len:usize )->i32
{
    return mbedtls_x509_set_extension( &((*ctx).extensions), oid, oid_len,
                               0, val, val_len );
}



pub fn mbedtls_x509write_csr_set_key_usage( mut ctx :&mut mbedtls_x509write_csr, key_usage:&mut u8 )->i32
{
    let mut buf:&mut Vec<u8>;
    let mut c:&mut[u8];
    let mut ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

   // c = buf + 4;
    c =&mut buf[4..];
    ret = mbedtls_asn1_write_named_bitstring( c, buf, &key_usage, 8 );
    if ret < 3 || ret > 4 {
        return ret;
    }
    ret = mbedtls_x509write_csr_set_extension( ctx, MBEDTLS_OID_KEY_USAGE,
                                       MBEDTLS_OID_SIZE( MBEDTLS_OID_KEY_USAGE ) ,
                                       c, ret as usize);
    if ret != 0 {
        return ret;
    }
    return 0;
}

pub fn mbedtls_x509write_csr_set_ns_cert_type( mut ctx :&mut mbedtls_x509write_csr,
                                    ns_cert_type:&mut u8 )->i32
{
    let mut buf:&mut Vec<u8>;
    let mut c:&mut[u8];
    let mut ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    c =&mut buf[4..];

    ret = mbedtls_asn1_write_named_bitstring( c, buf, &ns_cert_type, 8 );
    if ret < 3 || ret > 4 {
        return ret;
    }

    ret = mbedtls_x509write_csr_set_extension( ctx, MBEDTLS_OID_NS_CERT_TYPE[0],
                                       MBEDTLS_OID_SIZE( MBEDTLS_OID_NS_CERT_TYPE[0] ),
                                       c, ret as usize );
    if ret != 0 {
        return ret;
    }
    return 0;
}



pub fn  x509write_csr_der_internal( mut ctx :&mut mbedtls_x509write_csr,
    buf:&mut Vec<u8>,
    mut size :usize,
    sig:&mut Vec<u8>,
    f_rng : fn ( &mut Vec <u8>, &mut [u8], usize ) -> i32,
    p_rng:&mut Vec <u8> ) -> i32
{
    let mut ret:i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let sig_oid:Vec<i8>;//const char *sig_oid;
    let mut sig_oid_len:usize = 0;
    let mut c:&mut[u8];
    let mut c2:&mut[u8];//unsigned char *c, *c2;
    let mut hash:[u8;64];//unsigned char hash[64];
    let mut pub_len:usize=0;
    let mut sig_and_oid_len:usize=0;
    let mut sig_len:usize;    //size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
    let mut len:usize=0;

    let mut pk_alg:mbedtls_pk_type_t;
    //#if defined(MBEDTLS_USE_PSA_CRYPTO)
    let mut hash_operation:psa_hash_operation_t=PSA_HASH_OPERATION_INIT;//psa_hash_operation_t hash_operation = PSA_HASH_OPERATION_INIT;
    let mut hash_len:usize;//size_t hash_len;
    let mut hash_alg:psa_algorithm_t = mbedtls_psa_translate_md( &(*ctx).md_alg ); //psa_algorithm_t hash_alg = mbedtls_psa_translate_md( ctx->md_alg );
    //#endif /* MBEDTLS_USE_PSA_CRYPTO */

    /* Write the CSR backwards starting from the end of buf */
    c =&mut buf[size..];
    //mbedtls_x509_write_extensions( c, buf,&(*ctx).extensions );
    MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_x509_write_extensions( c, buf,&(*ctx).extensions ) );

    if len !=0
    {
        MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_len( c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD!( len,mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

        MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_len( c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD!( len,mbedtls_asn1_write_tag(c, buf,MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET ) );

        MBEDTLS_ASN1_CHK_ADD!( len,mbedtls_asn1_write_oid(c, buf, MBEDTLS_OID_PKCS9_CSR_EXT_REQ,MBEDTLS_OID_SIZE( MBEDTLS_OID_PKCS9_CSR_EXT_REQ ) ) );

        MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_len( c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD!( len,mbedtls_asn1_write_tag(c, buf,MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );
    }

    MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_len( c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) );

    MBEDTLS_ASN1_CHK_ADD!( pub_len, mbedtls_pk_write_pubkey_der( &(*ctx).key, buf, size ) );
    c= &mut buf[size-pub_len..];//c -= pub_len;
    len += pub_len;

    /*
    *  Subject  ::=  Name
    */
    MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_x509_write_names( c, buf, &(*ctx).subject ) );

    /*
    *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    */
    MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_int( c, buf, 0 ) );

    MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_len( c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD!( len,mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    /*
    * Sign the written CSR data into the sig buffer
    * Note: hash errors can happen only after an internal error
    */
    //#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if psa_hash_setup( &hash_operation, hash_alg ) != PSA_SUCCESS {
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    if psa_hash_update( &hash_operation, c, len ) != PSA_SUCCESS {
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    }

    if psa_hash_finish( &hash_operation, hash, 64, &mut hash_len )!= PSA_SUCCESS     {
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    //#else /* MBEDTLS_USE_PSA_CRYPTO */
    ret = mbedtls_md( mbedtls_md_info_from_type( &(*ctx).md_alg ), c, len, hash );
    if ret != 0 {
        return ret;
    }
    //#endif
    ret = mbedtls_pk_sign( &(*ctx).key, &(*ctx).md_alg, hash, 0, sig, &mut sig_len, f_rng, p_rng );
    if ret != 0 
    {
        return ret;
    }

    if mbedtls_pk_can_do( &(*ctx).key, MBEDTLS_PK_RSA ) != 0 {
        pk_alg = MBEDTLS_PK_RSA;
    }
    else if mbedtls_pk_can_do( &(*ctx).key, MBEDTLS_PK_ECDSA ) != 0 {
        pk_alg = MBEDTLS_PK_ECDSA;
    }
    else{
        return MBEDTLS_ERR_X509_INVALID_ALG;
    }
    
    ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, &(*ctx).md_alg, &sig_oid, &sig_oid_len );
    if  ret != 0 
    {
        return ret;
    }

    /*
    * Move the written CSR data to the start of buf to create space for
    * writing the signature into buf.
    */
    //memmove( buf, c, len );
    unsafe{
        write_bytes(buf,(*c)[0],len);
    }

    /*
    * Write sig and its OID into buf backwards from the end of buf.
    * Note: mbedtls_x509_write_sig will check for c2 - ( buf + len ) < sig_len
    * and return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL if needed.
    */
    c2 = &mut buf[size..];// buf + size;
    MBEDTLS_ASN1_CHK_ADD!( sig_and_oid_len, mbedtls_x509_write_sig( c2, &mut buf[size..], sig_oid, sig_oid_len, sig, sig_len ) );

    /*
    * Compact the space between the CSR data and signature by moving the
    * CSR data to the start of the signature.
    */
    c2= &mut buf[size-len..];// c2 -= len;
    unsafe{
        write_bytes(buf,size as u8,len);
    }

    //memmove( c2, buf, len );

    /* ASN encode the total size and tag the CSR data with it. */
    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_len( c2, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD!( len, mbedtls_asn1_write_tag( c2, buf,  MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    /* Zero the unused bytes at the start of buf */
    //memset( buf, 0, c2 - buf);
    unsafe{
        write_bytes(buf,0,size-len);
    }

    return len as i32 ;
}


pub fn mbedtls_x509write_csr_der( mut ctx :&mut mbedtls_x509write_csr,  buf:&mut Vec<u8>, mut size :usize, f_rng : fn ( &mut Vec <u8>, &mut [u8], usize ) -> i32, p_rng:&mut Vec <u8> ) -> i32
{
    let mut ret:i32;
    let mut sig:&mut Vec<u8>;//unsigned char *sig;
    //sig = mbedtls_calloc( 1, MBEDTLS_PK_SIGNATURE_MAX_SIZE );
    if sig[1] == 0 
    {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    ret = x509write_csr_der_internal( ctx, buf, size, sig, f_rng, p_rng );

    //mbedtls_free( sig );

    return ret;
}

//#define PEM_BEGIN_CSR           "-----BEGIN CERTIFICATE REQUEST-----\n"
//#define PEM_END_CSR             "-----END CERTIFICATE REQUEST-----\n"

//#if defined(MBEDTLS_PEM_WRITE_C)

pub fn mbedtls_x509write_csr_pem( mut ctx :&mut mbedtls_x509write_csr,  buf:&mut Vec<u8>, mut size :usize,f_rng : fn ( &mut Vec <u8>, &mut [u8], usize ) -> i32,p_rng:&mut Vec <u8> ) -> i32
{
    let mut ret:i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut olen:usize = 0;

    ret = mbedtls_x509write_csr_der( ctx, buf, size,f_rng, p_rng);
    if ret < 0 
    {
        return ret;
    }
    ret = mbedtls_pem_write_buffer( "-----BEGIN CERTIFICATE REQUEST-----\n", "-----END CERTIFICATE REQUEST-----\n",buf[size-ret as usize..], ret, buf, size, &olen );
    if ret != 0 
    {
        return ret;
    }

    return 0;
}
//#endif /* MBEDTLS_PEM_WRITE_C */

//#endif /* MBEDTLS_X509_CSR_WRITE_C */
