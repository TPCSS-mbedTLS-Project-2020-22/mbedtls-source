use std::str;
use std::ptr;

use x509_header;
use asn1write_h;
use error_h;
use oid_h;

//Each and every reference in RUST has some associated lifetime with it, and the reference
//should not live longer than the referring variable.
//structure p has lifetime equal to character array, one of its member variable is referring to.

pub struct p<'a>                                 
{
    pub ptr: &'a [char;MBEDTLS_X509_MAX_DN_NAME_SIZE],
    pub iptr: usize
}


//We need a array of unsigned character where we can move forward and backward based on the current pointing index
//As pointer arithmetic is not safe we have used this new type p_char.
pub struct p_uchar<'a>                               //unsigned char*
{
    pub ptr: &'a mut Vec<u8>,
    pub iptr: usize
}

impl p_uchar{
    pub fn copy(&self) -> p_uchar {
        let x = p_uchar{ptr: self.ptr[..].iter().cloned().collect(), iptr: self.iptr};
        return x
    }
}

//This structure contains attributes corresponding to x509 certificates.
pub struct x509_attr_descriptor_t
{
    pub name: &'static str,     /* String representation of AttributeType, e.g.
                                * "CN" or "emailAddress". */
    pub name_len:usize,         /* Length of 'name', without trailing 0 byte. */
    pub oid: &'static str,      /* String representation of OID of AttributeType,*/  
    pub default_tag:usize       /* The default character encoding used for the
                                * given attribute type, e.g.
                                * MBEDTLS_ASN1_UTF8_STRING for UTF-8. */
}

//These are predefined attribute list of x509 certificate protocol.
pub const x509_attrs:[x509_attr_descriptor_t;28]=
[
    x509_attr_descriptor_t{name:"CN", name_len:"CN".len(), oid:MBEDTLS_OID_AT_CN, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"commonName", name_len:"commonName".len(), oid:MBEDTLS_OID_AT_CN, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"C", name_len:1, oid:MBEDTLS_OID_AT_COUNTRY, default_tag:MBEDTLS_ASN1_PRINTABLE_STRING},
    x509_attr_descriptor_t{name:"countryName", name_len:"countryName".len(), oid:MBEDTLS_OID_AT_COUNTRY, default_tag:MBEDTLS_ASN1_PRINTABLE_STRING},
    x509_attr_descriptor_t{name:"O", name_len:1, oid:MBEDTLS_OID_AT_ORGANIZATION, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"organizationName", name_len:"organizationName".len(), oid:MBEDTLS_OID_AT_ORGANIZATION, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"L", name_len:"L".len(), oid:MBEDTLS_OID_AT_LOCALITY, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"locality", name_len:"locality".len(), oid:MBEDTLS_OID_AT_LOCALITY, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"R", name_len:1, oid:MBEDTLS_OID_PKCS9_EMAIL, default_tag:MBEDTLS_ASN1_IA5_STRING},
    x509_attr_descriptor_t{name:"OU", name_len:2, oid:MBEDTLS_OID_AT_ORG_UNIT, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"organizationalUnitName", name_len:"organizationalUnitName".len(), oid:MBEDTLS_OID_AT_ORG_UNIT, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"ST", name_len:2, oid:MBEDTLS_OID_AT_STATE, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"stateOrProvinceName", name_len:"stateOrProvinceName".len(), oid:MBEDTLS_OID_AT_STATE, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"emailAddress", name_len:"emailAddress".len(), oid:MBEDTLS_OID_PKCS9_EMAIL, default_tag:MBEDTLS_ASN1_IA5_STRING},
    x509_attr_descriptor_t{name:"serialNumber", name_len:"serialNumber".len(), oid:MBEDTLS_OID_AT_SERIAL_NUMBER, default_tag:MBEDTLS_ASN1_PRINTABLE_STRING},
    x509_attr_descriptor_t{name:"postalAddress", name_len:"postalAddress".len(), oid:MBEDTLS_OID_AT_POSTAL_ADDRESS, default_tag:MBEDTLS_ASN1_PRINTABLE_STRING},
    x509_attr_descriptor_t{name:"postalCode", name_len:11, oid:MBEDTLS_OID_AT_POSTAL_CODE, default_tag:MBEDTLS_ASN1_PRINTABLE_STRING},
    x509_attr_descriptor_t{name:"dnQualifier", name_len:"postalCode".len(), oid:MBEDTLS_OID_AT_DN_QUALIFIER, default_tag:MBEDTLS_ASN1_PRINTABLE_STRING},
    x509_attr_descriptor_t{name:"title", name_len:5, oid:MBEDTLS_OID_AT_TITLE, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"surName", name_len:7, oid:MBEDTLS_OID_AT_SUR_NAME, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"SN", name_len:2, oid:MBEDTLS_OID_AT_SUR_NAME, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"givenName", name_len:9, oid:MBEDTLS_OID_AT_GIVEN_NAME, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"GN", name_len:2, oid:MBEDTLS_OID_AT_GIVEN_NAME, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"initials", name_len:8, oid:MBEDTLS_OID_AT_INITIALS, defualt_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"pseudonym", name_len:"pseudonym".len(), oid:MBEDTLS_OID_AT_PSEUDONYM, default_tag:MBEDTLS_ASN1_UTF8_STRING},
    x509_attr_descriptor_t{name:"generationQualifier", name_len:"generationQualifier".len(), oid:MBEDTLS_OID_AT_GENERATION_QUALIFIER, default_tag:MBEDTLS_ASN1_UTF8_STRING },
    x509_attr_descriptor_t{name:"domainComponent", name_len:"domainComponent".len(), oid:MBEDTLS_OID_DOMAIN_COMPONENT, default_tag:MBEDTLS_ASN1_IA5_STRING},
    x509_attr_descriptor_t{name:"DC", name_len:2, oid:MBEDTLS_OID_DOMAIN_COMPONENT, default_tag:MBEDTLS_ASN1_IA5_STRING}
];

fn main()
{

}

//This is the function which compares first 'n' characters of a string with other and returns 1 if matches else 0.
fn strncmp(str1:&str, str2:&str, cmplen:usize) -> i32               //new function instead library strncmp()
{
    for i in 0..cmplen
    {
        if str1.chars().nth(i).unwrap() != str2.chars().nth(i).unwrap()
        {
            return 0;
        }
    }
    return 1;
}

//This function returns arrtibute corresponding to the name provided as parameter into the function.
//This function also returns none when no any attribute is present with the given name.

//To deal with this two kinds of return value we have used Option<> enum which is a feature of rust.
//using match keyword we can take decision accordingly for an Option.
fn x509_attr_descr_from_name(name:&str,mut name_len:usize) -> Option<&x509_attr_descriptor_t>        //returning NULL & different type
{
    let mut i:usize = 0;
    while i<28
    {
        if x509_attrs[i].name_len == name_len && strncmp(x509_attrs[i].name, name, name_len) == 0
        {
            break;
        }
        i = i+1;
    }

    if i<28
    {
        return Some(&x509_attrs[i]);
    }

    return None;

}

fn mbedtls_x509_string_to_names(head: &mbedtls_asn1_named_data, name: &str) -> i32         
{
    let mut ret:i32 = 0;
    let s:&str = name;
    let c:&str = s;
    let end:&str  = &s[s.len()..]; 
    //changing end pointer to refer to other location of the string.

    let oid:&str = "\0";     
    //initializing object identifier to NULL.

    let attr_descr:&x509_attr_descriptor_t;
    let mut in_tag :i32 = 1;
    let mut data:p = p{ptr: & mut ['\0';MBEDTLS_X509_MAX_DN_NAME_SIZE] ,iptr:0}; 
    //initializing variable data of type p to default values all 0.

    let mut d:p  = p{ptr: data.ptr ,iptr:0};
    //new variable d of type p pointing to data, iptr = 0 means it has complete access over data.
    
    mbedtls_asn1_free_named_data_list( head );                                                      

    while c as *const str <= end as *const str
    {
        if in_tag==1 && c.chars().nth(0) == Some('=') 
        {
            match x509_attr_descr_from_name( s, c.len() - s.len() )                                
            {
                None =>
                {
                    ret = MBEDTLS_ERR_X509_UNKNOWN_OID;
                    //if passed string doesn't match in x509_attrs[] return unknown object identifier.
                    return  ret ;
                }
                Some(x) =>
                {
                    attr_descr = x;
                    oid = x.oid;
                    s = &c[1..];
                    in_tag = 0;
                    d.iptr = data.iptr;
                    //make d point to where data is pointing in character array.
                }
            }
        }

        if in_tag == 0 && c.chars().nth(0) == Some('\\') && c as *const str != end as *const str 
        {
            c = &c[1..];

            if c as *const str == end as *const str || c.chars().nth(0) != Some(',')           
            //checking if c and end are pointing to same location of the string.
            //also checking 1st character of string is currently 0 or not.
            {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                return ret;
            }
        }

        else if in_tag == 0 && ( c.chars().nth(0) == Some(',') || c as *const str == end as *const str ) 
        {
            match mbedtls_asn1_store_named_data( head, oid, oid.len(), data  /* (unsigned char *) data */, d.iptr - data.iptr ) 
                                                                                                        //faced challenge in converting user defined one type to another.  
            {
                None =>
                {
                    return MBEDTLS_ERR_X509_ALLOC_FAILED ;
                }
                Some(x) =>
                {
                    x.val.tag = attr_descr.default_tag;

                    while c as *const(str)  <  end as *const(str) && c.chars().nth(1) == Some(' ')          //less than comparison between two string pointers
                    {
                        c = &c[1..];
                    }
                    s = &c[1..];
                    in_tag = 1;
                }
            }
        }

        if in_tag == 0 && s as *const str != &c[1..] as *const str 
        {
            d.ptr[d.iptr] = c.chars().nth(0);
            d.iptr = d.iptr + 1;

            if d.iptr - data.iptr == MBEDTLS_X509_MAX_DN_NAME_SIZE 
            {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                return ret;
            }
        }

        c = &c[1..];
    }
    return; //extra added
}

fn mbedtls_x509_set_extension(head: &mbedtls_asn1_named_data, oid: &str, oid_len: usize, critical: i32, val : &p, val_len: usize ) -> i32
{
    let mut cur = mbedtls_asn1_store_named_data( head, oid, oid_len, '\0', val_len + 1 );

    match cur
    {
        None =>
        {
            return MBEDTLS_ERR_X509_ALLOC_FAILED ;
        }
        Some(x) =>
        {
            x.val.p[0] = critical;
            cur.val.p.ptr.slice(cur.val.p.iptr + 1 .. cur.val.p.iptr + 1 + val_len, val.ptr );          //make the original string as substring of its own
            return 0;
        }
    }

}

fn x509_write_name(p: &p_uchar, start: &p_uchar, cur_name: &mbedtls_asn1_named_data) -> usize
{
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;
    let oid: String = cur_name.oid.p;
    let mut oid_len: usize = cur_name.oid.len;
    let name: &p_uchar = cur_name.val.p;
    let name_len: usize = cur_name.val.len;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tagged_string( p, start, cur_name. val.tag, name, name_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid, oid_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED, MBEDTLS_ASN1_SET ) );

    return len;

}

fn mbedtls_x509_write_names( p: &p_uchar, start: &p_uchar, first: &mbedtls_asn1_named_data) -> i32
{
    let ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let len: usize = 0;
    let cur: &mbedtls_asn1_named_data = first;

    while( cur != NULL )
    {
        MBEDTLS_ASN1_CHK_ADD( len, x509_write_name( p, start, cur ) );
        cur = cur.next;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED, MBEDTLS_ASN1_SEQUENCE ) );

    return len as i32 ;
}

fn mbedtls_x509_write_sig(p: &p_uchar, start: &p_uchar, oid: &str, oid_len:usize, sig: *mut p_uchar, size: usize) -> i32
{
    let ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let len: usize = 0;

    if p.iptr < start.iptr || ( p.iptr - start.iptr ) < size 
    {
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
    }

    len = size;
    p.iptr -= len;

    ptr::copy_nonoverlapping(p, sig, len);                                              
    //This is equivalent to C memcpy() function

    if p.iptr - start.iptr < 1 
    {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL ;
    }
        
    p.ptr[p.iptr - 1] = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_BIT_STRING ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, oid, oid_len, 0 ) );

    return len as i32 ;

}

fn x509_write_extension( p: &p_uchar, start: &p_uchar, ext: &mbedtls_asn1_named_data) -> i32
{
    let ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let len:usize = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start, ext.val.p + 1, ext.val.len - 1 ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, ext.val.len - 1 ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );

    if( ext.val.p[0] != 0 )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_bool( p, start, 1 ) );
    }{

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start, ext.oid.p, ext.oid.len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, ext.oid.len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OID ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    return len as i32 ;
}

fn mbedtls_x509_write_extensions(p: &p_uchar, start: &p_uchar, first: &mbedtls_asn1_named_data) -> i32
{
    let ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let len = 0;
    let cur_ext = first;

    while cur_ext != '\0'
    {
        MBEDTLS_ASN1_CHK_ADD( len, x509_write_extension( p, start, cur_ext ) );
        cur_ext = cur_ext.next;
    }

    return len as i32;
}
