#[cfg(feature = "BIGNUM")]
use super::bignum;
#[allow(dead_code)]
#[allow(unused)]
use std::convert::TryFrom;
use std::convert::TryInto;
pub const ERR_ERROR_CORRUPTION_DETECTED: i32 = -0x006E;
pub const MAX: u32 = u32::MAX;
use crate::ans1::BIT_STRING;
use crate::ans1::BOOLEAN;
use crate::ans1::CONSTRUCTED;
use crate::ans1::ENUMERATED;
use crate::ans1::ERR_BUF_TOO_SMALL;
use crate::ans1::ERR_INVALID_LENGTH;
use crate::ans1::IA5_STRING;
use crate::ans1::INTEGER;
use crate::ans1::NULL;
use crate::ans1::OCTET_STRING;
use crate::ans1::OID;
use crate::ans1::PRINTABLE_STRING;
use crate::ans1::SEQUENCE;
use crate::ans1::UTF8_STRING;

macro_rules! CHK_ADD {
    ($b: expr, $h:expr) => {
         loop {
             let reti : i32;
            if (reti = (h)) < 0 {
                return (reti);
            } 
            else {
                (b) = (b) + reti;
            }
        }
    };
}

struct SBuffer {
    /// Buffer holding data
    buf: Vec<u8>,
    /// index for keeping track of location to be read
    ptr: usize,
}

impl SBuffer {
    fn copy(&self) -> SBuffer {
        let x = SBuffer {
            buf: self.buf[..].iter().cloned().collect(),
            ptr: self.ptr,
        };
        return x;
    }
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

impl NamedData {
    fn new() -> Box<NamedData> {
        return Box::new(NamedData {
            oid: Buf {
                tag: 0,
                len: 0,
                p: Vec::new(),
            },
            val: Buf {
                tag: 0,
                len: 0,
                p: Vec::new(),
            },
            next: None,

            next_merged: 0,
        });
    }
}

fn write_len(p: &mut SBuffer, start: &mut usize, len: &mut usize) -> i32 {
    if len < &mut 0x80 {
        if (p.ptr - *start) < 1 {
            return ERR_BUF_TOO_SMALL;
        }
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = *len as u8;
        return 1;
    }

    if len <= &mut 0xFF {
        if (p.ptr - *start) < 2 {
            return ERR_BUF_TOO_SMALL;
        }
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = *len as u8;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = 0x81;
        return 2;
    }

    if len <= &mut 0xFFFF {
        if (p.ptr - *start) < 3 {
            return ERR_BUF_TOO_SMALL;
        }
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = (*len as u8) & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = (*len >> 8) as u8 & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = 0x82;

        return 3;
    }

    if len <= &mut 0xFFFFFF {
        if (p.ptr - *start) < 4 {
            return ERR_BUF_TOO_SMALL;
        }
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = *len as u8 & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = (*len >> 8) as u8 & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = (*len >> 16) as u8 & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = 0x83;

        return 4;
    }

    if len <= &mut 0xFFFFFFFF {
        if (p.ptr - *start) < 5 {
            return ERR_BUF_TOO_SMALL;
        }
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = *len as u8 & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = (*len >> 8) as u8 & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = (*len >> 16) as u8 & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = (*len >> 24) as u8 & 0xFF;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = 0x84;
        return 5;
    }

    if MAX > (0xFFFFFFFF as i32).try_into().unwrap() {
        return ERR_INVALID_LENGTH;
    } else {
        return 0;
    }
}

fn write_tag(p: &mut SBuffer, start: &mut usize, tag: u8) -> i32 {
    if (p.ptr - *start) < 1 {
        return ERR_BUF_TOO_SMALL;
    }

    p.ptr = p.ptr - 1;
    p.buf[p.ptr] = tag;

    return 1;
}
fn write_raw_buffer(p: &mut SBuffer, start: &mut usize, buff: &mut Vec<u8>, size: usize) -> i32 {
    let mut len: usize = 0;

    if p.ptr < *start || (p.ptr - *start) < size {
        return ERR_BUF_TOO_SMALL;
    }

    len = size;
    p.ptr = p.ptr - len;
    for i in 0..(len - 1) {
        buff[i] = p.buf[i];
    }

    return len as i32;
}

#[cfg(feature = "BIGNUM")]

fn write_mpi(p: &mut SBuffer, start: &mut usize, x: &mut bignum::mpi) -> i32 {
    let mut ret: i32 = ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;

    //write the MPI
    //
    len = bignum::size(x);

    if p.ptr < start || (p.ptr - *start) < len {
        return ERR_BUF_TOO_SMALL;
    }

    p.ptr = p.ptr - len;
    CHK_ADD!(write_binary(x, p.ptr, len));

    if x.s == 1 && p.buf[p.ptr] & 0x80 {
        if (p.ptr - *start) < 1 {
            return ERR_BUF_TOO_SMALL;
        }

        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = 0x00;
        len = len + 1;
    }

    CHK_ADD!(len, write_len(p, start, len));
    CHK_ADD!(len, write_tag(p, start, INTEGER));

    return len as i32;
}

fn write_null(p: &mut SBuffer, start: &mut usize) -> i32 {
    let mut ret: i32 = ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;

    // Write NULL
    //
    CHK_ADD!(len, write_len(p, start, 0));
    CHK_ADD!(len, write_tag(p, start, NULL));
    return len as i32;
}

fn write_oid(p: &mut SBuffer, start: Vec<u8>, oid: &Vec<u8>, oid_len: usize) -> i32 {
    let mut ret: i32 = ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;

    CHK_ADD!(len, write_raw_buffer(p, start, oid, oid_len));
    CHK_ADD!(len, write_len(p, start, len));
    CHK_ADD!(len, write_len(p, start, OID));

    return len as i32;
}

fn write_algorithm_identifier(
    p: &mut SBuffer,
    start: Vec<u8>,
    oid: &Vec<u8>,
    oid_len: usize,
    par_len: usize,
) -> i32 {
    let mut ret: i32 = ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;

    if par_len == 0 {
        CHK_ADD!(len, write_null(p, start));
    } else {
        len = len + par_len;
    }

    CHK_ADD!(len, write_oid(p, start, oid, oid_len));
    CHK_ADD!(len, write_len(p, start, len));
    CHK_ADD!(len, write_tag(p, start, CONSTRUCTED | SEQUENCE));

    return len as i32;
}

fn write_bool(p: &mut SBuffer, start: &mut usize, boolean: i32) -> i32 {
    let mut ret: i32 = ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;

    if (p.ptr - *start) < 1 {
        return ERR_BUF_TOO_SMALL;
    }

    p.ptr = p.ptr - 1;
    if boolean == 0 {
        p.buf[p.ptr] = 255;
    } else {
        p.buf[p.ptr] = 0;
    }

    len = len + 1;

    CHK_ADD!(len, write_len(p, start, len));
    CHK_ADD!(len, write_tag(p, start, BOOLEAN));

    return len as i32;
}

fn write_tagged_int(p: &mut SBuffer, start: &mut usize, val: i32, tag: i32) -> i32 {
    let len: usize;

    loop {
        if (p.ptr - *start) < 1 {
            return ERR_BUF_TOO_SMALL;
        }
        len = len + 1;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = val as u8 & 0xFF;
        val >>= 8;

        if val <= 0 {
            break;
        }
    }

    if (p.buf[p.ptr] & 0x80) != 0 {
        if (p.ptr - *start) < 1 {
            return ERR_BUF_TOO_SMALL;
        }
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = 0x00;
        len = len + 1;
    }

    CHK_ADD!(len, write_len(p, start, len));
    CHK_ADD!(len, write_tag(p, start, len));

    return len as i32;
}

fn write_int(p: &mut SBuffer, start: &mut usize, val: i32) -> i32 {
    return write_tagged_int(p, start, val, INTEGER);
}

fn write_enum(p: &mut SBuffer, start: &mut usize, val: i32) -> i32 {
    return write_tagged_int(p, start, val, ENUMERATED);
}

fn write_tagged_string(
    p: &mut SBuffer,
    start: &mut usize,
    tag: i32,
    text: &mut usize,
    text_len: usize,
) -> i32 {
    let mut ret: i32 = ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;

    CHK_ADD!(len, write_raw_buffer(p, start, text, text_len));
    CHK_ADD!(len, write_len(p, start, len));
    CHK_ADD!(len, write_tag(p, start, tag));

    return len as i32;
}

fn write_printable_string(
    p: &mut SBuffer,
    start: &mut usize,
    text: &mut usize,
    text_len: usize,
) -> i32 {
    return write_tagged_string(p, start, PRINTABLE_STRING, text, text_len);
}

fn write_utf8_string(p: &mut SBuffer, start: &mut usize, text: &mut usize, text_len: usize) -> i32 {
    return write_tagged_string(p, start, UTF8_STRING, text, text_len);
}

fn write_ias_string(p: &mut SBuffer, start: &mut usize, text: &mut usize, text_len: usize) -> i32 {
    return write_tagged_string(p, start, IA5_STRING, text, text_len);
}

fn write_bitstring(p: &mut SBuffer, start: &mut usize, buff: &mut Vec<u8>, bits: usize) -> i32 {
    let mut ret: i32 = ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;
    let mut unused_bits: usize;
    let mut byte_len: usize;

    byte_len = (bits + 7) / 8;
    unused_bits = (byte_len * 8) - bits;

    if p.ptr < *start || (p.ptr - *start) < byte_len + 1 {
        return ERR_BUF_TOO_SMALL;
    }

    len = byte_len + 1;

    // Write the bitstring. Ensure the unsed bits are zeroed
    if byte_len > 0 {
        byte_len = byte_len - 1;
        p.ptr = p.ptr - 1;
        p.buf[p.ptr] = buff[byte_len] & !((0x1 << unused_bits) - 1);
        p.ptr = p.ptr - byte_len;
        for i in 0..(byte_len) {
            buff[i] = p.buf[i];
        }
    }
    // Write unused bits
    p.ptr = p.ptr - 1;
    p.buf[p.ptr] = unused_bits as u8;

    CHK_ADD!(len, write_len(p, start, len));
    CHK_ADD!(len, write_tag(p, start, BIT_STRING));

    return len as i32;
}

fn write_named_bitstring(p: &mut SBuffer, start: &mut usize, buff: usize, mut bits: usize) -> i32 {
    let mut unused_bits: usize;
    let mut byte_len: usize;
    let mut cur_byte: usize = 0;
    let mut cur_byte_shifted: u8 = 0;
    let mut bit: u8;

    byte_len = (bits + 7) / 8;
    unused_bits = (byte_len * 8) - bits;

    /*
     * Named bitstrings require that trailing 0s are excluded in the encoding
     * of the bitstring. Trailing 0s are considered part of the 'unused' bits
     * when encoding this value in the first content octet
     */
    if bits != 0 {
        cur_byte = buff + byte_len - 1;
        cur_byte_shifted = (cur_byte >> unused_bits) as u8;
    }

    loop {
        bit = cur_byte_shifted & 0x1;
        cur_byte_shifted >>= 1;

        if bit != 0 {
            break;
        }

        bits = bits - 1;

        if bits == 0 {
            break;
        }

        if (bits % 8) == 0 {
            cur_byte_shifted = (cur_byte - 1) as u8;
        }
    }
    return 0;
}

fn write_octet_string(p: &mut SBuffer, start: &mut usize, buff: &Vec<u8>, size: usize) -> i32 {
    let mut ret: i32 = ERR_ERROR_CORRUPTION_DETECTED;
    let mut len: usize = 0;

    CHK_ADD!(len, write_raw_buffer(p, start, buff, size));
    CHK_ADD!(len, write_len(p, start, len));
    CHK_ADD!(len, write_tag(p, start, OCTET_STRING));

    return len as i32;
}

fn cmp_(list: &Vec<u8>, oid: &Vec<u8>, len: usize) -> i32 {
    for i in 0..len {
        if list[i] != oid[i] {
            return 1;
        }
    }
    return 0;
}
/* This is a copy of the ASN.1 parsing function mbedtls_asn1_find_named_data(),
 * which is replicated to avoid a dependency ASN1_WRITE_C on ASN1_PARSE_C. */
fn find_named_data<'a>(
    mut list: &'a mut NamedData,
    oid: &Vec<u8>,
    len: usize,
) -> &'a mut NamedData {
    loop {
        // Note: following line is just a placeholder
        match &mut list.next {
            None => break,
            Some(x) => {
                if (list.oid.len == len) && cmp_(&list.oid.p, oid, len) == 0 {
                    break;
                }
                list = x;
            }
        };
    }

    return list;
}

fn find_stored_named_data<'a>(
    mut head: &'a mut NamedData,
    oid: &Vec<u8>,
    oid_len: usize,
    val: &Vec<u8>,
    val_len: usize,
) -> &'a mut NamedData {
    let my_null: &mut NamedData;
    let mut cur: &mut NamedData;
    cur = find_named_data(head, oid, oid_len);

    match &mut cur {
        Some(x) => {
            cur.next = Some(NamedData::new());
            cur.oid.len = oid_len;
            cur.oid.p = vec![0];

            for n in 0..(oid_len - 1) {
                cur.oid.p[n] = oid[n];
            }

            cur.val.len = val_len;

            if val_len != 0 {
                cur.val.p = vec![0];
            }
            cur.next = head;
            head = x;
        }
    };

    if cur.val.len != val_len {
        let p = vec![0];
        cur.val.p = p;
        cur.val.len = val_len;
    }

    for n in 0..val_len {
        cur.val.p[n] = val[n];
    }

    return cur;
}

