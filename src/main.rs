#![allow(unused)]
#![allow(unused_imports)]

pub mod entropy;
use entropy::*;
use crate::entropy_header::*;
use crate::entropy_poll_header::*;

fn main() {

}


#[test]
fn entropy_add_source_func() {

    let mut ctx: mbedtls_entropy_context = Default::default();
    mbedtls_entropy_init(&mut ctx);
    let ret = mbedtls_entropy_add_source(&mut ctx, entropy_dummy_source, None, 16, MBEDTLS_ENTROPY_SOURCE_WEAK);
    assert_eq!(ret, 0);
}


#[test]
fn entropy_update_manual_func() {

    let mut ctx: mbedtls_entropy_context = Default::default();
    let mut buf: [u8; MBEDTLS_ENTROPY_BLOCK_SIZE] = [0; MBEDTLS_ENTROPY_BLOCK_SIZE];
    mbedtls_entropy_init(&mut ctx);
    let ret = mbedtls_entropy_update_manual(&mut ctx, &mut buf, MBEDTLS_ENTROPY_BLOCK_SIZE);
    assert_eq!(ret, 0);
}

#[test]
fn entropy_gather_internal_func() {

    let mut ctx: mbedtls_entropy_context = Default::default();
    mbedtls_entropy_init(&mut ctx);
    let ret = mbedtls_entropy_gather(&mut ctx);
    println!("{}", ret);
    assert_eq!(ret, 2);
}


#[test]
fn entropy_func() {

    let mut ctx: mbedtls_entropy_context = Default::default();
    mbedtls_entropy_init(&mut ctx);
    let mut buf: [u8; MBEDTLS_ENTROPY_BLOCK_SIZE] = [0; MBEDTLS_ENTROPY_BLOCK_SIZE];
    let ret = mbedtls_entropy_func(&mut ctx, &mut buf, MBEDTLS_ENTROPY_BLOCK_SIZE);
    assert_eq!(ret, 2);
}

#[test]
fn entropy_update_nv_seed() {

    let mut ctx: mbedtls_entropy_context = Default::default();
    mbedtls_entropy_init(&mut ctx);
    let ret = mbedtls_entropy_update_nv_seed(&mut ctx);
    assert_eq!(ret, 2);
}
