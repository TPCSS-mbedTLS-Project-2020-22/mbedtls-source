use mbed::cipher::camellia::*;
#[test]
fn initialize_camellia_cipher_128() {
    let keybits: u32 = 128;
    let key = [4u8; 16];
    let cipher = CamelliaContext::init(key, keybits);
    assert_eq!(3, cipher.nr);
}
#[test]
fn initialize_camellia_cipher_256() {
    let keybits: u32 = 256;
    let key = [4u8; 16];
    let cipher = CamelliaContext::init(key, keybits);
    assert_eq!(4, cipher.nr);
}
