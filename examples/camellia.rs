use mbed::cipher::camellia::*;
fn main() {
    test();
    let keybits: u32 = 128;
    let key = [4u8; 16];

    let cipher = CamelliaContext::init(key, keybits);

    let encrypted_value: i32 = cipher.encrypt(key);

    println!("Encrypted Value of the text: {}", encrypted_value);

    let decrypted_value: i32 = cipher.decrypt(key);

    println!("Decrypted Value of the text: {}", decrypted_value);
}
