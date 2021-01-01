// Data structures
#[derive(Debug, Clone)]
pub struct CamelliaContext {
    pub nr: i32,
    pub rk: [u32; 68],
}

impl CamelliaContext {
    pub fn init(key: [u8; 16], keybits: u32) -> CamelliaContext {
        // Set nr
        let nr = 4;
        let rk = [0; 68];
        // Schedule Keys
        Self::key_schedule(&key);
        CamelliaContext { nr, rk }
    }
    fn key_schedule(key: &[u8]) {
        Self::camellia_feistel();
    }

    fn camellia_feistel() {}

    pub fn encrypt(&self, text: [u8; 16]) -> i32 {
        0
    }
    pub fn decrypt(&self, cipher_text: [u8; 16]) -> i32 {
        0
    }
}

// Constants
pub const SIGMA_CHARS: [[u8; 8]; 6] = [[0u8; 8]; 6];

pub const S_BOX: [[u32; 256]; 4] = [[0u32; 256]; 4];

//Util Functions
pub fn camellia_feistel() {}
pub fn test() {
    println!("====|| Camellia Cipher Algorithm ||====");
}
