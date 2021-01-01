// Data structures
#[derive(Debug, Clone)]
pub struct CamelliaContext {
    pub nr: i32,
    pub rk: [u32; 68],
}

impl CamelliaContext {
    pub fn init(key: [u8; 16], keybits: u32) -> CamelliaContext {
        // Set nr
        let mut nr = 0;
        if keybits == 128 {
            nr = 3;
        } else if keybits == 256 {
            nr = 4;
        }
        let rk = [0; 68];
        // Schedule Keys
        Self::key_schedule(&key);
        CamelliaContext { nr, rk }
    }

    // Key Scheduler and key generating internal function
    fn key_schedule(key: &[u8]) {
        let mut kl: u32 = 0;
        let mut kr: u32 = 0;
        // Only use KA and KB if the key length is 192 or 256
        let mut ka: u32 = 0;
        let mut kb: u32 = 0;

        let mut subkeys: [[u32; 2]; 26] = Default::default();
        //kw1
        subkeys[0][0] = 0;
        //kw2
        subkeys[0][1] = 0;
        // For 128 bit
        Self::camellia_feistel();
    }

    // Perform Feistel operation used in encryption
    fn camellia_feistel() {}

    //Component of Camellia
    fn f(f_in: [u8; 8], f_out: &[u8; 8]) {}
    //Component of Camellia
    fn fl(fl_in: [u8; 8], fl_out: &[u8; 8]) {}
    //Component of Camellia and inverse of FL Function
    fn fl_inv(fl_inv_in: [u8; 8], fl_inv_out: &[u8; 8]) {}

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

pub fn test() {
    println!("====|| Camellia Cipher Algorithm ||====");
}
