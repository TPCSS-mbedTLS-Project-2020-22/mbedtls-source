// Data structures

// Operations
pub const ENCRYPT: i32 = 1;
pub const DECRYPT: i32 = 0;

// Bit Lengths
pub const _128_BIT: u32 = 128;
pub const _192_BIT: u32 = 192;
pub const _256_BIT: u32 = 256;

pub const ROUND_128: i32 = 3;
pub const ROUND_192: i32 = 4;
pub const ROUND_256: i32 = 4;

// Modes of operation

#[derive(Debug, Clone)]
pub struct CamelliaContext {
    pub nr: i32,
    pub rk: [u32; 68],
    pub active_mode: i32,
    key: [u8; 32],
    keybits: u32,
}

impl CamelliaContext {
    pub fn init(key: [u8; 32], key_bits: u32) -> CamelliaContext {
        // Set nr
        let mut nr = 0;
        if key_bits == _128_BIT {
            nr = ROUND_128;
        } else if key_bits == _256_BIT || key_bits == _192_BIT {
            nr = ROUND_192;
        } else {
            //error
            //MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA
        }
        // Round Keys Array
        let rk = [0; 68];
        let active_mode: i32 = Default::default();

        let keybits = key_bits;
        // Schedule Keys

        CamelliaContext {
            nr,
            rk,
            active_mode,
            key,
            keybits,
        }
    }

    pub fn get_uint32_be(t: &[u8], i: usize) -> u32 {
        (t[i] as u32) << 24 | (t[i + 1] as u32) << 16 | (t[i + 2] as u32) << 8 | (t[i + 3] as u32)
    }

    pub fn set_mode(&mut self, op_mode: i32) -> i32 {
        self.active_mode = op_mode;

        if op_mode == DECRYPT {
            Self::mbedtls_camellia_setkey_dec(&mut self.rk, &self.key, &self.nr, self.keybits);
        } else {
            Self::mbedtls_camellia_setkey_enc(&mut self.rk, &self.key, &self.nr, self.keybits);
        }
        1
    }

    // Key Scheduler and key generating internal function
    fn mbedtls_camellia_setkey_enc(rk: &mut [u32], key: &[u8], nr: &i32, key_bits: u32) {
        let mut t: [u8; 64] = [0; 64];
        let mut sigma: [[u32; 2]; 6] = Default::default();
        let mut kc: [u32; 16] = Default::default();
        let mut tk: [u32; 20] = Default::default();
        // let mut i32: i = 0;
        let idx: i32 = if *nr == ROUND_128 { 0 } else { 1 };

        /* Initialize temporary variable */
        for i in 0..(key_bits as usize / 8) {
            t[i] = key[i];
        }

        if key_bits == _192_BIT {
            for i in 0..8 {
                t[24 + i] = !t[16 + i];
            }
        }

        /* Prepare Sigma */
        for i in 0..6 {
            sigma[i as usize][0] = Self::get_uint32_be(&SIGMA_CHARS[i], 0);
            sigma[i as usize][1] = Self::get_uint32_be(&SIGMA_CHARS[i], 4);
        }

        /* Store KL, KR */
        for i in 0..8 {
            kc[i] = Self::get_uint32_be(&t, i * 4);
        }

        /* Generate KA */
        for i in 0..4 {
            kc[8 + i] = kc[i] ^ kc[4 + i];
        }

        let result = Self::camellia_feistel(&[kc[8], kc[9]], &sigma[0], &[kc[10], kc[11]]);
        kc[10] = result[0];
        kc[11] = result[1];

        let result = Self::camellia_feistel(&[kc[10], kc[11]], &sigma[1], &[kc[8], kc[9]]);

        kc[8] = result[0];
        kc[9] = result[1];
        //? Verified
        // println!("kc :{:?}", kc);

        for i in 0..4 {
            kc[8 + i] ^= kc[i];
        }
        //? Verified
        //  println!("kc :{:?}", kc);

        let result = Self::camellia_feistel(&[kc[8], kc[9]], &sigma[2], &[kc[10], kc[11]]);
        kc[10] = result[0];
        kc[11] = result[1];

        let result = Self::camellia_feistel(&[kc[10], kc[11]], &sigma[3], &[kc[8], kc[9]]);

        kc[8] = result[0];
        kc[9] = result[1];

        if key_bits > _128_BIT {
            /* Generate KB */
            for i in 0..4 {
                kc[12 + i] = kc[4 + i] ^ kc[8 + i];
            }
            let result = Self::camellia_feistel(&[kc[12], kc[13]], &sigma[4], &[kc[14], kc[15]]);
            kc[14] = result[0];
            kc[15] = result[1];

            let result = Self::camellia_feistel(&[kc[14], kc[15]], &sigma[5], &[kc[12], kc[13]]);

            kc[12] = result[0];
            kc[13] = result[1];

            // camellia_feistel(kc + 12, sigma[4], kc + 14);
            // camellia_feistel(kc + 14, sigma[5], kc + 12);
        }

        /* Manipulating KL */
        let mut offset: usize = 0;

        tk[0] = kc[offset * 4 + 0];
        tk[1] = kc[offset * 4 + 1];
        tk[2] = kc[offset * 4 + 2];
        tk[3] = kc[offset * 4 + 3];

        for i in 1..5 {
            // println!("i: {}", i);
            if SHIFTS[idx as usize][offset][i - 1] != 0 {
                let response = Self::rotl(&tk, (15 * (i as i32)) % 32);
                tk[i * 4] = response[0];
                tk[i * 4 + 1] = response[1];
                tk[i * 4 + 2] = response[2];
                tk[i * 4 + 3] = response[3];
            }
        }
        for i in 0..20 {
            if INDEXES[idx as usize][offset][i] != -1 {
                rk[INDEXES[idx as usize][offset][i] as usize] = tk[i];
            }
        }

        /* Manipulating KR */
        if key_bits > _128_BIT {
            offset = 1;

            tk[0] = kc[4 * offset];
            tk[1] = kc[4 * offset + 1];
            tk[2] = kc[4 * offset + 2];
            tk[3] = kc[4 * offset + 3];

            for i in 1..5 {
                if SHIFTS[idx as usize][offset][i - 1] != 0 {
                    let response = Self::rotl(&tk, ((15 * i) % 32) as i32);
                    tk[i * 4] = response[0];
                    tk[i * 4 + 1] = response[1];
                    tk[i * 4 + 2] = response[2];
                    tk[i * 4 + 3] = response[3];
                }
            }

            for i in 0..20 {
                if INDEXES[idx as usize][offset][i] != -1 {
                    rk[INDEXES[idx as usize][offset][i] as usize] = tk[i];
                }
            }
        }

        /* Manipulating KA */

        offset = 2;

        tk[0] = kc[4 * offset];
        tk[1] = kc[4 * offset + 1];
        tk[2] = kc[4 * offset + 2];
        tk[3] = kc[4 * offset + 3];

        for i in 1..5 {
            if SHIFTS[idx as usize][offset][i - 1] != 0 {
                let response = Self::rotl(&tk, ((15 * i) % 32) as i32);
                tk[i * 4] = response[0];
                tk[i * 4 + 1] = response[1];
                tk[i * 4 + 2] = response[2];
                tk[i * 4 + 3] = response[3];
            }
        }

        for i in 0..20 {
            if INDEXES[idx as usize][offset][i] != -1 {
                rk[INDEXES[idx as usize][offset][i] as usize] = tk[i];
            }
        }

        /* Manipulating KB */
        if key_bits > _128_BIT {
            offset = 3;

            tk[0] = kc[4 * offset];
            tk[1] = kc[4 * offset + 1];
            tk[2] = kc[4 * offset + 2];
            tk[3] = kc[4 * offset + 3];

            for i in 1..5 {
                if SHIFTS[idx as usize][offset][i - 1] != 0 {
                    let response = Self::rotl(&tk, ((15 * i) % 32) as i32);
                    tk[i * 4] = response[0];
                    tk[i * 4 + 1] = response[1];
                    tk[i * 4 + 2] = response[2];
                    tk[i * 4 + 3] = response[3];
                }
            }

            for i in 0..20 {
                if INDEXES[idx as usize][offset][i] != -1 {
                    rk[INDEXES[idx as usize][offset][i] as usize] = tk[i];
                }
            }
        }
        //* Transpose *//

        for i in 0..20 {
            if TRANSPOSES[idx as usize][i] != -1 {
                rk[(32 + 12 * idx + i as i32) as usize] = rk[TRANSPOSES[idx as usize][i] as usize];
            }
        }
    }

    fn mbedtls_camellia_setkey_dec(rk: &mut [u32], key: &[u8], nr: &i32, key_bits: u32) {
        Self::mbedtls_camellia_setkey_enc(rk, key, nr, key_bits);

        let idx: usize = if *nr == ROUND_128 { 0 } else { 1 };

        let mut dec_rk: [u32; 68] = [0; 68];

        let mut rindex = 0;
        let mut sindex = 24 * 2 + 8 * idx * 2;

        // println!("rindex:{} sindex:{}", rindex, sindex);

        dec_rk[rindex] = rk[sindex];
        rindex += 1;
        sindex += 1;
        dec_rk[rindex] = rk[sindex];
        rindex += 1;
        sindex += 1;
        dec_rk[rindex] = rk[sindex];
        rindex += 1;
        sindex += 1;
        dec_rk[rindex] = rk[sindex];
        rindex += 1;
        sindex += 1;

        // for loop initializations
        let mut i = 22 + 8 * idx;
        // println!("rindex:{} sindex:{}", rindex, sindex);

        sindex -= 6;
        while i > 0 {
            dec_rk[rindex] = rk[sindex];
            rindex += 1;
            sindex += 1;
            dec_rk[rindex] = rk[sindex];
            rindex += 1;
            sindex += 1;

            i = i - 1;
            sindex -= 4;
        }
        sindex -= 2;

        // println!("rindex:{} sindex:{}", rindex, sindex);

        dec_rk[rindex] = rk[sindex];
        rindex += 1;
        sindex += 1;
        dec_rk[rindex] = rk[sindex];
        rindex += 1;
        sindex += 1;
        dec_rk[rindex] = rk[sindex];
        rindex += 1;
        sindex += 1;
        dec_rk[rindex] = rk[sindex];

        for i in 0..68 {
            rk[i] = dec_rk[i];
        }
    }

    fn rotl(src: &[u32], shift: i32) -> [u32; 4] {
        let mut dest: [u32; 4] = Default::default();
        for i in 0..4 {
            dest[i] = src[i % 4] << (shift) ^ src[(i + 1) % 4] >> (32 - shift);
        }
        dest
    }

    pub fn camellia_feistel(x: &[u32], k: &[u32], z: &[u32]) -> [u32; 2] {
        let mut i0: u32;
        let mut i1: u32;
        let mut z: [u32; 2] = [z[0], z[1]];
        i0 = x[0] ^ k[0];
        i1 = x[1] ^ k[1];

        i0 = ((S_BOX[0][((i0 >> 24) & 0xFF) as usize] as u32) << 24)
            | ((S_BOX[1][((i0 >> 16) & 0xFF) as usize] as u32) << 16)
            | ((S_BOX[2][((i0 >> 8) & 0xFF) as usize] as u32) << 8)
            | (S_BOX[3][((i0) & 0xFF) as usize] as u32);

        i1 = ((S_BOX[1][((i1 >> 24) & 0xFF) as usize] as u32) << 24)
            | ((S_BOX[2][((i1 >> 16) & 0xFF) as usize] as u32) << 16)
            | ((S_BOX[3][((i1 >> 8) & 0xFF) as usize] as u32) << 8)
            | (S_BOX[0][((i1) & 0xFF) as usize] as u32);

        i0 ^= (i1 << 8) | (i1 >> 24);
        i1 ^= (i0 << 16) | (i0 >> 16);
        i0 ^= (i1 >> 8) | (i1 << 24);
        i1 ^= (i0 >> 8) | (i0 << 24);

        z[0] ^= i1;
        z[1] ^= i0;

        z
    }

    // Perform Feistel operation used in encryption
    #[cfg(feature = "camellia-ecb-mode")]
    pub fn mbedtls_camellia_crypt_ecb(&self, _text: [u8; 16]) -> [u8; 16] {
        //Temporary variable
        let mut x: [u32; 4] = [0; 4];

        // Round keys pointer
        let rk: &[u32; 68] = &self.rk;

        let text = u128::from_ne_bytes(_text).to_ne_bytes();

        x[0] = Self::get_uint32_be(&text, 0);
        x[1] = Self::get_uint32_be(&text, 4);
        x[2] = Self::get_uint32_be(&text, 8);
        x[3] = Self::get_uint32_be(&text, 12);

        //? Indexing Round Keys
        let mut rindex = 0;

        x[0] ^= rk[rindex];
        rindex += 1;
        x[1] ^= rk[rindex];
        rindex += 1;
        x[2] ^= rk[rindex];
        rindex += 1;
        x[3] ^= rk[rindex];
        rindex += 1;

        let mut nr = self.nr;
        while nr > 0 {
            nr -= 1;
            let response =
                Self::camellia_feistel(&[x[0], x[1]], &[rk[rindex], rk[rindex + 1]], &[x[2], x[3]]);
            x[2] = response[0];
            x[3] = response[1];
            rindex += 2;

            let response =
                Self::camellia_feistel(&[x[2], x[3]], &[rk[rindex], rk[rindex + 1]], &[x[0], x[1]]);
            x[0] = response[0];
            x[1] = response[1];
            rindex += 2;

            let response =
                Self::camellia_feistel(&[x[0], x[1]], &[rk[rindex], rk[rindex + 1]], &[x[2], x[3]]);
            x[2] = response[0];
            x[3] = response[1];
            rindex += 2;

            let response =
                Self::camellia_feistel(&[x[2], x[3]], &[rk[rindex], rk[rindex + 1]], &[x[0], x[1]]);
            x[0] = response[0];
            x[1] = response[1];
            rindex += 2;
            let response =
                Self::camellia_feistel(&[x[0], x[1]], &[rk[rindex], rk[rindex + 1]], &[x[2], x[3]]);
            x[2] = response[0];
            x[3] = response[1];
            rindex += 2;

            let response =
                Self::camellia_feistel(&[x[2], x[3]], &[rk[rindex], rk[rindex + 1]], &[x[0], x[1]]);
            x[0] = response[0];
            x[1] = response[1];
            rindex += 2;

            if nr > 0 {
                let fl_out = Self::fl([x[0], x[1]], &[rk[rindex], rk[rindex + 1]]);
                x[1] = fl_out[1];
                x[0] = fl_out[0];

                rindex += 2;

                let fl_out = Self::fl_inv([x[2], x[3]], &[rk[rindex], rk[rindex + 1]]);

                x[2] = fl_out[0];
                x[3] = fl_out[1];

                rindex += 2;
            }
        }

        x[2] ^= rk[rindex];
        rindex += 1;
        x[3] ^= rk[rindex];
        rindex += 1;
        x[0] ^= rk[rindex];
        rindex += 1;
        x[1] ^= rk[rindex];

        x[2] = u32::to_be(x[2]);
        x[1] = u32::to_be(x[1]);
        x[0] = u32::to_be(x[0]);
        x[3] = u32::to_be(x[3]);

        let mut out_temp_array: [[u8; 4]; 4] = [[0; 4]; 4];
        out_temp_array[0] = x[2].to_ne_bytes();
        out_temp_array[1] = x[3].to_ne_bytes();
        out_temp_array[2] = x[0].to_ne_bytes();
        out_temp_array[3] = x[1].to_ne_bytes();

        let mut out_array: [u8; 16] = [0; 16];
        for i in 0..4 {
            for j in 0..4 {
                out_array[4 * i + j] = out_temp_array[i][j];
            }
        }
        out_array
    }
    #[cfg(feature = "camellia-cbc-mode")]
    pub fn mbedtls_camellia_crypt_cbc(
        &self,
        mut iv: [u8; 16],
        mut length: u32,
        _text: Vec<u8>,
    ) -> Vec<u8> {
        if length % 16 != 0 {
            //Error
        }
        let mut input_index: usize = 0;
        let mut output: Vec<u8> = Vec::new();

        if self.active_mode == DECRYPT {
            while length > 0 {
                //Prepare Input
                let mut block_input: [u8; 16] = [0; 16];
                for i in 0..16 {
                    block_input[i] = _text[input_index + i];
                }

                let block_out = self.mbedtls_camellia_crypt_ecb(block_input);
                //Push to Output
                for i in 0..16 {
                    output.push(block_out[i] ^ iv[i]);
                }
                iv = block_input;

                input_index += 16;
                //outputIndex += 16;
                length -= 16;
            }
        } else {
            while length > 0 {
                //Prepare Input
                let mut block_input: [u8; 16] = [0; 16];

                for i in 0..16 {
                    block_input[i] = _text[input_index + i] ^ iv[i];
                }

                let block_out = self.mbedtls_camellia_crypt_ecb(block_input);

                //Push to Output
                for i in 0..16 {
                    output.push(block_out[i]);
                }
                iv = block_out;

                input_index += 16;
                // outputIndex += 16;
                length -= 16;
            }
        }

        output
    }
    #[cfg(feature = "camellia-cfb-mode")]
    pub fn mbedtls_camellia_crypt_cfb128(
        &self,
        mut iv: [u8; 16],
        iv_off: u32,
        mut length: u32,
        _text: Vec<u8>,
    ) -> Vec<u8> {
        let mut n = iv_off;
        if n >= 16 {
            //Error
        }

        let mut output: Vec<u8> = Vec::new();

        if self.active_mode == DECRYPT {
            let mut input_index: usize = 0;

            while length > 0 {
                if n == 0 {
                    iv = self.mbedtls_camellia_crypt_ecb(iv);
                }
                let c = _text[input_index];
                input_index += 1;
                output.push(c ^ iv[n as usize]);
                iv[n as usize] = c;

                n = (n + 1) & 0x0F;

                length -= 1;
            }
        } else {
        }

        output
    }
    #[cfg(feature = "camellia-ctr-mode")]
    pub fn mbedtls_camellia_crypt_ctr(
        &self,
        mut length: u32,
        nc_off: &mut u32,
        mut nonce_counter: [u8; 16],
        _text: Vec<u8>,
    ) -> Vec<u8> {
        let mut n = *nc_off;

        if n >= 16 {
            //Error
        }
        let mut output: Vec<u8> = Vec::new();
        let mut input_index: usize = 0;

        let mut stream_block: [u8; 16] = Default::default();

        while length > 0 {
            if n == 0 {
                stream_block = self.mbedtls_camellia_crypt_ecb(nonce_counter);

                for i in 0..16 {
                    nonce_counter[16 - (i + 1)] += 1;
                    if nonce_counter[16 - (i + 1)] != 0 {
                        break;
                    }
                }
            }
            let c = _text[input_index];
            input_index += 1;
            output.push(c ^ stream_block[n as usize]);

            n = (n + 1) & 0x0F;

            length -= 1;
        }
        *nc_off = n;
        output
    }
    //Component of Camellia
    pub fn f(f_in: u64, ke: u64) -> u64 {
        let x = f_in ^ ke;
        let mut t: [u8; 8] = x.to_ne_bytes();
        let mut y: [u8; 8] = [0; 8];
        t[0] = S_BOX[0][t[0] as usize];
        t[1] = S_BOX[1][t[1] as usize];
        t[2] = S_BOX[2][t[2] as usize];
        t[3] = S_BOX[3][t[3] as usize];
        t[4] = S_BOX[1][t[4] as usize];
        t[5] = S_BOX[2][t[5] as usize];
        t[6] = S_BOX[3][t[6] as usize];
        t[7] = S_BOX[0][t[7] as usize];

        y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
        y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
        y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
        y[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
        y[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
        y[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
        y[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
        y[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];

        let fo_out: u64 = ((y[0] as u64) << 56)
            | ((y[1] as u64) << 48)
            | ((y[2] as u64) << 40)
            | ((y[3] as u64) << 32)
            | ((y[4] as u64) << 24)
            | ((y[5] as u64) << 16)
            | ((y[6] as u64) << 8)
            | (y[7] as u64);

        fo_out
    }
    //Component of Camellia
    fn fl(fl_in: [u32; 2], keys: &[u32; 2]) -> [u32; 2] {
        let mut fl_out: [u32; 2] = [fl_in[0], fl_in[1]];
        fl_out[1] ^= (fl_out[0] & keys[0]).rotate_left(1);
        fl_out[0] ^= fl_out[1] | keys[1];
        fl_out
    }
    //Component of Camellia and inverse of FL Function
    fn fl_inv(fl_inv_in: [u32; 2], keys: &[u32; 2]) -> [u32; 2] {
        let mut fl_out: [u32; 2] = [fl_inv_in[0], fl_inv_in[1]];

        fl_out[0] ^= fl_out[1] | keys[1];
        fl_out[1] ^= ((fl_out[0] & keys[0]) << 1) | ((fl_out[0] & keys[0]) >> 31);

        fl_out
    }
}

// Constants
pub const SIGMA_CHARS: [[u8; 8]; 6] = [
    [0xa0, 0x9e, 0x66, 0x7f, 0x3b, 0xcc, 0x90, 0x8b],
    [0xb6, 0x7a, 0xe8, 0x58, 0x4c, 0xaa, 0x73, 0xb2],
    [0xc6, 0xef, 0x37, 0x2f, 0xe9, 0x4f, 0x82, 0xbe],
    [0x54, 0xff, 0x53, 0xa5, 0xf1, 0xd3, 0x6f, 0x1c],
    [0x10, 0xe5, 0x27, 0xfa, 0xde, 0x68, 0x2d, 0x1d],
    [0xb0, 0x56, 0x88, 0xc2, 0xb3, 0xe6, 0xc1, 0xfd],
];

pub const S_BOX: [[u8; 256]; 4] = [
    [
        112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65, 35, 239, 107,
        147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189, 134, 184, 175, 143, 124, 235, 31,
        206, 62, 48, 220, 95, 94, 197, 11, 26, 166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214,
        81, 86, 108, 77, 139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
        223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215, 20, 88, 58, 97,
        222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34, 254, 68, 207, 178, 195, 181, 122, 145,
        36, 8, 232, 168, 96, 252, 105, 80, 170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149,
        224, 255, 100, 210, 16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
        135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226, 82, 155, 216,
        38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46, 233, 121, 167, 140, 159, 110,
        188, 142, 41, 245, 249, 182, 47, 253, 180, 89, 120, 152, 6, 106, 231, 70, 113, 186, 212,
        37, 171, 66, 136, 162, 141, 250, 114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60,
        56, 241, 164, 64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158,
    ],
    [
        224, 5, 88, 217, 103, 78, 129, 203, 201, 11, 174, 106, 213, 24, 93, 130, 70, 223, 214, 39,
        138, 50, 75, 66, 219, 28, 158, 156, 58, 202, 37, 123, 13, 113, 95, 31, 248, 215, 62, 157,
        124, 96, 185, 190, 188, 139, 22, 52, 77, 195, 114, 149, 171, 142, 186, 122, 179, 2, 180,
        173, 162, 172, 216, 154, 23, 26, 53, 204, 247, 153, 97, 90, 232, 36, 86, 64, 225, 99, 9,
        51, 191, 152, 151, 133, 104, 252, 236, 10, 218, 111, 83, 98, 163, 46, 8, 175, 40, 176, 116,
        194, 189, 54, 34, 56, 100, 30, 57, 44, 166, 48, 229, 68, 253, 136, 159, 101, 135, 107, 244,
        35, 72, 16, 209, 81, 192, 249, 210, 160, 85, 161, 65, 250, 67, 19, 196, 47, 168, 182, 60,
        43, 193, 255, 200, 165, 32, 137, 0, 144, 71, 239, 234, 183, 21, 6, 205, 181, 18, 126, 187,
        41, 15, 184, 7, 4, 155, 148, 33, 102, 230, 206, 237, 231, 59, 254, 127, 197, 164, 55, 177,
        76, 145, 110, 141, 118, 3, 45, 222, 150, 38, 125, 198, 92, 211, 242, 79, 25, 63, 220, 121,
        29, 82, 235, 243, 109, 94, 251, 105, 178, 240, 49, 12, 212, 207, 140, 226, 117, 169, 74,
        87, 132, 17, 69, 27, 245, 228, 14, 115, 170, 241, 221, 89, 20, 108, 146, 84, 208, 120, 112,
        227, 73, 128, 80, 167, 246, 119, 147, 134, 131, 42, 199, 91, 233, 238, 143, 1, 61,
    ],
    [
        56, 65, 22, 118, 217, 147, 96, 242, 114, 194, 171, 154, 117, 6, 87, 160, 145, 247, 181,
        201, 162, 140, 210, 144, 246, 7, 167, 39, 142, 178, 73, 222, 67, 92, 215, 199, 62, 245,
        143, 103, 31, 24, 110, 175, 47, 226, 133, 13, 83, 240, 156, 101, 234, 163, 174, 158, 236,
        128, 45, 107, 168, 43, 54, 166, 197, 134, 77, 51, 253, 102, 88, 150, 58, 9, 149, 16, 120,
        216, 66, 204, 239, 38, 229, 97, 26, 63, 59, 130, 182, 219, 212, 152, 232, 139, 2, 235, 10,
        44, 29, 176, 111, 141, 136, 14, 25, 135, 78, 11, 169, 12, 121, 17, 127, 34, 231, 89, 225,
        218, 61, 200, 18, 4, 116, 84, 48, 126, 180, 40, 85, 104, 80, 190, 208, 196, 49, 203, 42,
        173, 15, 202, 112, 255, 50, 105, 8, 98, 0, 36, 209, 251, 186, 237, 69, 129, 115, 109, 132,
        159, 238, 74, 195, 46, 193, 1, 230, 37, 72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
        41, 205, 108, 19, 100, 155, 99, 157, 192, 75, 183, 165, 137, 95, 177, 23, 244, 188, 211,
        70, 207, 55, 94, 71, 148, 250, 252, 91, 151, 254, 90, 172, 60, 76, 3, 53, 243, 35, 184, 93,
        106, 146, 213, 33, 68, 81, 198, 125, 57, 131, 220, 170, 124, 119, 86, 5, 27, 164, 21, 52,
        30, 28, 248, 82, 32, 20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227, 64,
        79,
    ],
    [
        112, 44, 179, 192, 228, 87, 234, 174, 35, 107, 69, 165, 237, 79, 29, 146, 134, 175, 124,
        31, 62, 220, 94, 11, 166, 57, 213, 93, 217, 90, 81, 108, 139, 154, 251, 176, 116, 43, 240,
        132, 223, 203, 52, 118, 109, 169, 209, 4, 20, 58, 222, 17, 50, 156, 83, 242, 254, 207, 195,
        122, 36, 232, 96, 105, 170, 160, 161, 98, 84, 30, 224, 100, 16, 0, 163, 117, 138, 230, 9,
        221, 135, 131, 205, 144, 115, 246, 157, 191, 82, 216, 200, 198, 129, 111, 19, 99, 233, 167,
        159, 188, 41, 249, 47, 180, 120, 6, 231, 113, 212, 171, 136, 141, 114, 185, 248, 172, 54,
        42, 60, 241, 64, 211, 187, 67, 21, 173, 119, 128, 130, 236, 39, 229, 133, 53, 12, 65, 239,
        147, 25, 33, 14, 78, 101, 189, 184, 143, 235, 206, 48, 95, 197, 26, 225, 202, 71, 61, 1,
        214, 86, 77, 13, 102, 204, 45, 18, 32, 177, 153, 76, 194, 126, 5, 183, 49, 23, 215, 88, 97,
        27, 28, 15, 22, 24, 34, 68, 178, 181, 145, 8, 168, 252, 80, 208, 125, 137, 151, 91, 149,
        255, 210, 196, 72, 247, 219, 3, 218, 63, 148, 92, 2, 74, 51, 103, 243, 127, 226, 155, 38,
        55, 59, 150, 75, 190, 46, 121, 140, 110, 142, 245, 182, 253, 89, 152, 106, 70, 186, 37, 66,
        162, 250, 7, 85, 238, 10, 73, 104, 56, 164, 40, 123, 201, 193, 227, 244, 199, 158,
    ],
];

pub const SHIFTS: [[[usize; 4]; 4]; 2] = [
    [[1, 1, 1, 1], [0, 0, 0, 0], [1, 1, 1, 1], [0, 0, 0, 0]],
    [[1, 0, 1, 1], [1, 1, 0, 1], [1, 1, 1, 0], [1, 1, 0, 1]],
];

pub const INDEXES: [[[i32; 20]; 4]; 2] = [
    [
        [
            0, 1, 2, 3, 8, 9, 10, 11, 38, 39, 36, 37, 23, 20, 21, 22, 27, -1, -1, 26,
        ], /* KL -> rk */
        [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        ], /* KR -> rk */
        [
            4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, -1, 24, 25, -1, 31, 28, 29, 30,
        ], /* KA -> rk */
        [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        ], /* KB -> rk */
    ],
    [
        [
            0, 1, 2, 3, 61, 62, 63, 60, -1, -1, -1, -1, 27, 24, 25, 26, 35, 32, 33, 34,
        ], /* KL -> rk */
        [
            -1, -1, -1, -1, 8, 9, 10, 11, 16, 17, 18, 19, -1, -1, -1, -1, 39, 36, 37, 38,
        ], /* KR -> rk */
        [
            -1, -1, -1, -1, 12, 13, 14, 15, 58, 59, 56, 57, 31, 28, 29, 30, -1, -1, -1, -1,
        ], /* KA -> rk */
        [
            4, 5, 6, 7, 65, 66, 67, 64, 20, 21, 22, 23, -1, -1, -1, -1, 43, 40, 41, 42,
        ], /* KB -> rk */
    ],
];

pub const TRANSPOSES: [[i32; 20]; 2] = [
    [
        21, 22, 23, 20, -1, -1, -1, -1, 18, 19, 16, 17, 11, 8, 9, 10, 15, 12, 13, 14,
    ],
    [
        25, 26, 27, 24, 29, 30, 31, 28, 18, 19, 16, 17, -1, -1, -1, -1, -1, -1, -1, -1,
    ],
];

pub fn test() {
    println!("====|| Camellia Cipher Algorithm ||====");
}
