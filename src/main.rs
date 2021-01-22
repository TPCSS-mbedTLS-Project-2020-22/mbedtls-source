mod arc4c ;
use crate :: arc4c :: mbedtls_arc4_init;
use crate :: arc4c :: mbedtls_arc4_free;
use crate :: arc4c :: mbedtls_arc4_setup;
use crate :: arc4c :: mbedtls_arc4_crypt;
use arc4c::arc4;
use arc4:: mbedtls_arc4_context;

fn main()
{


let ibuf: &mut[u8; 8]=&mut[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
let  obuf: &mut[u8; 8]=&mut[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
let mut ctx: mbedtls_arc4_context = mbedtls_arc4_context { x : 0, y : 0, m: [0;256]};

mbedtls_arc4_init(&mut ctx);

const TEST_KEY: [[u8; 8]; 3] = [[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
                       [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
                       [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]];

const TEST_PT: [[u8; 8]; 3] = [[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
                                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]];

const TEST_CT: [[u8; 8]; 3] = [[ 0x75, 0xB7, 0x87, 0x80, 0x99, 0xE0, 0xC5, 0x96 ],
                                [ 0x74, 0x94, 0xC2, 0xE7, 0x10, 0x4B, 0x08, 0x79 ],
                                [0xDE, 0x18, 0x89, 0x41, 0xA3, 0x37, 0x5D, 0x3A ]];

    for i in 0..3
        {
            println!("ARC4 test  #{}", i+1);
            ibuf.copy_from_slice(&TEST_PT[i]);
            

            mbedtls_arc4_setup(&mut ctx, &TEST_KEY[i],8);
            mbedtls_arc4_crypt(&mut ctx, 8, ibuf, obuf);
           
            use std::cmp;
            fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
                    a.iter()
                    .zip(b)
                    .map(|(x, y)| x.cmp(y))                                  
                    .find(|&ord| ord != cmp::Ordering::Equal)
                    .unwrap_or(a.len().cmp(&b.len()))
            }
            assert_eq!(cmp::Ordering::Equal, compare(obuf.as_ref(), &TEST_CT[i]));

            println!("Passed. \n");
            

        }

        mbedtls_arc4_free(&mut ctx);

    
  
}