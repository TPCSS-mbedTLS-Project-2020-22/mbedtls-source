use std::mem;
pub const MBEDTLS_HAVEGE_COLLECT_SIZE:usize =  1024;
/*
 * HAVEGE state structure
 */
pub struct mbedtls_havege_state{
	pt1:u32,
	pt2:u32,
	offset:[i32;2],
	pool:[i32;MBEDTLS_HAVEGE_COLLECT_SIZE],	
	walk:[i32;8192]
}
impl mbedtls_havege_state{
    pub fn new(pt1: u32, pt2: u32,offset:[i32;2],pool:[i32;1024],walk:[i32;8192]) -> mbedtls_havege_state {
            mbedtls_havege_state{ pt1: pt1, pt2: pt2,offset:offset,pool:pool,walk:walk }
    }
}

/*
*CPU cycle counter. 
Here in our implementation we are using this dummy funtion 
to make our RNG/havege module independent module.
*/
 
fn mbedtls_timing_hardclock() -> i32{
    let num:i32= 10;
    num
}

/*
 * Entropy gathering function
 */
pub fn havege_fill(hs:&mut mbedtls_havege_state){
    let mut n:usize = 0;
    let mut i:usize;
    let mut U1:i32=0;
    let mut U2:i32=0;
    let mut res:[i32;16]=[0;16];
    let mut PTX:u32=0;
    let mut PTY:u32=0;
    let mut CLK:i32=0;
    let mut PTEST:u32;
    let mut IN:i32;
    while n < 4096{
        PTEST = hs.pt1 >> 20;
        
        if (PTEST & 1) != 0{
            PTEST ^= 3;
            PTEST >>= 1;
            if (PTEST & 1) != 0{
                PTEST ^= 3;
                PTEST >>= 1;
                if (PTEST & 1) != 0{
                    PTEST ^= 3;
                    PTEST >>= 1;
                    if (PTEST & 1) != 0{
                        PTEST ^= 3;
                        PTEST >>= 1;
                        if (PTEST & 1) != 0{
                            PTEST ^= 3;
                            PTEST >>= 1;
                            if (PTEST & 1) != 0{
                                PTEST ^= 3;
                                PTEST >>= 1;
                                if (PTEST & 1) != 0{
                                    PTEST ^= 3;
                                    PTEST >>= 1;
                                    if (PTEST & 1) != 0{
                                        PTEST ^= 3;
                                        PTEST >>= 1;
                                        if (PTEST & 1) != 0{
                                            PTEST ^= 3;
                                            PTEST >>= 1;
                                            if (PTEST & 1) != 0{
                                                PTEST ^= 3;
                                                PTEST >>= 1;
                                                if (PTEST & 1) != 0{
                                                    PTEST ^= 3;
                                                    PTEST >>= 1;
                                                    if (PTEST & 1) != 0{
                                                        PTEST ^= 3;
                                                        PTEST >>= 1;
                                                        U1+=1;
                                                    }
                                                    U1+=1;
                                                }
                                                U1+=1;
                                            }
                                            U1+=1;
                                        }
                                        U1+=1;
                                    }
                                    U1+=1;
                                }
                                U1+=1;
                            }
                            U1+=1;
                        }
                        U1+=1;
                    }
                    U1+=1;
                }
                U1+=1;
            }
            U1+=1;
        }
        
        PTX = (hs.pt1 >> 18) & 7;
        hs.pt1 &= 0x1FFF;
        hs.pt2 &= 0x1FFF;
        CLK = mbedtls_timing_hardclock();
        i=0;
        res[i] ^= hs.walk[hs.pt1 as usize];
        i+=1;
        res[i] ^= hs.walk[hs.pt2 as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 1) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 4) as usize];
        i+=1;
        IN = (hs.walk[hs.pt1 as usize] >> (1)) ^ (hs.walk[hs.pt1 as usize] << (31)) ^ CLK;
        
        hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt2 as usize] >> (2)) ^ (hs.walk[hs.pt2 as usize] << (30)) ^ CLK;
        hs.walk[hs.pt2 as usize] = IN ^ U1;                                       
        hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[(hs.pt1 ^ 1) as usize] >> (3)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (29)) ^ CLK;
        hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (4)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (28)) ^ CLK;
        res[i] ^= hs.walk[(hs.pt1 ^ 2) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 2) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 3) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 6) as usize];
        i+=1;
    
        if (PTEST & 1) != 0{
            IN = (hs.walk[(hs.pt1 ^ 1) as usize] >> (5)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (27)) ^ CLK;
            hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[hs.pt2 as usize] >> (6)) ^ (hs.walk[hs.pt2 as usize] << (26)) ^ CLK;
            hs.walk[hs.pt2 as usize] = IN; 
            CLK = mbedtls_timing_hardclock();
            hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt1 as usize] >> (7)) ^ (hs.walk[hs.pt1 as usize] << (25)) ^ CLK;
            hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (8)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (24)) ^ CLK;
        }
        else{
            IN = (hs.walk[hs.pt1 as usize] >> (5)) ^ (hs.walk[hs.pt1 as usize] << (27)) ^ CLK;
            hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt2 as usize] >> (6)) ^ (hs.walk[hs.pt2 as usize] << (26)) ^ CLK;
            hs.walk[hs.pt2 as usize] = IN; 
            CLK = mbedtls_timing_hardclock();
            hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[(hs.pt1 ^ 1) as usize] >> (7)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (25)) ^ CLK;
            hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (8)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (24)) ^ CLK;
        }
        PTEST = hs.pt2 >> 1;
        hs.pt2 = (res[((i - 8)as u32 ^ PTY) as usize] ^ hs.walk[(hs.pt2 ^ PTY ^ 7) as usize]) as u32;
        hs.pt2 = ((hs.pt2 & 0x1FFF) & (!8)) ^ ((hs.pt1 ^ 8) & 0x8);  
        PTY = (hs.pt2 >> 10) & 7;
        
        if (PTEST & 1) != 0{
            PTEST ^= 3;
            PTEST >>= 1;
            if (PTEST & 1) != 0{
                PTEST ^= 3;
                PTEST >>= 1;
                if (PTEST & 1) != 0{
                    PTEST ^= 3;
                    PTEST >>= 1;
                    if (PTEST & 1) != 0{
                        PTEST ^= 3;
                        PTEST >>= 1;
                        if (PTEST & 1) != 0{
                            PTEST ^= 3;
                            PTEST >>= 1;
                            if (PTEST & 1) != 0{
                                PTEST ^= 3;
                                PTEST >>= 1;
                                if (PTEST & 1) != 0{
                                    PTEST ^= 3;
                                    PTEST >>= 1;
                                    if (PTEST & 1) != 0{
                                        PTEST ^= 3;
                                        PTEST >>= 1;
                                        if (PTEST & 1) != 0{
                                            PTEST ^= 3;
                                            PTEST >>= 1;
                                            if (PTEST & 1) != 0{
                                                PTEST ^= 3;
                                                PTEST >>= 1;
                                                if (PTEST & 1) != 0{
                                                    PTEST ^= 3;
                                                    PTEST >>= 1;
                                                    if (PTEST & 1) != 0{
                                                        PTEST ^= 3;
                                                        PTEST >>= 1;
                                                        U2+=1;
                                                    }
                                                    U2+=1;
                                                }
                                                U2+=1;
                                            }
                                            U2+=1;
                                        }
                                        U2+=1;
                                    }
                                    U2+=1;
                                }
                                U2+=1;
                            }
                            U2+=1;
                        }
                        U2+=1;
                    }
                    U2+=1;
                }
                U2+=1;
            }
            U2+=1;
        }
        
        res[i] ^= hs.walk[(hs.pt1 ^ 4) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 1) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 5) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2^ 5) as usize];
        i+=1;
        
        IN = (hs.walk[(hs.pt1 ^ 4) as usize] >> ( 9)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (23)) ^ CLK;
        hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt2 ^ 1) as usize] >> (10)) ^ (hs.walk[(hs.pt2 ^ 1) as usize] << (22)) ^ CLK;
        hs.walk[(hs.pt2 ^ 1) as usize] = IN ^ U2;
        hs.walk[(hs.pt1 ^ 5) as usize] = (hs.walk[(hs.pt1 ^ 5) as usize] >> (11)) ^ (hs.walk[(hs.pt1 ^ 5) as usize] << (21)) ^ CLK;
        hs.walk[(hs.pt2^ 5) as usize] = (hs.walk[(hs.pt2^ 5) as usize] >> (12)) ^ (hs.walk[(hs.pt2^ 5) as usize] << (20)) ^ CLK;
        res[i] ^= hs.walk[(hs.pt1 ^ 6) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 3) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 7) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 7) as usize];
        i+=1;
        
        IN = (hs.walk[(hs.pt1 ^ 6) as usize] >> (13)) ^ (hs.walk[(hs.pt1 ^ 6) as usize] << (19)) ^ CLK;
        hs.walk[(hs.pt1 ^ 6) as usize] = (hs.walk[(hs.pt2 ^ 3) as usize] >> (14)) ^ (hs.walk[(hs.pt2 ^ 3) as usize] << (18)) ^ CLK;
        hs.walk[(hs.pt2 ^ 3) as usize] = IN;
        hs.walk[(hs.pt1 ^ 7) as usize] = (hs.walk[(hs.pt1 ^ 7) as usize] >> (15)) ^ (hs.walk[(hs.pt1 ^ 7) as usize] << (17)) ^ CLK;
        hs.walk[(hs.pt2 ^ 7) as usize] = (hs.walk[(hs.pt2 ^ 7) as usize] >> (16)) ^ (hs.walk[(hs.pt2 ^ 7) as usize] << (16)) ^ CLK;
        hs.pt1 = (( res[(( i - 8 )as u32 ^ PTX) as usize] ^ hs.walk[(hs.pt1 ^ PTX ^ 7) as usize] ) & (!1)) as u32;
        hs.pt1 ^= (hs.pt2 ^ 0x10) & 0x10;
        n+=1;
        for i in 0..16{
            hs.pool[n%1024] ^= res[i];
        }

        //iteration_2
        PTEST = hs.pt1 >> 20;
        
        if (PTEST & 1) != 0{
            PTEST ^= 3;
            PTEST >>= 1;
            if (PTEST & 1) != 0{
                PTEST ^= 3;
                PTEST >>= 1;
                if (PTEST & 1) != 0{
                    PTEST ^= 3;
                    PTEST >>= 1;
                    if (PTEST & 1) != 0{
                        PTEST ^= 3;
                        PTEST >>= 1;
                        if (PTEST & 1) != 0{
                            PTEST ^= 3;
                            PTEST >>= 1;
                            if (PTEST & 1) != 0{
                                PTEST ^= 3;
                                PTEST >>= 1;
                                if (PTEST & 1) != 0{
                                    PTEST ^= 3;
                                    PTEST >>= 1;
                                    if (PTEST & 1) != 0{
                                        PTEST ^= 3;
                                        PTEST >>= 1;
                                        if (PTEST & 1) != 0{
                                            PTEST ^= 3;
                                            PTEST >>= 1;
                                            if (PTEST & 1) != 0{
                                                PTEST ^= 3;
                                                PTEST >>= 1;
                                                if (PTEST & 1) != 0{
                                                    PTEST ^= 3;
                                                    PTEST >>= 1;
                                                    if (PTEST & 1) != 0{
                                                        PTEST ^= 3;
                                                        PTEST >>= 1;
                                                        U1+=1;
                                                    }
                                                    U1+=1;
                                                }
                                                U1+=1;
                                            }
                                            U1+=1;
                                        }
                                        U1+=1;
                                    }
                                    U1+=1;
                                }
                                U1+=1;
                            }
                            U1+=1;
                        }
                        U1+=1;
                    }
                    U1+=1;
                }
                U1+=1;
            }
            U1+=1;
        }
        
        PTX = (hs.pt1 >> 18) & 7;
        hs.pt1 &= 0x1FFF;
        hs.pt2 &= 0x1FFF;
        CLK = mbedtls_timing_hardclock();
        i=0;
        res[i] ^= hs.walk[hs.pt1 as usize];
        i+=1;
        res[i] ^= hs.walk[hs.pt2 as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 1) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 4) as usize];
        i+=1;
        IN = (hs.walk[hs.pt1 as usize] >> (1)) ^ (hs.walk[hs.pt1 as usize] << (31)) ^ CLK;
        
        hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt2 as usize] >> (2)) ^ (hs.walk[hs.pt2 as usize] << (30)) ^ CLK;
        hs.walk[hs.pt2 as usize] = IN ^ U1;                                       
        hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[(hs.pt1 ^ 1) as usize] >> (3)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (29)) ^ CLK;
        hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (4)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (28)) ^ CLK;
        res[i] ^= hs.walk[(hs.pt1 ^ 2) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 2) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 3) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 6) as usize];
        i+=1;
    
        if (PTEST & 1) != 0{
            IN = (hs.walk[(hs.pt1 ^ 1) as usize] >> (5)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (27)) ^ CLK;
            hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[hs.pt2 as usize] >> (6)) ^ (hs.walk[hs.pt2 as usize] << (26)) ^ CLK;
            hs.walk[hs.pt2 as usize] = IN; 
            CLK = mbedtls_timing_hardclock();
            hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt1 as usize] >> (7)) ^ (hs.walk[hs.pt1 as usize] << (25)) ^ CLK;
            hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (8)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (24)) ^ CLK;
        }
        else{
            IN = (hs.walk[hs.pt1 as usize] >> (5)) ^ (hs.walk[hs.pt1 as usize] << (27)) ^ CLK;
            hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt2 as usize] >> (6)) ^ (hs.walk[hs.pt2 as usize] << (26)) ^ CLK;
            hs.walk[hs.pt2 as usize] = IN; 
            CLK = mbedtls_timing_hardclock();
            hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[(hs.pt1 ^ 1) as usize] >> (7)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (25)) ^ CLK;
            hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (8)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (24)) ^ CLK;
        }
        PTEST = hs.pt2 >> 1;
        hs.pt2 = (res[((i - 8)as u32 ^ PTY) as usize] ^ hs.walk[(hs.pt2 ^ PTY ^ 7) as usize]) as u32;
        hs.pt2 = ((hs.pt2 & 0x1FFF) & (!8)) ^ ((hs.pt1 ^ 8) & 0x8);  
        PTY = (hs.pt2 >> 10) & 7;
        
        if (PTEST & 1) != 0{
            PTEST ^= 3;
            PTEST >>= 1;
            if (PTEST & 1) != 0{
                PTEST ^= 3;
                PTEST >>= 1;
                if (PTEST & 1) != 0{
                    PTEST ^= 3;
                    PTEST >>= 1;
                    if (PTEST & 1) != 0{
                        PTEST ^= 3;
                        PTEST >>= 1;
                        if (PTEST & 1) != 0{
                            PTEST ^= 3;
                            PTEST >>= 1;
                            if (PTEST & 1) != 0{
                                PTEST ^= 3;
                                PTEST >>= 1;
                                if (PTEST & 1) != 0{
                                    PTEST ^= 3;
                                    PTEST >>= 1;
                                    if (PTEST & 1) != 0{
                                        PTEST ^= 3;
                                        PTEST >>= 1;
                                        if (PTEST & 1) != 0{
                                            PTEST ^= 3;
                                            PTEST >>= 1;
                                            if (PTEST & 1) != 0{
                                                PTEST ^= 3;
                                                PTEST >>= 1;
                                                if (PTEST & 1) != 0{
                                                    PTEST ^= 3;
                                                    PTEST >>= 1;
                                                    if (PTEST & 1) != 0{
                                                        PTEST ^= 3;
                                                        PTEST >>= 1;
                                                        U2+=1;
                                                    }
                                                    U2+=1;
                                                }
                                                U2+=1;
                                            }
                                            U2+=1;
                                        }
                                        U2+=1;
                                    }
                                    U2+=1;
                                }
                                U2+=1;
                            }
                            U2+=1;
                        }
                        U2+=1;
                    }
                    U2+=1;
                }
                U2+=1;
            }
            U2+=1;
        }
        
        res[i] ^= hs.walk[(hs.pt1 ^ 4) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 1) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 5) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2^ 5) as usize];
        i+=1;
        
        IN = (hs.walk[(hs.pt1 ^ 4) as usize] >> ( 9)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (23)) ^ CLK;
        hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt2 ^ 1) as usize] >> (10)) ^ (hs.walk[(hs.pt2 ^ 1) as usize] << (22)) ^ CLK;
        hs.walk[(hs.pt2 ^ 1) as usize] = IN ^ U2;
        hs.walk[(hs.pt1 ^ 5) as usize] = (hs.walk[(hs.pt1 ^ 5) as usize] >> (11)) ^ (hs.walk[(hs.pt1 ^ 5) as usize] << (21)) ^ CLK;
        hs.walk[(hs.pt2^ 5) as usize] = (hs.walk[(hs.pt2^ 5) as usize] >> (12)) ^ (hs.walk[(hs.pt2^ 5) as usize] << (20)) ^ CLK;
        res[i] ^= hs.walk[(hs.pt1 ^ 6) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 3) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 7) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 7) as usize];
        i+=1;
        
        IN = (hs.walk[(hs.pt1 ^ 6) as usize] >> (13)) ^ (hs.walk[(hs.pt1 ^ 6) as usize] << (19)) ^ CLK;
        hs.walk[(hs.pt1 ^ 6) as usize] = (hs.walk[(hs.pt2 ^ 3) as usize] >> (14)) ^ (hs.walk[(hs.pt2 ^ 3) as usize] << (18)) ^ CLK;
        hs.walk[(hs.pt2 ^ 3) as usize] = IN;
        hs.walk[(hs.pt1 ^ 7) as usize] = (hs.walk[(hs.pt1 ^ 7) as usize] >> (15)) ^ (hs.walk[(hs.pt1 ^ 7) as usize] << (17)) ^ CLK;
        hs.walk[(hs.pt2 ^ 7) as usize] = (hs.walk[(hs.pt2 ^ 7) as usize] >> (16)) ^ (hs.walk[(hs.pt2 ^ 7) as usize] << (16)) ^ CLK;
        hs.pt1 = (( res[(( i - 8 )as u32 ^ PTX) as usize] ^ hs.walk[(hs.pt1 ^ PTX ^ 7) as usize] ) & (!1)) as u32;
        hs.pt1 ^= (hs.pt2 ^ 0x10) & 0x10;
        n+=1;
        for i in 0..16{
            hs.pool[n%1024] ^= res[i];
        }

        //iteration_3
        PTEST = hs.pt1 >> 20;
        
        if (PTEST & 1) != 0{
            PTEST ^= 3;
            PTEST >>= 1;
            if (PTEST & 1) != 0{
                PTEST ^= 3;
                PTEST >>= 1;
                if (PTEST & 1) != 0{
                    PTEST ^= 3;
                    PTEST >>= 1;
                    if (PTEST & 1) != 0{
                        PTEST ^= 3;
                        PTEST >>= 1;
                        if (PTEST & 1) != 0{
                            PTEST ^= 3;
                            PTEST >>= 1;
                            if (PTEST & 1) != 0{
                                PTEST ^= 3;
                                PTEST >>= 1;
                                if (PTEST & 1) != 0{
                                    PTEST ^= 3;
                                    PTEST >>= 1;
                                    if (PTEST & 1) != 0{
                                        PTEST ^= 3;
                                        PTEST >>= 1;
                                        if (PTEST & 1) != 0{
                                            PTEST ^= 3;
                                            PTEST >>= 1;
                                            if (PTEST & 1) != 0{
                                                PTEST ^= 3;
                                                PTEST >>= 1;
                                                if (PTEST & 1) != 0{
                                                    PTEST ^= 3;
                                                    PTEST >>= 1;
                                                    if (PTEST & 1) != 0{
                                                        PTEST ^= 3;
                                                        PTEST >>= 1;
                                                        U1+=1;
                                                    }
                                                    U1+=1;
                                                }
                                                U1+=1;
                                            }
                                            U1+=1;
                                        }
                                        U1+=1;
                                    }
                                    U1+=1;
                                }
                                U1+=1;
                            }
                            U1+=1;
                        }
                        U1+=1;
                    }
                    U1+=1;
                }
                U1+=1;
            }
            U1+=1;
        }
        
        PTX = (hs.pt1 >> 18) & 7;
        hs.pt1 &= 0x1FFF;
        hs.pt2 &= 0x1FFF;
        CLK = mbedtls_timing_hardclock();
        i=0;
        res[i] ^= hs.walk[hs.pt1 as usize];
        i+=1;
        res[i] ^= hs.walk[hs.pt2 as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 1) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 4) as usize];
        i+=1;
        IN = (hs.walk[hs.pt1 as usize] >> (1)) ^ (hs.walk[hs.pt1 as usize] << (31)) ^ CLK;
        
        hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt2 as usize] >> (2)) ^ (hs.walk[hs.pt2 as usize] << (30)) ^ CLK;
        hs.walk[hs.pt2 as usize] = IN ^ U1;                                       
        hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[(hs.pt1 ^ 1) as usize] >> (3)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (29)) ^ CLK;
        hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (4)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (28)) ^ CLK;
        res[i] ^= hs.walk[(hs.pt1 ^ 2) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 2) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 3) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 6) as usize];
        i+=1;
    
        if (PTEST & 1) != 0{
            IN = (hs.walk[(hs.pt1 ^ 1) as usize] >> (5)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (27)) ^ CLK;
            hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[hs.pt2 as usize] >> (6)) ^ (hs.walk[hs.pt2 as usize] << (26)) ^ CLK;
            hs.walk[hs.pt2 as usize] = IN; 
            CLK = mbedtls_timing_hardclock();
            hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt1 as usize] >> (7)) ^ (hs.walk[hs.pt1 as usize] << (25)) ^ CLK;
            hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (8)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (24)) ^ CLK;
        }
        else{
            IN = (hs.walk[hs.pt1 as usize] >> (5)) ^ (hs.walk[hs.pt1 as usize] << (27)) ^ CLK;
            hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt2 as usize] >> (6)) ^ (hs.walk[hs.pt2 as usize] << (26)) ^ CLK;
            hs.walk[hs.pt2 as usize] = IN; 
            CLK = mbedtls_timing_hardclock();
            hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[(hs.pt1 ^ 1) as usize] >> (7)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (25)) ^ CLK;
            hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (8)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (24)) ^ CLK;
        }
        PTEST = hs.pt2 >> 1;
        hs.pt2 = (res[((i - 8)as u32 ^ PTY) as usize] ^ hs.walk[(hs.pt2 ^ PTY ^ 7) as usize]) as u32;
        hs.pt2 = ((hs.pt2 & 0x1FFF) & (!8)) ^ ((hs.pt1 ^ 8) & 0x8);  
        PTY = (hs.pt2 >> 10) & 7;
        
        if (PTEST & 1) != 0{
            PTEST ^= 3;
            PTEST >>= 1;
            if (PTEST & 1) != 0{
                PTEST ^= 3;
                PTEST >>= 1;
                if (PTEST & 1) != 0{
                    PTEST ^= 3;
                    PTEST >>= 1;
                    if (PTEST & 1) != 0{
                        PTEST ^= 3;
                        PTEST >>= 1;
                        if (PTEST & 1) != 0{
                            PTEST ^= 3;
                            PTEST >>= 1;
                            if (PTEST & 1) != 0{
                                PTEST ^= 3;
                                PTEST >>= 1;
                                if (PTEST & 1) != 0{
                                    PTEST ^= 3;
                                    PTEST >>= 1;
                                    if (PTEST & 1) != 0{
                                        PTEST ^= 3;
                                        PTEST >>= 1;
                                        if (PTEST & 1) != 0{
                                            PTEST ^= 3;
                                            PTEST >>= 1;
                                            if (PTEST & 1) != 0{
                                                PTEST ^= 3;
                                                PTEST >>= 1;
                                                if (PTEST & 1) != 0{
                                                    PTEST ^= 3;
                                                    PTEST >>= 1;
                                                    if (PTEST & 1) != 0{
                                                        PTEST ^= 3;
                                                        PTEST >>= 1;
                                                        U2+=1;
                                                    }
                                                    U2+=1;
                                                }
                                                U2+=1;
                                            }
                                            U2+=1;
                                        }
                                        U2+=1;
                                    }
                                    U2+=1;
                                }
                                U2+=1;
                            }
                            U2+=1;
                        }
                        U2+=1;
                    }
                    U2+=1;
                }
                U2+=1;
            }
            U2+=1;
        }
        
        res[i] ^= hs.walk[(hs.pt1 ^ 4) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 1) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 5) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2^ 5) as usize];
        i+=1;
        
        IN = (hs.walk[(hs.pt1 ^ 4) as usize] >> ( 9)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (23)) ^ CLK;
        hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt2 ^ 1) as usize] >> (10)) ^ (hs.walk[(hs.pt2 ^ 1) as usize] << (22)) ^ CLK;
        hs.walk[(hs.pt2 ^ 1) as usize] = IN ^ U2;
        hs.walk[(hs.pt1 ^ 5) as usize] = (hs.walk[(hs.pt1 ^ 5) as usize] >> (11)) ^ (hs.walk[(hs.pt1 ^ 5) as usize] << (21)) ^ CLK;
        hs.walk[(hs.pt2^ 5) as usize] = (hs.walk[(hs.pt2^ 5) as usize] >> (12)) ^ (hs.walk[(hs.pt2^ 5) as usize] << (20)) ^ CLK;
        res[i] ^= hs.walk[(hs.pt1 ^ 6) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 3) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 7) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 7) as usize];
        i+=1;
        
        IN = (hs.walk[(hs.pt1 ^ 6) as usize] >> (13)) ^ (hs.walk[(hs.pt1 ^ 6) as usize] << (19)) ^ CLK;
        hs.walk[(hs.pt1 ^ 6) as usize] = (hs.walk[(hs.pt2 ^ 3) as usize] >> (14)) ^ (hs.walk[(hs.pt2 ^ 3) as usize] << (18)) ^ CLK;
        hs.walk[(hs.pt2 ^ 3) as usize] = IN;
        hs.walk[(hs.pt1 ^ 7) as usize] = (hs.walk[(hs.pt1 ^ 7) as usize] >> (15)) ^ (hs.walk[(hs.pt1 ^ 7) as usize] << (17)) ^ CLK;
        hs.walk[(hs.pt2 ^ 7) as usize] = (hs.walk[(hs.pt2 ^ 7) as usize] >> (16)) ^ (hs.walk[(hs.pt2 ^ 7) as usize] << (16)) ^ CLK;
        hs.pt1 = (( res[(( i - 8 )as u32 ^ PTX) as usize] ^ hs.walk[(hs.pt1 ^ PTX ^ 7) as usize] ) & (!1)) as u32;
        hs.pt1 ^= (hs.pt2 ^ 0x10) & 0x10;
        n+=1;
        for i in 0..16{
            hs.pool[n%1024] ^= res[i];
        }

        //iteration_4
        PTEST = hs.pt1 >> 20;
        
        if (PTEST & 1) != 0{
            PTEST ^= 3;
            PTEST >>= 1;
            if (PTEST & 1) != 0{
                PTEST ^= 3;
                PTEST >>= 1;
                if (PTEST & 1) != 0{
                    PTEST ^= 3;
                    PTEST >>= 1;
                    if (PTEST & 1) != 0{
                        PTEST ^= 3;
                        PTEST >>= 1;
                        if (PTEST & 1) != 0{
                            PTEST ^= 3;
                            PTEST >>= 1;
                            if (PTEST & 1) != 0{
                                PTEST ^= 3;
                                PTEST >>= 1;
                                if (PTEST & 1) != 0{
                                    PTEST ^= 3;
                                    PTEST >>= 1;
                                    if (PTEST & 1) != 0{
                                        PTEST ^= 3;
                                        PTEST >>= 1;
                                        if (PTEST & 1) != 0{
                                            PTEST ^= 3;
                                            PTEST >>= 1;
                                            if (PTEST & 1) != 0{
                                                PTEST ^= 3;
                                                PTEST >>= 1;
                                                if (PTEST & 1) != 0{
                                                    PTEST ^= 3;
                                                    PTEST >>= 1;
                                                    if (PTEST & 1) != 0{
                                                        PTEST ^= 3;
                                                        PTEST >>= 1;
                                                        U1+=1;
                                                    }
                                                    U1+=1;
                                                }
                                                U1+=1;
                                            }
                                            U1+=1;
                                        }
                                        U1+=1;
                                    }
                                    U1+=1;
                                }
                                U1+=1;
                            }
                            U1+=1;
                        }
                        U1+=1;
                    }
                    U1+=1;
                }
                U1+=1;
            }
            U1+=1;
        }
        
        PTX = (hs.pt1 >> 18) & 7;
        hs.pt1 &= 0x1FFF;
        hs.pt2 &= 0x1FFF;
        CLK = mbedtls_timing_hardclock();
        i=0;
        res[i] ^= hs.walk[hs.pt1 as usize];
        i+=1;
        res[i] ^= hs.walk[hs.pt2 as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 1) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 4) as usize];
        i+=1;
        IN = (hs.walk[hs.pt1 as usize] >> (1)) ^ (hs.walk[hs.pt1 as usize] << (31)) ^ CLK;
        
        hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt2 as usize] >> (2)) ^ (hs.walk[hs.pt2 as usize] << (30)) ^ CLK;
        hs.walk[hs.pt2 as usize] = IN ^ U1;                                       
        hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[(hs.pt1 ^ 1) as usize] >> (3)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (29)) ^ CLK;
        hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (4)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (28)) ^ CLK;
        res[i] ^= hs.walk[(hs.pt1 ^ 2) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 2) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 3) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 6) as usize];
        i+=1;
    
        if (PTEST & 1) != 0{
            IN = (hs.walk[(hs.pt1 ^ 1) as usize] >> (5)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (27)) ^ CLK;
            hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[hs.pt2 as usize] >> (6)) ^ (hs.walk[hs.pt2 as usize] << (26)) ^ CLK;
            hs.walk[hs.pt2 as usize] = IN; 
            CLK = mbedtls_timing_hardclock();
            hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt1 as usize] >> (7)) ^ (hs.walk[hs.pt1 as usize] << (25)) ^ CLK;
            hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (8)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (24)) ^ CLK;
        }
        else{
            IN = (hs.walk[hs.pt1 as usize] >> (5)) ^ (hs.walk[hs.pt1 as usize] << (27)) ^ CLK;
            hs.walk[hs.pt1 as usize] = (hs.walk[hs.pt2 as usize] >> (6)) ^ (hs.walk[hs.pt2 as usize] << (26)) ^ CLK;
            hs.walk[hs.pt2 as usize] = IN; 
            CLK = mbedtls_timing_hardclock();
            hs.walk[(hs.pt1 ^ 1) as usize] = (hs.walk[(hs.pt1 ^ 1) as usize] >> (7)) ^ (hs.walk[(hs.pt1 ^ 1) as usize] << (25)) ^ CLK;
            hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt1 ^ 4) as usize] >> (8)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (24)) ^ CLK;
        }
        PTEST = hs.pt2 >> 1;
        hs.pt2 = (res[((i - 8)as u32 ^ PTY) as usize] ^ hs.walk[(hs.pt2 ^ PTY ^ 7) as usize]) as u32;
        hs.pt2 = ((hs.pt2 & 0x1FFF) & (!8)) ^ ((hs.pt1 ^ 8) & 0x8);  
        PTY = (hs.pt2 >> 10) & 7;
        
        if (PTEST & 1) != 0{
            PTEST ^= 3;
            PTEST >>= 1;
            if (PTEST & 1) != 0{
                PTEST ^= 3;
                PTEST >>= 1;
                if (PTEST & 1) != 0{
                    PTEST ^= 3;
                    PTEST >>= 1;
                    if (PTEST & 1) != 0{
                        PTEST ^= 3;
                        PTEST >>= 1;
                        if (PTEST & 1) != 0{
                            PTEST ^= 3;
                            PTEST >>= 1;
                            if (PTEST & 1) != 0{
                                PTEST ^= 3;
                                PTEST >>= 1;
                                if (PTEST & 1) != 0{
                                    PTEST ^= 3;
                                    PTEST >>= 1;
                                    if (PTEST & 1) != 0{
                                        PTEST ^= 3;
                                        PTEST >>= 1;
                                        if (PTEST & 1) != 0{
                                            PTEST ^= 3;
                                            PTEST >>= 1;
                                            if (PTEST & 1) != 0{
                                                PTEST ^= 3;
                                                PTEST >>= 1;
                                                if (PTEST & 1) != 0{
                                                    PTEST ^= 3;
                                                    PTEST >>= 1;
                                                    if (PTEST & 1) != 0{
                                                        PTEST ^= 3;
                                                        PTEST >>= 1;
                                                        U2+=1;
                                                    }
                                                    U2+=1;
                                                }
                                                U2+=1;
                                            }
                                            U2+=1;
                                        }
                                        U2+=1;
                                    }
                                    U2+=1;
                                }
                                U2+=1;
                            }
                            U2+=1;
                        }
                        U2+=1;
                    }
                    U2+=1;
                }
                U2+=1;
            }
            U2+=1;
        }
        
        res[i] ^= hs.walk[(hs.pt1 ^ 4) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 1) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 5) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2^ 5) as usize];
        i+=1;
        
        IN = (hs.walk[(hs.pt1 ^ 4) as usize] >> ( 9)) ^ (hs.walk[(hs.pt1 ^ 4) as usize] << (23)) ^ CLK;
        hs.walk[(hs.pt1 ^ 4) as usize] = (hs.walk[(hs.pt2 ^ 1) as usize] >> (10)) ^ (hs.walk[(hs.pt2 ^ 1) as usize] << (22)) ^ CLK;
        hs.walk[(hs.pt2 ^ 1) as usize] = IN ^ U2;
        hs.walk[(hs.pt1 ^ 5) as usize] = (hs.walk[(hs.pt1 ^ 5) as usize] >> (11)) ^ (hs.walk[(hs.pt1 ^ 5) as usize] << (21)) ^ CLK;
        hs.walk[(hs.pt2^ 5) as usize] = (hs.walk[(hs.pt2^ 5) as usize] >> (12)) ^ (hs.walk[(hs.pt2^ 5) as usize] << (20)) ^ CLK;
        res[i] ^= hs.walk[(hs.pt1 ^ 6) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 3) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt1 ^ 7) as usize];
        i+=1;
        res[i] ^= hs.walk[(hs.pt2 ^ 7) as usize];
        i+=1;
        
        IN = (hs.walk[(hs.pt1 ^ 6) as usize] >> (13)) ^ (hs.walk[(hs.pt1 ^ 6) as usize] << (19)) ^ CLK;
        hs.walk[(hs.pt1 ^ 6) as usize] = (hs.walk[(hs.pt2 ^ 3) as usize] >> (14)) ^ (hs.walk[(hs.pt2 ^ 3) as usize] << (18)) ^ CLK;
        hs.walk[(hs.pt2 ^ 3) as usize] = IN;
        hs.walk[(hs.pt1 ^ 7) as usize] = (hs.walk[(hs.pt1 ^ 7) as usize] >> (15)) ^ (hs.walk[(hs.pt1 ^ 7) as usize] << (17)) ^ CLK;
        hs.walk[(hs.pt2 ^ 7) as usize] = (hs.walk[(hs.pt2 ^ 7) as usize] >> (16)) ^ (hs.walk[(hs.pt2 ^ 7) as usize] << (16)) ^ CLK;
        hs.pt1 = (( res[(( i - 8 )as u32 ^ PTX) as usize] ^ hs.walk[(hs.pt1 ^ PTX ^ 7) as usize] ) & (!1)) as u32;
        hs.pt1 ^= (hs.pt2 ^ 0x10) & 0x10;
        n+=1;
        for i in 0..16{
            hs.pool[n%1024] ^= res[i];
        }
    }
    hs.offset[0] = 0;
    hs.offset[1] = 1024/2;
}

/*
 * HAVEGE initialization
 */
pub fn initialise(hs:&mut mbedtls_havege_state){
    hs.pt1=0;
    hs.pt2=0;
    hs.offset[0] = 0;
    hs.offset[1] = 0;
    for i in 0..MBEDTLS_HAVEGE_COLLECT_SIZE{
        hs.pool[i] = 0;
    }
    for i in 0..8192{
        hs.walk[i]=0;
    }
    havege_fill(hs);
}

/*
 * HAVEGE rand function
 */
pub fn havege_random(hs:&mut mbedtls_havege_state, buf:&mut String, len: usize)->i32{
    let mut val:usize=0;
    let mut use_len:usize=0;
    while use_len < len {
        if hs.offset[1] >= MBEDTLS_HAVEGE_COLLECT_SIZE as i32{
            havege_fill( hs );
        }
        val  = hs.pool[hs.offset[0] as usize] as usize;
        val = val ^ hs.pool[hs.offset[1] as usize] as usize;
        //println!("{}",use_len);
        hs.offset[0]+=1;
        hs.offset[1]+=1;
        buf.push_str(& val.to_string());
        use_len = use_len + mem::size_of_val(&val);
    }
    return 0;
}
