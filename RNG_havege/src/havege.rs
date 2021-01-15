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
 * Entropy gathering function
 */
pub fn havege_fill(hs:&mut mbedtls_havege_state){
    hs.offset[0]=0;
    hs.offset[1] = MBEDTLS_HAVEGE_COLLECT_SIZE as i32 / 2;
    println!("{}",hs.pt1);
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
