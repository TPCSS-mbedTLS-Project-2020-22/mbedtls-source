use std::mem;
pub struct mbedtls_havege_state{
	pt1:u32,
	pt2:u32,
	offset:[i32;2],
	pool:[i32;1024],	
	walk:[i32;8192]
}
impl mbedtls_havege_state{
    pub fn new(pt1: u32, pt2: u32,offset:[i32;2],pool:[i32;1024],walk:[i32;8192]) -> mbedtls_havege_state {
            mbedtls_havege_state{ pt1: pt1, pt2: pt2,offset:offset,pool:pool,walk:walk }
    }
}
pub fn initialise(hs:&mut mbedtls_havege_state){
    hs.pt1=0;
    hs.pt2=0;
    hs.offset[0] = 0;
    hs.offset[1] = 0;
    for i in 0..1024{
        hs.pool[i] = 0;
    }
    for i in 0..8192{
        hs.walk[i]=0;
    }
    //havege_fill(hs);
}