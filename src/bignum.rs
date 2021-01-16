const MBEDTLS_ERR_MPI_FILE_IO_ERROR : i32                  =  -0x0002; /**< An error occurred while reading from or writing to a file. */
const MBEDTLS_ERR_MPI_BAD_INPUT_DATA : i32                 =  -0x0004;  /**< Bad input parameters to function. */
const MBEDTLS_ERR_MPI_INVALID_CHARACTER : i32              =  -0x0006;  /**< There is an invalid character in the digit string. */
const MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL : i32               =  -0x0008; /**< The buffer is too small to write to. */
const MBEDTLS_ERR_MPI_NEGATIVE_VALUE  : i32                =  -0x000A;  /**< The input arguments are negative or result in illegal output. */
const MBEDTLS_ERR_MPI_DIVISION_BY_ZERO  : i32              =  -0x000C;  /**< The input argument for division is zero, which is not allowed. */
const MBEDTLS_ERR_MPI_NOT_ACCEPTABLE  : i32                =  -0x000E;  /**< The input arguments are not acceptable. */
const MBEDTLS_ERR_MPI_ALLOC_FAILED   : i32                 =  -0x0010;  /**< Memory allocation failed. */

const MBEDTLS_MPI_MAX_LIMBS : i32                          =  10000;
const MBEDTLS_MPI_WINDOW_SIZE : i32                        =  6   ;
const MBEDTLS_MPI_MAX_SIZE : i32                           =  1024;
const MBEDTLS_MPI_MAX_BITS : i32                           = 8 * MBEDTLS_MPI_MAX_SIZE;
const MBEDTLS_MPI_MAX_BITS_SCALE100 : i32                  =  100 * MBEDTLS_MPI_MAX_BITS ;
const MBEDTLS_LN_2_DIV_LN_10_SCALE100 : i32                = 332;
const MBEDTLS_MPI_RW_BUFFER_SIZE : i32                     = ((MBEDTLS_MPI_MAX_BITS_SCALE100 + MBEDTLS_LN_2_DIV_LN_10_SCALE100 - 1) / MBEDTLS_LN_2_DIV_LN_10_SCALE100) + 10 + 6;
const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED : i32          = -0x006E;
const MBEDTLS_MPI_GEN_PRIME_FLAG_DH : i32				   =  0x0001;
const MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR : i32			   = 0x0002;

type mbedtls_mpi_sint = i64;
type mbedtls_mpi_uint = u64;

struct mbedtls_mpi
{
    s: i32 ,              
    n: usize,             
    p: Vec<mbedtls_mpi_uint>        
}

const ciL: usize = 8;
const biL: usize = ciL << 3;
const biH: usize = ciL << 2;

const MPI_SIZE_T_MAX: usize =  65536;

fn BITS_TO_LIMBS(i: usize) -> usize {
      (i) / biL + ( (i) % biL != 0 ) as usize 
}
fn CHARS_TO_LIMBS(i: usize) -> usize {
     (i) / ciL + ( (i) % ciL != 0 ) as usize 
}

fn mbedtls_mpi_zeroize(v: &mut Vec<mbedtls_mpi_uint>, n: &mut usize ) {
    for i in &mut v.iter_mut(){
        *i = 0u64;
    }
    *n = 0;
}

fn mbedtls_mpi_init( X: &mut mbedtls_mpi )
{
    X.s = 1;
    X.n = 0;
    X.p = vec![];       
}
fn mbedtls_mpi_free( X: &mut mbedtls_mpi )
{
    mbedtls_mpi_zeroize( &mut X.p, &mut X.n );
    X.s = 1;
    X.n = 0;
    X.p = vec![];
}

fn mbedtls_mpi_grow( X: &mut mbedtls_mpi, nblimbs: usize) -> i32
{
    let mut p: Vec<mbedtls_mpi_uint>;

    if nblimbs > MBEDTLS_MPI_MAX_LIMBS as usize {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED ;
    }
    if X.n < nblimbs 
    {
        p = vec![0; nblimbs];

        p[..X.n].clone_from_slice(&X.p[..X.n]);
        mbedtls_mpi_zeroize( &mut X.p, &mut X.n );
        
        X.n = nblimbs;
        X.p = p;
    }
    return 0 ;
}

fn mbedtls_mpi_shrink( mut X: &mut mbedtls_mpi, nblimbs: usize ) -> i32
{
    let mut p: Vec<mbedtls_mpi_uint>;
    let mut i: usize;

    if nblimbs > MBEDTLS_MPI_MAX_LIMBS as usize  {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED ;
    }

    if X.n <= nblimbs  {
        return mbedtls_mpi_grow( &mut X, nblimbs );
    }

    i = X.n;
    while i > 0 {
        if X.p[i] != 0 {
            break;
        }
        i = i - 1;
    }
    i += 1;

    if i < nblimbs  {
        i = nblimbs;
    }

    p = vec![0; i];       

    p[..i].clone_from_slice(&X.p[..i]);    
    mbedtls_mpi_zeroize( &mut X.p, &mut X.n );

    X.n = i;
    X.p = p;

    return 0 ;
}
fn mbedtls_mpi_copy( mut X: &mut mbedtls_mpi, Y: &mbedtls_mpi ) -> i32
{
    let ret: i32 = 0;
    let mut i: usize = 0;
    if Y.n == 0 
    {
        mbedtls_mpi_free( &mut X );
        return 0;
    }
    i = Y.n - 1;
    while i > 0{
        if Y.p[i] != 0 {
            break;
        }
        i = i - 1;
    }
    i += 1;
    X.s = Y.s;
    if X.n < i 
    {
        mbedtls_mpi_grow( &mut X, i ) ;
    }
    else{
        let mut j: usize = i;             
        while j < X.n{
            X.p[j] = 0;
            j += 1;
        }
    }
    X.p[..i].clone_from_slice(&Y.p[..i]);
    return ret ;
}
fn mbedtls_mpi_swap( X: &mut mbedtls_mpi, Y: &mut mbedtls_mpi )
{   
    let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; 
    tmp.s = X.s;
    tmp.n = X.n;
    tmp.p = vec![0; X.p.len()];
    for i in 0..(X.p.len()) {
        tmp.p[i] = X.p[i];
    }
    X.s = Y.s;
    X.n = Y.n;
    X.p = vec![0; Y.p.len()];
    for i in 0..(Y.p.len()) {
        X.p[i] = Y.p[i];
    }
    Y.s = tmp.s;
    Y.n = tmp.n;
    Y.p = vec![0; tmp.p.len()];
    for i in 0..(tmp.p.len()) {
        Y.p[i] = tmp.p[i];
    }
}

fn mpi_safe_cond_assign( n: usize, dest: &mut Vec<mbedtls_mpi_uint>, src: &Vec<mbedtls_mpi_uint>, assign: u8 )
{
    let mut i: usize = 0;
    while i < n {
        dest[i] = dest[i] * ( 1 - assign as u64 ) + src[i] * assign as u64;
        i += 1;
    }
}
fn mbedtls_mpi_safe_cond_assign( mut X: &mut mbedtls_mpi , Y: &mbedtls_mpi, mut assign: u8 ) -> i32
{
    let ret: i32 = 0;
    let mut i: usize;

    assign = (assign as i32 | -(assign as i32)) as u8 >> 7;        
    mbedtls_mpi_grow( &mut X, Y.n );
    X.s = X.s * ( 1 - assign as i32 ) as i32 + Y.s * assign as i32;
    mpi_safe_cond_assign( Y.n, &mut X.p, &Y.p, assign );

    i = Y.n;
    while i < X.n {
        X.p[i] *= 1 - assign as u64;
        i += 1;
    }
    return ret ;
}

fn mbedtls_mpi_safe_cond_swap( mut X: &mut mbedtls_mpi, mut Y: &mut mbedtls_mpi, mut swap: u8 ) -> i32
{
    let ret: i32 = 0;
    let s: i32;
    let mut i: usize;
    let mut tmp: mbedtls_mpi_uint;

    swap = (swap as i32 | -(swap as i32)) as u8 >> 7;          

    mbedtls_mpi_grow( &mut X, Y.n );
    mbedtls_mpi_grow( &mut Y, X.n );

    s = X.s;
    X.s = X.s * ( 1 - swap as i32 ) + Y.s * swap as i32;
    Y.s = Y.s * ( 1 - swap as i32 ) +    s * swap as i32;

    i = 0;
    while i < X.n {
        tmp = X.p[i];
        X.p[i] = X.p[i] * ( 1 - swap as u64) + Y.p[i] * swap as u64;
        Y.p[i] = Y.p[i] * ( 1 - swap as u64 ) +     tmp * swap as u64;
        i += 1;
    }

    return ret;
}
fn mbedtls_mpi_lset( mut X: &mut mbedtls_mpi, z: mbedtls_mpi_sint ) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_grow( &mut X, 1 );

    let mut i: usize = 0;
    while i < X.n {
        X.p[i] = 0;
        i += 1;
    }
    if z < 0 {
        X.p[0] = -z as u64;
        X.s = -1;
    }
    else {
        X.p[0] = z as u64;
        X.s = 1;
    }

    return ret ;
}

fn mbedtls_mpi_get_bit(  X: &mbedtls_mpi, pos: usize ) -> i32
{
    if X.n * biL <= pos  {
        return 0 ;
    }
    return (( X.p[pos / biL] >> ( pos % biL ) ) & 0x01 ) as i32;
}
fn GET_BYTE( X: &mbedtls_mpi, i: usize ) -> i32 {                              
    return ( (  X.p[i / ciL] >> ( ( i ) % ciL ) * 8 ) & 0xff ) as i32;
}

fn mbedtls_mpi_set_bit( mut X: &mut mbedtls_mpi, pos: usize, val: u8 ) -> i32
{
    let ret: i32 = 0;
    let off: usize = pos / biL;
    let idx: usize = pos % biL;

    if val != 0 && val != 1 {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if X.n * biL <= pos 
    {
        if val == 0 {
            return 0;
        }
        mbedtls_mpi_grow( &mut X, off + 1);       
    }

    X.p[off] &= !( (0x01 as u64) << idx );
    X.p[off] |=  (val as u64) << idx;

    return ret ;
}
fn mbedtls_mpi_lsb( X: &mbedtls_mpi) -> usize
{
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut count: usize  = 0;

    while i < X.n {
        j = 0;
        while j < biL{
            if ( ( X.p[i] >> j ) & 1 ) != 0 {
                return count ;
            }
            count += 1;
            j += 1;
        }
        i += 1;
    }

    return 0;
}

fn mbedtls_clz( x: mbedtls_mpi_uint ) -> usize
{
    let mut j: usize = 0;
    let mut mask: mbedtls_mpi_uint = (1 as mbedtls_mpi_uint) << (biL - 1);

    while j < biL {
        if x & mask != 0 {break;}
        mask >>= 1;
        j += 1;
    } 

    return j;
}
fn mbedtls_mpi_bitlen( X: &mbedtls_mpi ) -> usize
{
    let mut i: usize;
    let j: usize;

    if X.n == 0 {
        return 0 ;
    }
    i = X.n - 1;
    while i > 0 {
        if X.p[i] != 0 {
            break;
        }
        i -= 1;
    }
    j = biL - mbedtls_clz( X.p[i] );

    return ( i * biL ) + j;
}

fn mbedtls_mpi_size( X: &mbedtls_mpi ) -> usize
{
    return mbedtls_mpi_bitlen( &X ) + 7 >> 3 ;
}
fn mpi_get_digit( d: &mut mbedtls_mpi_uint, radix: i32, c: char ) -> i32
{  
    *d = 255;

    if c as u64 >= 0x30 && c as u64 <= 0x39 {*d = c as u64 - 0x30 as u64; }
    if c as u64 >= 0x41 && c as u64 <= 0x46 {*d = c as u64 - 0x37 as u64; }
    if c as u64 >= 0x61 && c as u64 <= 0x66 {*d = c as u64 - 0x57 as u64; }

    if *d >= radix as mbedtls_mpi_uint  {
        return MBEDTLS_ERR_MPI_INVALID_CHARACTER;
    }
    return 0 ;
}
fn mbedtls_mpi_read_string( mut X: &mut mbedtls_mpi, radix: i32, s: &str ) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut i: usize;
    let mut j: usize;
    let slen: usize;
    let n: usize;
    let mut d: mbedtls_mpi_uint = 0;
    let mut T: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};

    if radix < 2 || radix > 16 {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init( &mut T );

    slen = s.len();             

    if radix == 16
    {
        if slen > MPI_SIZE_T_MAX >> 2 {
            return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        }
        n = BITS_TO_LIMBS( slen << 2 );

        mbedtls_mpi_grow( &mut X, n );
        mbedtls_mpi_lset( &mut X, 0 );      

        i = slen;
        j = 0;
        while i > 0 {
            if i == 1 && s.chars().nth(i-1).unwrap() == '-'
            {
                X.s = -1;
                break;
            }
            mpi_get_digit( &mut d, radix, s.chars().nth(i-1).unwrap());    
            X.p[j / ( 2 * ciL )] |= d << ( ( j % ( 2 * ciL ) ) << 2 );
            i -= 1; 
            j += 1;
        }
    }
    else
    {
        mbedtls_mpi_lset( &mut X, 0 );
        i = 0;
        while i < slen {
            if i == 0 && s.chars().nth(i).unwrap() == '-'
            {
                X.s = -1;
                continue;
            }
            mpi_get_digit( &mut d, radix, s.chars().nth(i).unwrap() ) ;  
            mbedtls_mpi_mul_int( &mut T, &X, radix as mbedtls_mpi_uint ) ;
            if X.s == 1
            {
                mbedtls_mpi_add_int( &mut X, &T, d as mbedtls_mpi_sint);
            }
            else
            {
                mbedtls_mpi_sub_int( &mut X, &T, d as mbedtls_mpi_sint );
            }
            i += 1;
        }
    }
    mbedtls_mpi_free( &mut T );
    return ret;
}
fn mbedtls_mpi_add_int( mut X: &mut mbedtls_mpi, A: &mbedtls_mpi, b: mbedtls_mpi_sint ) -> i32
{
    let mut _B: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
    let mut p: Vec<mbedtls_mpi_uint> = vec![];

    if b < 0{
        p.push(-b as mbedtls_mpi_uint);
        _B.s = -1;
    }
    else { p.push(b as mbedtls_mpi_uint); _B.s = 1;}

    _B.n = 1;
    _B.p = p;

    return mbedtls_mpi_add_mpi( &mut X, &A, &_B ) ;
}
fn mbedtls_mpi_sub_int( mut X: &mut mbedtls_mpi, A: &mbedtls_mpi, b: mbedtls_mpi_sint ) -> i32
{
    let mut _B: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
    let mut p: Vec<mbedtls_mpi_uint> = vec![];

    if b < 0{
        p.push(-b as mbedtls_mpi_uint);
        _B.s = -1;
    }
    else { p.push(b as mbedtls_mpi_uint); _B.s = 1;}

    _B.n = 1;
    _B.p = p;

    return mbedtls_mpi_sub_mpi( &mut X, &A, &_B ) ;
}
fn mbedtls_mpi_add_mpi( mut X: &mut mbedtls_mpi, A: &mbedtls_mpi, B: &mbedtls_mpi ) -> i32
{
    let ret: i32 = 0;
    let s: i32;
    s = A.s;
    if A.s * B.s < 0
    {
        if mbedtls_mpi_cmp_abs( &A, &B ) >= 0 
        {
            mbedtls_mpi_sub_abs( &mut X, &A, &B );
            X.s =  s;
        }
        else
        {
            mbedtls_mpi_sub_abs( &mut X, &B, &A );
            X.s = -s;
        }
    }
    else
    {
        mbedtls_mpi_add_abs( &mut X, &A, &B );
        X.s = s;
    }
    return ret ;
}

fn mbedtls_mpi_sub_mpi(mut X: &mut mbedtls_mpi, A: &mbedtls_mpi, B: &mbedtls_mpi ) -> i32
{
    let ret: i32 = 0;
    let s: i32;
    s = A.s;
    if A.s * B.s > 0
    {
        if mbedtls_mpi_cmp_abs( &A, &B ) >= 0 
        {
            mbedtls_mpi_sub_abs( &mut X, &A, &B );
            X.s =  s;
        }
        else
        {
            mbedtls_mpi_sub_abs( &mut X, &B, &A );
            X.s = -s;
        }
    }
    else
    {
        mbedtls_mpi_add_abs( &mut X, &A, &B );
        X.s = s;
    }
    return ret;
}
fn mbedtls_mpi_sub_abs( mut X: &mut mbedtls_mpi , A: &mbedtls_mpi, B: &mbedtls_mpi ) -> i32
{
    let mut TB: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p: vec![]};
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut n: usize;
    let carry: mbedtls_mpi_uint;

    mbedtls_mpi_init( &mut TB );         
    mbedtls_mpi_copy( &mut X, &A ) ;
    X.s = 1;
    ret = 0;
    n = B.n;
    while n > 0 {
        if B.p[n - 1] != 0
            {break;}
        n -= 1;
    }
    carry = mpi_sub_hlp( n, &mut X.p, &B.p );
    if carry != 0
    {
        while n < X.n && X.p[n] == 0 {
            X.p[n] -= 1;
            n += 1;
        }
        if n == X.n
        {
            ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
        }
        X.p[n] -= 1;
    }
    mbedtls_mpi_free( &mut TB );
    return ret ;
}
fn mbedtls_mpi_add_abs( mut X: &mut mbedtls_mpi, A: &mbedtls_mpi, B: &mbedtls_mpi ) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut i: usize;
    let mut j: usize;
    let o: &Vec<mbedtls_mpi_uint>; 
    //let mut p: &mut Vec<mbedtls_mpi_uint>; 
    let mut c: mbedtls_mpi_uint; 
    let mut tmp: mbedtls_mpi_uint; 

    mbedtls_mpi_copy( &mut X, &A ) ;   
    X.s = 1;
    j = B.n;
    while j > 0 {
        if B.p[j - 1] != 0
        { break;}
        j -= 1;
    }     
    mbedtls_mpi_grow( &mut X, j );
    o = &B.p; c = 0;      
    i = 0;
    let mut pi: usize = 0;
    let mut oi: usize = 0;

    while i < j {
        tmp = o[oi];
        X.p[pi] +=  c; c  = ( X.p[pi] <  c ) as mbedtls_mpi_uint;
        X.p[pi] += tmp; c += ( X.p[pi] < tmp ) as mbedtls_mpi_uint;

        i += 1; oi += 1; pi += 1;
    }
    while c != 0 {
        if i >= X.n
        {
            mbedtls_mpi_grow( &mut X, i + 1 );
            pi = i;
        }

        X.p[pi] += c; c = ( X.p[pi] < c ) as mbedtls_mpi_uint; 
        i += 1; pi += 1;
    }
    return ret;
}

fn mpi_sub_hlp( n: usize, d: &mut Vec<mbedtls_mpi_uint>, s: &Vec<mbedtls_mpi_uint> ) -> mbedtls_mpi_uint
{
    let mut i: usize;
    let mut c: mbedtls_mpi_uint;
    let mut z: mbedtls_mpi_uint;

    i = 0; c = 0;
    let mut si: usize = 0;
    let mut di: usize = 0;
    while i < n {
        z = ( d[di] <  c ) as mbedtls_mpi_uint;  d[di] -=  c;
        c = (( d[di] < s[si] ) as mbedtls_mpi_uint) + z;  d[di] -= s[si];

        i += 1; si += 1; di += 1;
    }

    return c;
}
fn mbedtls_mpi_cmp_abs(X: &mbedtls_mpi, Y: &mbedtls_mpi) -> i32
{
    let mut i: usize;
    let mut j: usize;
    i = X.n;
    while i > 0{
        if X.p[i - 1] != 0 { break;}
        i -= 1;
    }
    j = Y.n;
    while j > 0{
        if X.p[j - 1] != 0 { break;}
        j -= 1;
    }
    if i == 0 && j == 0 {
        return 0 ;
    }
    if i > j  {return  1 ;}
    if j > i {return -1 ;}

    while  i > 0 {
        if X.p[i - 1] > Y.p[i - 1]  {return  1 ;}
        if X.p[i - 1] < Y.p[i - 1] {return -1 ;}
        i -= 1;
    }
    return 0 ;
}
fn mbedtls_mpi_mul_int( mut X: &mut mbedtls_mpi, A: &mbedtls_mpi, b: mbedtls_mpi_uint ) -> i32
{
    let mut _B: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    let mut p: Vec<mbedtls_mpi_uint> = vec![];

    _B.s = 1;
    _B.n = 1;
	p.push(b);
    _B.p = p;
    return mbedtls_mpi_mul_mpi( &mut X, &A, &_B ) ;
}

fn mbedtls_mpi_mul_mpi( mut X: &mut mbedtls_mpi, A: &mbedtls_mpi, B: &mbedtls_mpi ) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut i: usize;
    let mut j: usize;
    let mut TA: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    let mut TB: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};

    mbedtls_mpi_init( &mut TA ); mbedtls_mpi_init( &mut TB );

    i = A.n;
    while i > 0 {
        if A.p[i - 1] != 0
            {break;}
        i -= 1;
    }
    j = B.n;
    while j > 0 {
        if B.p[j - 1] != 0
            {break;}
        j -= 1;
    }
    mbedtls_mpi_grow( &mut X, i + j );
    mbedtls_mpi_lset( &mut X, 0 );

    while j > 0 {
        //mpi_mul_hlp( i, A.p, X.p + j - 1, B.p[j - 1] );     //todo
        j -= 1;
    }
    X.s = A.s * B.s;
    mbedtls_mpi_free( &mut TB ); mbedtls_mpi_free( &mut TA );
    return ret ;
}
fn mpi_write_hlp( mut X: &mut mbedtls_mpi, radix: i32, buf: &mut Vec<u8>, buflen: usize) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut r: mbedtls_mpi_uint = 0;
    let mut length: usize = 0;
    let mut p_end: usize = buf.len();   

    let mut tmp: i32 = 1;
    while tmp == 1 || mbedtls_mpi_cmp_int( X, 0 ) != 0
    {
        tmp = 0;
        if length >= buflen
        {
            return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
        }

        mbedtls_mpi_mod_int( &mut r, &X, radix as i64);
        let mut tmpX: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
        mbedtls_mpi_copy(&mut tmpX, &X);
        mbedtls_mpi_div_int(&mut X, None, &tmpX, radix as i64 );     //todo

        if r < (0xA as mbedtls_mpi_uint) {       
            p_end -= 1;  
            buf[p_end] = '0' as u8 + r as u8;     
        }
        else{
            p_end -= 1;  
            buf[p_end] = 'A' as u8 + r as u8 - 0xA as u8;   
        }

        length += 1;
    } 
    let mut p: usize = 0;
    for i in p_end..(p_end+length) {
        buf[p] = buf[i];
        p += 1;
    }  
    return ret;
} 
fn mbedtls_int_div_int(u1: mbedtls_mpi_uint, u0: mbedtls_mpi_uint, d: mbedtls_mpi_uint, r: Option<&mut mbedtls_mpi_uint>) -> mbedtls_mpi_uint
{
    let mut dividend: mbedtls_mpi_uint;
    let mut quotient: mbedtls_mpi_uint;

    if 0 == d || u1 >= d
    {
        match r{
            Some(x) => {*x = !0;}
            None => {} 
        }
        return  !0 ;
    }
    dividend  = (u1 << sh(biL)) as mbedtls_mpi_uint;
    dividend |= u0 as mbedtls_mpi_uint;
    quotient = dividend / d;
    if quotient > ( 1 << sh(biL) ) as mbedtls_mpi_uint  - 1 {
        quotient = ( 1  << sh(biL) ) as  mbedtls_mpi_uint - 1;
    }
    match r{
        Some(x) => {*x = ( dividend - (quotient * d ) ) as mbedtls_mpi_uint;}
        None => {}
    }
    return quotient as mbedtls_mpi_uint;
}
fn sh(biLvar: usize) -> usize {
	if biLvar == 64 {
		return 0;
	} 
	else {return biLvar; }
}
fn mbedtls_mpi_cmp_int( X: &mbedtls_mpi, z: mbedtls_mpi_sint ) -> i32
{
    let mut Y: mbedtls_mpi = mbedtls_mpi{n:0, s:0, p:vec![]};
    let mut p: Vec<mbedtls_mpi_uint> = vec![]; 

    if z < 0 { p.push(-z as mbedtls_mpi_uint); }        
    else { p.push(z as mbedtls_mpi_uint); }
    if z < 0 { Y.s = -1; }
    else { Y.s = 1; }
    Y.n = 1;
    Y.p = p; 

    return mbedtls_mpi_cmp_mpi( &X, &Y );
}
fn mbedtls_mpi_cmp_mpi (X: &mbedtls_mpi, Y: &mbedtls_mpi) -> i32
{
    let mut i: usize;
    let mut j: usize;

    i = X.n;
    while i > 0{
        if X.p[i - 1] != 0 { break;}
        i -= 1;
    }
    j = Y.n;
    while j > 0{
        if X.p[j - 1] != 0 { break;}
        j -= 1;
    }
    if i == 0 && j == 0 {
        return 0 ;
    }
    if i > j  {return  X.s ;}
    if j > i  {return -Y.s ;}

    if X.s > 0 && Y.s < 0  {return  1 ;}
    if Y.s > 0 && X.s < 0 {return -1 ;}

    while  i > 0 {
        if X.p[i - 1] > Y.p[i - 1]  {return  X.s ;}
        if X.p[i - 1] < Y.p[i - 1]  {return -X.s ;}
        i -= 1;
    }
    return 0;
}
fn mbedtls_mpi_mod_int( r: &mut mbedtls_mpi_uint, A: &mbedtls_mpi, b: mbedtls_mpi_sint ) -> i32
{
    let mut i: usize;
    let mut x: mbedtls_mpi_uint;
    let mut y: mbedtls_mpi_uint;
    let mut z: mbedtls_mpi_uint;

    if b == 0 {
        return MBEDTLS_ERR_MPI_DIVISION_BY_ZERO ;
    }
    if b < 0  {
        return MBEDTLS_ERR_MPI_NEGATIVE_VALUE ;
    }
    if b == 1 
    {
        *r = 0;
        return 0 ;
    }
    if b == 2 
    {
        *r = A.p[0] & 1;
        return 0 ;
    }
    i = A.n;
    y = 0;
    while i > 0 {
        x  = A.p[i - 1];
        y  = ( y << biH ) | ( x >> biH );
        z  = y / (b as mbedtls_mpi_uint);
        y -= z * b as mbedtls_mpi_uint;

        x <<= biH;
        y  = ( y << biH ) | ( x >> biH );
        z  = y / (b as mbedtls_mpi_uint);
        y -= z * (b as mbedtls_mpi_uint);
        i -= 1;
    }
    if A.s < 0 && y != 0  {
        y = b as mbedtls_mpi_uint - y;
    }
    *r = y;
    return 0 ;
}
fn mbedtls_mpi_div_int( mut Q: &mut mbedtls_mpi, R: Option<&mut mbedtls_mpi>, A: &mbedtls_mpi, b: mbedtls_mpi_sint ) -> i32
{
    let mut _B: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    let mut p: Vec<mbedtls_mpi_uint> = vec![];

    if b < 0 { p.push(-b as mbedtls_mpi_uint); _B.s = -1; }
    else { p.push(b as mbedtls_mpi_uint); _B.s = 1; }

    _B.n = 1;
    _B.p = p;
    return mbedtls_mpi_div_mpi( Some(&mut Q), R, &A, &_B ) ;
}
fn mbedtls_mpi_div_mpi( mut Q: Option<&mut mbedtls_mpi>, mut R: Option<&mut mbedtls_mpi>, A: &mbedtls_mpi, B: &mbedtls_mpi ) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut i: usize;
    let n: usize;
    let t: usize;
    let mut k: usize;
    let mut X: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    let mut Y: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    let mut Z: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]}; 
    let mut T1: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    let mut T2: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};

    if mbedtls_mpi_cmp_int( &B, 0 ) == 0 {
        return MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
    }
    mbedtls_mpi_init( &mut X ); mbedtls_mpi_init( &mut Y ); mbedtls_mpi_init( &mut Z );
    mbedtls_mpi_init( &mut T1 );
    T2.s = 1;
    T2.n = 3;
    T2.p = vec![0; 3];
    if mbedtls_mpi_cmp_abs( &A, &B ) < 0
    {
        match &mut Q{
            Some(x) => {mbedtls_mpi_lset( x, 0 );}
            None => {}
        }
        match &mut R{
            Some(x) => {mbedtls_mpi_copy( x, A ) ; }
            None => {}
        }
        return 0 ;
    }

    mbedtls_mpi_copy( &mut X, &A ) ;
    mbedtls_mpi_copy( &mut Y, &B ) ;
    X.s = 1; Y.s = 1;

    mbedtls_mpi_grow( &mut Z, A.n + 2 );
    mbedtls_mpi_lset( &mut Z,  0 ) ;
    mbedtls_mpi_grow( &mut T1, 2 ) ;

    k = mbedtls_mpi_bitlen( &Y ) % biL;
    if k < biL - 1
    {
        k = biL - 1 - k;
        mbedtls_mpi_shift_l( &mut X, k ) ;
        mbedtls_mpi_shift_l( &mut Y, k ) ;
    }
    else{ k = 0; }

    n = X.n - 1;
    t = Y.n - 1;
    mbedtls_mpi_shift_l( &mut Y, biL * ( n - t ) );

    while mbedtls_mpi_cmp_mpi( &X, &Y ) >= 0 
    {
        Z.p[n - t] += 1;
        let mut tmpX: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
        mbedtls_mpi_copy(&mut tmpX, &X);
        mbedtls_mpi_sub_mpi( &mut X, &tmpX, &Y );
    }
    mbedtls_mpi_shift_r( &mut Y, biL * ( n - t ) );

    i = n;
    while i > t {
        if X.p[i] >= Y.p[t] {
            Z.p[i - t - 1] = !0;
        }
        else {
            Z.p[i - t - 1] = mbedtls_int_div_int( X.p[i], X.p[i - 1], Y.p[t], None); //todo
        }
        if i < 2 { T2.p[0] = 0; }
        else { T2.p[0] = X.p[i-2]; }
        if i < 1 { T2.p[1] = 0; }
        else { T2.p[1] = X.p[i-1]; }

        T2.p[2] = X.p[i];

        Z.p[i - t - 1] += 1;

        let mut tmp: i32 = 1;
        while tmp == 1 || mbedtls_mpi_cmp_mpi( &T1, &T2 ) > 0
        {   tmp = 0;
            Z.p[i - t - 1] -= 1;

            mbedtls_mpi_lset( &mut T1, 0 );
            if t < 1 { T1.p[0] = 0; }
            else { T1.p[0] = Y.p[t-1]; }
            T1.p[1] = Y.p[t];
            let mut tmpX: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
			mbedtls_mpi_copy(&mut tmpX, &T1);
            mbedtls_mpi_mul_int( &mut T1, &tmpX, Z.p[i - t - 1] );
        }
        mbedtls_mpi_mul_int( &mut T1, &Y, Z.p[i - t - 1] ) ;
        mbedtls_mpi_shift_l( &mut T1,  biL * ( i - t - 1 ) );
        let mut tmpX: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
        mbedtls_mpi_copy(&mut tmpX, &X);
        mbedtls_mpi_sub_mpi( &mut X, &tmpX, &T1 );

        if mbedtls_mpi_cmp_int( &X, 0 ) < 0
        {
            mbedtls_mpi_copy( &mut T1, &Y ) ;
            mbedtls_mpi_shift_l( &mut T1, biL * ( i - t - 1 ) ) ;
            let mut tmpX: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
			mbedtls_mpi_copy(&mut tmpX, &X);
            mbedtls_mpi_add_mpi( &mut X, &tmpX, &T1 ) ;
            Z.p[i - t - 1] -= 1;
        }

        i -= 1;
    }
    match &mut Q{
        Some(x) => {
            mbedtls_mpi_copy( x, &Z );
            x.s = A.s * B.s;
        }
        None => {}
    }
    match &mut R{
        Some(x) => {
            mbedtls_mpi_shift_r( x, k );
            X.s = A.s;
            mbedtls_mpi_copy( x, &X );
            if mbedtls_mpi_cmp_int( x, 0 ) == 0 {
                x.s = 1;
            }
        }
        None => {}
    }
    mbedtls_mpi_free( &mut X ); mbedtls_mpi_free( &mut Y ); mbedtls_mpi_free( &mut Z );
    mbedtls_mpi_free( &mut T1 );
    return ret;
}

fn mbedtls_mpi_shift_l(mut X: &mut mbedtls_mpi, count: usize) -> i32
{
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut i: usize;
    let v0: usize;
    let t1: usize;
    let mut r0: mbedtls_mpi_uint = 0;
    let mut r1: mbedtls_mpi_uint;

    v0 = count / (biL    );
    t1 = count & (biL - 1);

    i = mbedtls_mpi_bitlen( &X ) + count;

    if X.n * biL < i  {
        mbedtls_mpi_grow( &mut X, BITS_TO_LIMBS( i ) );
    }

    ret = 0;
    if v0 > 0 
    {
        i = X.n;
        while i > v0 {
            X.p[i - 1] = X.p[i - v0 - 1];
            i -= 1;
        }
        while i > 0 {
            X.p[i - 1] = 0;
            i -= 1;
        }
    }

    if t1 > 0
    {
        i = v0;
        while i < X.n {
            r1 = X.p[i] >> (biL - t1);
            X.p[i] <<= t1;
            X.p[i] |= r0;
            r0 = r1;
            i += 1;
        }
    }
    return ret ;
}
fn mbedtls_mpi_shift_r(mut X: &mut mbedtls_mpi, count: usize) -> i32
{
    let mut i: usize;
    let v0: usize;
    let v1: usize;
    let mut r0: mbedtls_mpi_uint = 0;
    let mut r1: mbedtls_mpi_uint;

    v0 = count /  biL;
    v1 = count & (biL - 1);

    if v0 > X.n || ( v0 == X.n && v1 > 0 )  {
        return mbedtls_mpi_lset( &mut X, 0 );
    }
    if v0 > 0 
    {
        i = 0;
        while i < X.n - v0 {
            X.p[i] = X.p[i + v0];
            i += 1;
        }
        while i < X.n {
            X.p[i] = 0;
            i += 1;
        }
    }
    if v1 > 0 
    {
        i = X.n;
        while i > 0 {
            r1 = X.p[i - 1] << (biL - v1);
            X.p[i - 1] >>= v1;
            X.p[i - 1] |= r0;
            r0 = r1;
            i -=  1;
        }
    }
    return 0 ;
}
fn mbedtls_mpi_gcd( mut G: &mut mbedtls_mpi, A: &mbedtls_mpi, B: &mbedtls_mpi ) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut lz: usize;
    let lzt: usize;
    let mut TA: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    let mut TB: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
	let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    mbedtls_mpi_init( &mut TA ); mbedtls_mpi_init( &mut TB );

    mbedtls_mpi_copy( &mut TA, &A ) ;
    mbedtls_mpi_copy( &mut TB, &B ) ;

    lz = mbedtls_mpi_lsb( &TA );
    lzt = mbedtls_mpi_lsb( &TB );

    if lzt < lz  {
        lz = lzt;
    }
    mbedtls_mpi_shift_r( &mut TA, lz );
    mbedtls_mpi_shift_r( &mut TB, lz );

    TA.s = 1; TB.s = 1;

    while mbedtls_mpi_cmp_int( &TA, 0 ) != 0
    {
		mbedtls_mpi_copy(&mut tmp, &TA);
        mbedtls_mpi_shift_r( &mut TA, mbedtls_mpi_lsb( &tmp ) ) ;
        mbedtls_mpi_copy(&mut tmp, &TA);
        mbedtls_mpi_shift_r( &mut TB, mbedtls_mpi_lsb( &tmp ) ) ;

        if mbedtls_mpi_cmp_mpi( &TA, &TB ) >= 0
        {
			mbedtls_mpi_copy( &mut tmp, &TA );
            mbedtls_mpi_sub_abs( &mut TA, &tmp, &TB ) ;
            mbedtls_mpi_shift_r( &mut TA, 1 ) ;
        }
        else
        {
			mbedtls_mpi_copy( &mut tmp, &TB );
            mbedtls_mpi_sub_abs( &mut TB, &tmp, &TA ) ;
            mbedtls_mpi_shift_r( &mut TB, 1 ) ;
        }
    }
    mbedtls_mpi_shift_l( &mut TB, lz );
    mbedtls_mpi_copy( &mut G, &TB );
    mbedtls_mpi_free( &mut TA ); mbedtls_mpi_free( &mut TB );
    return ret ;
}

fn mbedtls_mpi_fill_random( mut X: &mut mbedtls_mpi, size: usize, 
    f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32, mut p_rng: &mut Vec<u8>) -> i32 
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let limbs: usize = CHARS_TO_LIMBS( size );
    let overhead: usize = ( limbs * ciL ) - size;

    if X.n != limbs 
    {
        mbedtls_mpi_free( &mut X );
        mbedtls_mpi_init( &mut X );
        mbedtls_mpi_grow( &mut X, limbs );
    }
    mbedtls_mpi_lset( &mut X, 0 );
    f_rng( &mut p_rng, &mut X.p[overhead..], size );
    mpi_bigendian_to_host( &mut X.p, limbs );
    return ret;
}
fn mbedtls_mpi_exp_mod( mut X: &mut mbedtls_mpi, mut A: &mut mbedtls_mpi,
                         E: &mbedtls_mpi, N: &mbedtls_mpi, mut _RR: Option<&mut mbedtls_mpi> ) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut wbits: usize;
    let mut wsize: usize;
    let one: usize = 1;
    let mut i: usize;
    let mut j: usize;
    let mut nblimbs: usize;
    let mut bufsize: usize;
    let mut nbits: usize;
    let mut ei: mbedtls_mpi_uint;
    let mut mm: mbedtls_mpi_uint = 0;
    let mut state: mbedtls_mpi_uint;
    let mut RR: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]} ;
    let mut T: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
    let mut W: Vec<mbedtls_mpi> = Vec::with_capacity( 1 << MBEDTLS_MPI_WINDOW_SIZE);   
    let mut Apos: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    let neg: i32;
    let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};

    if (mbedtls_mpi_cmp_int( &N, 0 ) <= 0 )|| (( N.p[0] & 1 ) == 0) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA ;
    }

    if mbedtls_mpi_cmp_int( &E, 0 ) < 0 {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA ;
    }

    mpi_montg_init( &mut mm, &N );
    mbedtls_mpi_init( &mut RR ); mbedtls_mpi_init( &mut T );
    mbedtls_mpi_init( &mut Apos );

    for i in 0..W.len() { 
        W[i] = mbedtls_mpi{s:0,n:0,p:vec![]};
    }      

    i = mbedtls_mpi_bitlen( &E );

    if i > 671 { wsize = 6; }
    else if i > 239 { wsize = 5; }
    else if i > 79 { wsize = 4; }
    else if i > 23 { wsize = 3; }
    else { wsize = 1; }

if MBEDTLS_MPI_WINDOW_SIZE < 6 {
    if wsize > MBEDTLS_MPI_WINDOW_SIZE as usize
         { wsize = MBEDTLS_MPI_WINDOW_SIZE as usize;}
}

    j = N.n + 1;
    mbedtls_mpi_grow( &mut X, j );
    mbedtls_mpi_grow( &mut W[1],  j );      
    mbedtls_mpi_grow( &mut T, j * 2 );

    neg = ( A.s == -1 ) as i32;
    if neg != 0
    {
        mbedtls_mpi_copy( &mut Apos, &A );
        Apos.s = 1;
        //A = &mut Apos;
        mbedtls_mpi_copy(&mut A, &Apos);
    }

    match &mut _RR{
        Some(x) => {
            x.n = RR.n;
            x.s = RR.s;
            x.p[..].clone_from_slice(&RR.p[..]);
        },
        None => {
            mbedtls_mpi_lset( &mut RR, 1 ) ;
            mbedtls_mpi_shift_l( &mut RR, N.n * 2 * biL ) ;
            mbedtls_mpi_copy(&mut tmp, &RR);	
            mbedtls_mpi_mod_mpi( &mut RR, &tmp, &N ) ;
        }
    }

    if mbedtls_mpi_cmp_mpi( &A, &N ) >= 0 { 
        mbedtls_mpi_mod_mpi( &mut W[1], &A, &N ); 
    }
    else {
        mbedtls_mpi_copy( &mut W[1], &A );
    }

    mpi_montmul( &mut W[1], &RR, &N, mm, &mut T);

    mbedtls_mpi_copy( &mut X, &RR );
    mpi_montred( &mut X, &N, mm, &mut T);

    if wsize > 1 
    {
        j =  one << ( wsize - 1 );
        mbedtls_mpi_grow( &mut W[j], N.n + 1 );
        mbedtls_mpi_copy( &mut W[1], &tmp );
        mbedtls_mpi_copy( &mut W[j], &tmp   );
        i = 0;
        while i < (wsize - 1) {
			mbedtls_mpi_copy(&mut tmp, &W[j]);	
            mpi_montmul( &mut W[j], &tmp, &N, mm, &mut T );
            i += 1;
        }
        i = j + 1;
        while i < ( one << wsize ) {
            mbedtls_mpi_grow( &mut W[i], N.n + 1 );
            mbedtls_mpi_copy(&mut tmp, &W[i-1]);	
            mbedtls_mpi_copy( &mut W[i], &tmp );
			mbedtls_mpi_copy(&mut tmp, &W[1]);	
            mpi_montmul( &mut W[i], &tmp, &N, mm, &mut T );
            i += 1;
        }
    }
    nblimbs = E.n;
    bufsize = 0;
    nbits   = 0;
    wbits   = 0;
    state   = 0;

    loop
    {
        if bufsize == 0 
        {
            if nblimbs == 0  {
                break;
            }
            nblimbs -= 1;
            bufsize = 8 << 3;     
        }

        bufsize -= 1;

        ei = (E.p[nblimbs] >> bufsize) & 1;

        if ei == 0 && state == 0 {  continue;  }

        if ei == 0 && state == 1 
        {
			mbedtls_mpi_copy( &mut tmp, &X );
            mpi_montmul( &mut X, &tmp, &N, mm, &mut T );
            continue;
        }

        state = 2;

        nbits += 1;
        wbits |= ( ei << ( wsize - nbits ) ) as usize;

        if nbits == wsize 
        {
            i = 0;
            while i < wsize {
				let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
				mbedtls_mpi_copy(&mut tmp, &X);
                mpi_montmul( &mut X, &tmp, &N, mm, &mut T );
                i += 1;
            }
            mpi_montmul( &mut X, &W[wbits], &N, mm, &mut T );

            state -= 1;
            nbits = 0;
            wbits = 0;
        }
    }
    i = 0;
    while i < nbits {
		mbedtls_mpi_copy(&mut tmp, &X);	
        mpi_montmul( &mut X, &tmp, &N, mm, &mut T );

        wbits <<= 1;

        if ( wbits & ( one << wsize ) ) != 0  {
            mpi_montmul( &mut X, &W[1], &N, mm, &mut T );
        }
        i += 1;
    }
    mpi_montred( &mut X, &N, mm, &mut T );

    if (neg != 0) && (E.n != 0) && (E.p[0] & 1 != 0) 
    {
        X.s = -1;
        let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
        mbedtls_mpi_copy(&mut tmp, &X);
        mbedtls_mpi_add_mpi( &mut X, &N, &tmp );
    }
    i =  one << ( wsize - 1 ) ;
    while i < (one << ( wsize )) {
        mbedtls_mpi_free( &mut W[i] );
        i += 1;
    }

    mbedtls_mpi_free( &mut W[1] ); mbedtls_mpi_free( &mut T );

    match &mut _RR{
        Some(x) => {},
        None => {mbedtls_mpi_free( &mut RR );}
    }

    return ret ;
}
fn mpi_montg_init( mm: &mut mbedtls_mpi_uint,  N: &mbedtls_mpi )
{
    let mut x: mbedtls_mpi_uint;
    let m0: mbedtls_mpi_uint = N.p[0];
    let mut i: u32;

    x  = m0;
    x += ( ( m0 + 2 ) & 4 ) << 1;

    i = biL as u32;
    while i >= 8 {
        x *=  2 - ( m0 * x );
        i /= 2;
    }
    *mm = !x + 1;
}
fn mpi_montmul( A: &mut mbedtls_mpi, B: &mbedtls_mpi, N: &mbedtls_mpi, mm: mbedtls_mpi_uint, T: &mut mbedtls_mpi )
{
    let mut i: usize;
    let n: usize;
    let m: usize;
    let mut u0: mbedtls_mpi_uint;
    let mut u1: mbedtls_mpi_uint;
    let mut d: &mut Vec<mbedtls_mpi_uint>;

    for i in 0..(T.n) { T.p[i] = 0;  }

    d = &mut T.p;
    n = N.n;
    if B.n < n { m = B.n; }
    else { m = n; }

    i = 0;
    let mut di: usize = 0;      
    while i < n {
        u0 = A.p[i];
        u1 = ( d[di] + u0 * B.p[0] ) * mm;

        //mpi_mul_hlp( m, &B.p, &d, u0 );     //come after implementing this fn
        //mpi_mul_hlp( n, &N.p, &d, u1 );     //come after implementing this fn

        d[di+1] = u0;  di += 1; d[di + n + 1] = 0;  
        i += 1;
    }
    A.p[..n].clone_from_slice(&d[di..(di+n)]);     
    d[di + n] += 1;     
    d[di + n] -= mpi_sub_hlp( n, &mut d, &N.p );    
    mpi_safe_cond_assign( n, &mut A.p, &d, d[di + n] as u8 );  
}
fn mpi_montred( mut A: &mut mbedtls_mpi, N: &mbedtls_mpi, mm: mbedtls_mpi_uint, mut T: &mut mbedtls_mpi )
{
    let z: mbedtls_mpi_uint  = 1;
    let mut U: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
    U.n = z as usize;
    U.s = z as i32;
    U.p = vec![z];      
    mpi_montmul( &mut A, &U, &N, mm, &mut T );
}
fn mbedtls_mpi_mod_mpi( mut R: &mut mbedtls_mpi, A: &mbedtls_mpi, B: &mbedtls_mpi ) -> i32
{
    let ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if mbedtls_mpi_cmp_int( &B, 0 ) < 0 {
        return MBEDTLS_ERR_MPI_NEGATIVE_VALUE ;
    }

    mbedtls_mpi_div_mpi( None, Some(&mut R), &A, &B ); //todo

    while mbedtls_mpi_cmp_int( &R, 0 ) < 0 {
        let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
        mbedtls_mpi_copy(&mut tmp, &R);
        mbedtls_mpi_add_mpi( &mut R, &tmp, &B ) ;   //todo
    }

    while mbedtls_mpi_cmp_mpi( &R, &B ) >= 0  {
        let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
        mbedtls_mpi_copy(&mut tmp, &R);
        mbedtls_mpi_sub_mpi( &mut R, &tmp, &B);
    }
    return ret ;
}
fn mpi_bigendian_to_host( p: &mut Vec<mbedtls_mpi_uint>, limbs: usize )
{
    let mut cur_limb_left: usize;
    let mut cur_limb_right: usize;
    if limbs == 0 {
        return;
    }
    cur_limb_left = 0; cur_limb_right =  limbs - 1;
     while cur_limb_left <= cur_limb_right {
        let tmp: mbedtls_mpi_uint;
        tmp               = mpi_uint_bigendian_to_host_c( p[cur_limb_left]  );
        p[cur_limb_left]  = mpi_uint_bigendian_to_host_c( p[cur_limb_right] );
        p[cur_limb_right] = tmp;

        cur_limb_left += 1; cur_limb_right -= 1 ;
     }
}

fn mpi_uint_bigendian_to_host_c( x: mbedtls_mpi_uint ) -> mbedtls_mpi_uint
{
    let mut i: u8;
    let x_ptr = x.to_be_bytes();       
    let mut tmp: mbedtls_mpi_uint = 0;

	for i in 0..x_ptr.len(){        
        tmp <<= 8;           
        tmp |= x_ptr[i] as mbedtls_mpi_uint;
	}
    return tmp ;
}
fn mbedtls_mpi_inv_mod( mut X: &mut mbedtls_mpi, A: &mbedtls_mpi, N: &mbedtls_mpi ) -> i32
{
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut G: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut TA: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut TU: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
    let mut U1: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut U2: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut TB: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
    let mut TV: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut V1: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut V2: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};

    if mbedtls_mpi_cmp_int( &N, 1 ) <= 0 {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init( &mut TA ); mbedtls_mpi_init( &mut TU ); mbedtls_mpi_init( &mut U1 ); mbedtls_mpi_init( &mut U2 );
    mbedtls_mpi_init( &mut G ); mbedtls_mpi_init( &mut TB ); mbedtls_mpi_init( &mut TV );
    mbedtls_mpi_init( &mut V1 ); mbedtls_mpi_init( &mut V2 );

    mbedtls_mpi_gcd( &mut G, &A, &N ) ;

    if mbedtls_mpi_cmp_int( &mut G, 1 ) != 0 
    {
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        mbedtls_mpi_free( &mut TA ); mbedtls_mpi_free( &mut TU ); mbedtls_mpi_free( &mut U1 ); mbedtls_mpi_free( &mut U2 );
        mbedtls_mpi_free( &mut G ); mbedtls_mpi_free( &mut TB ); mbedtls_mpi_free( &mut TV );
        mbedtls_mpi_free( &mut V1 ); mbedtls_mpi_free( &mut V2 );

        return ret ;
    }

    mbedtls_mpi_mod_mpi( &mut TA, &A, &N ) ;
    mbedtls_mpi_copy( &mut TU, &TA ) ;
    mbedtls_mpi_copy( &mut TB, &N ) ;
    mbedtls_mpi_copy( &mut TV, &N ) ;

    mbedtls_mpi_lset( &mut U1, 1 ) ;
    mbedtls_mpi_lset( &mut U2, 0 ) ;
    mbedtls_mpi_lset( &mut V1, 0 ) ;
    mbedtls_mpi_lset( &mut V2, 1 ) ;
    let mut tmp1: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
				
    let mut tmp: i32 = 1;
    while tmp == 1 || mbedtls_mpi_cmp_int( &TU, 0 ) != 0 
    {
        tmp = 0 ;
        while ( TU.p[0] & 1 ) == 0 
        {
            mbedtls_mpi_shift_r( &mut TU, 1 ) ;

            if ( U1.p[0] & 1 ) != 0 || ( U2.p[0] & 1 ) != 0 
            {
				mbedtls_mpi_copy(&mut tmp1, &U1);
                mbedtls_mpi_add_mpi( &mut U1, &tmp1, &TB );
                mbedtls_mpi_copy(&mut tmp1, &U2);
                mbedtls_mpi_sub_mpi( &mut U2, &tmp1, &TA );
            }

            mbedtls_mpi_shift_r( &mut U1, 1 );
            mbedtls_mpi_shift_r( &mut U2, 1 );
        }

        while ( TV.p[0] & 1 ) == 0 
        {
            mbedtls_mpi_shift_r( &mut TV, 1 ) ;

            if ( V1.p[0] & 1 ) != 0 || ( V2.p[0] & 1 ) != 0 
            {
				mbedtls_mpi_copy(&mut tmp1, &V1);
                mbedtls_mpi_add_mpi( &mut V1, &tmp1, &TB ) ;
                mbedtls_mpi_copy(&mut tmp1, &V2);
                mbedtls_mpi_sub_mpi( &mut V2, &tmp1, &TA ) ;
            }

            mbedtls_mpi_shift_r( &mut V1, 1 ) ;
            mbedtls_mpi_shift_r( &mut V2, 1 ) ;
        }

        if mbedtls_mpi_cmp_mpi( &TU, &TV ) >= 0
        {
			mbedtls_mpi_copy(&mut tmp1, &TU);
            mbedtls_mpi_sub_mpi( &mut TU, &tmp1, &TV ) ;
            mbedtls_mpi_copy(&mut tmp1, &U1);
            mbedtls_mpi_sub_mpi( &mut U1, &tmp1, &V1 ) ;
            mbedtls_mpi_copy(&mut tmp1, &U2);
            mbedtls_mpi_sub_mpi( &mut U2, &tmp1, &V2 ) ;
        }
        else
        {
			mbedtls_mpi_copy(&mut tmp1, &TV);
            mbedtls_mpi_sub_mpi( &mut TV, &tmp1, &TU ) ;
            mbedtls_mpi_copy(&mut tmp1, &V1);
            mbedtls_mpi_sub_mpi( &mut V1, &tmp1, &U1 ) ;
            mbedtls_mpi_copy(&mut tmp1, &V2);
            mbedtls_mpi_sub_mpi( &mut V2, &tmp1, &U2 ) ;
        }
    }

    while mbedtls_mpi_cmp_int( &TU, 0 ) != 0{}

    while mbedtls_mpi_cmp_int( &V1, 0 ) < 0  {
		let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
		mbedtls_mpi_copy(&mut tmp, &V1);
        mbedtls_mpi_add_mpi( &mut V1, &tmp, N );
    }

    while mbedtls_mpi_cmp_mpi( &V1, N ) >= 0  {
		let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
		mbedtls_mpi_copy(&mut tmp, &V1);
        mbedtls_mpi_sub_mpi( &mut V1, &tmp, N );
    }
    mbedtls_mpi_copy( &mut X, &V1 );
    mbedtls_mpi_free( &mut TA ); mbedtls_mpi_free( &mut TU ); mbedtls_mpi_free( &mut U1 ); mbedtls_mpi_free( &mut U2 );
    mbedtls_mpi_free( &mut G ); mbedtls_mpi_free( &mut TB ); mbedtls_mpi_free( &mut TV );
    mbedtls_mpi_free( &mut V1 ); mbedtls_mpi_free( &mut V2 );
    return ret;
}
const small_prime: [i64; 168] = [
        3,    5,    7,   11,   13,   17,   19,   23,
       29,   31,   37,   41,   43,   47,   53,   59,
       61,   67,   71,   73,   79,   83,   89,   97,
      101,  103,  107,  109,  113,  127,  131,  137,
      139,  149,  151,  157,  163,  167,  173,  179,
      181,  191,  193,  197,  199,  211,  223,  227,
      229,  233,  239,  241,  251,  257,  263,  269,
      271,  277,  281,  283,  293,  307,  311,  313,
      317,  331,  337,  347,  349,  353,  359,  367,
      373,  379,  383,  389,  397,  401,  409,  419,
      421,  431,  433,  439,  443,  449,  457,  461,
      463,  467,  479,  487,  491,  499,  503,  509,
      521,  523,  541,  547,  557,  563,  569,  571,
      577,  587,  593,  599,  601,  607,  613,  617,
      619,  631,  641,  643,  647,  653,  659,  661,
      673,  677,  683,  691,  701,  709,  719,  727,
      733,  739,  743,  751,  757,  761,  769,  773,
      787,  797,  809,  811,  821,  823,  827,  829,
      839,  853,  857,  859,  863,  877,  881,  883,
      887,  907,  911,  919,  929,  937,  941,  947,
      953,  967,  971,  977,  983,  991,  997, -103
];      

fn mpi_check_small_factors( X: &mbedtls_mpi ) -> i32
{
    let ret: i32 = 0;
    let mut i: usize;
    let mut r: mbedtls_mpi_uint = 0;

    if ( X.p[0] & 1 ) == 0  {
        return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    }
    i = 0;
    while small_prime[i] > 0 {
        if mbedtls_mpi_cmp_int( &X, small_prime[i] ) <= 0  {
            return 1 ;
        }

        mbedtls_mpi_mod_int( &mut r, &X, small_prime[i] );

        if r == 0  {
            return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE ;
        }
        i += 1;
    }
    return ret;
}
fn mpi_miller_rabin( X: &mbedtls_mpi, rounds: usize,
    f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32, p_rng: &mut Vec<u8>) -> i32
{
    let mut ret: i32 = 0;
    let mut count: i32;
    let mut i: usize;
    let mut j: usize;
    let mut k: usize;
    let s: usize;
    let mut W: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut R: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};  let mut T: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; 
    let mut A: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut RR: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};

    mbedtls_mpi_init( &mut W ); mbedtls_mpi_init( &mut R );
    mbedtls_mpi_init( &mut T ); mbedtls_mpi_init( &mut A );
    mbedtls_mpi_init( &mut RR );

    mbedtls_mpi_sub_int( &mut W, X, 1 );
    s = mbedtls_mpi_lsb( &W );
    mbedtls_mpi_copy( &mut R, &W );
    mbedtls_mpi_shift_r( &mut R, s ) ;
 
    i = 0;
    while i < rounds {
        count = 0;
        let mut tmp: i32 = 1;
        while tmp == 1 || (mbedtls_mpi_cmp_mpi( &A, &W ) >= 0 ||
                mbedtls_mpi_cmp_int( &A, 1 )  <= 0)
        {
            tmp = 0;
             mbedtls_mpi_fill_random( &mut A, X.n * ciL, f_rng, p_rng ) ;

            j = mbedtls_mpi_bitlen( &A );
            k = mbedtls_mpi_bitlen( &W );
            if j > k {
                A.p[A.n - 1] &= ( (1 as mbedtls_mpi_uint )<< ( k - ( A.n - 1 ) * biL - 1 ) ) - 1;
            }

            if count > 30 {
                count += 1;
                ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
                mbedtls_mpi_free( &mut W ); mbedtls_mpi_free( &mut R );
                mbedtls_mpi_free( &mut T ); mbedtls_mpi_free( &mut A );
                mbedtls_mpi_free( &mut RR );
                return ret;
            }
        }
        let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
		mbedtls_mpi_copy(&mut tmp, &A);
        mbedtls_mpi_exp_mod( &mut A, &mut tmp, &R, &X, Some(&mut RR) );

        if mbedtls_mpi_cmp_mpi( &A, &W ) == 0 ||
            mbedtls_mpi_cmp_int( &A,  1 ) == 0 
           { continue; }

        j = 1;
        while j < s && mbedtls_mpi_cmp_mpi( &A, &W ) != 0 
        {
             mbedtls_mpi_mul_mpi( &mut T, &A, &A ) ;
             mbedtls_mpi_mod_mpi( &mut A, &T, &X  ) ;

            if mbedtls_mpi_cmp_int( &A, 1 ) == 0
                { break; }
            j += 1;
        }
        if mbedtls_mpi_cmp_mpi( &A, &W ) != 0 ||
            mbedtls_mpi_cmp_int( &A,  1 ) == 0
        {
            ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            break;
        }
        i += 1;
    }

    mbedtls_mpi_free( &mut W ); mbedtls_mpi_free( &mut R );
    mbedtls_mpi_free( &mut T ); mbedtls_mpi_free( &mut A );
    mbedtls_mpi_free( &mut RR );
    return ret ;
}
fn mbedtls_mpi_is_prime( X: &mbedtls_mpi, f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32, p_rng: &mut Vec<u8> ) -> i32
{
return mbedtls_mpi_is_prime_ext( &X, 40, f_rng, p_rng );
}

fn mbedtls_mpi_gen_prime( mut X: &mut mbedtls_mpi, nbits: usize, flags: i32,
f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32, mut p_rng: &mut Vec<u8> ) -> i32
{

    let CEIL_MAXUINT_DIV_SQRT2: u64 = 0xb504f333f9de6485 as u64;

    let mut ret: i32 = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    let mut k: usize ;
    let n: usize;
    let rounds: i32;
    let mut r: mbedtls_mpi_uint = 0;
    let mut Y: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};

    if nbits < 3 || nbits > MBEDTLS_MPI_MAX_BITS  as usize
        { return MBEDTLS_ERR_MPI_BAD_INPUT_DATA ; }

    mbedtls_mpi_init( &mut Y );

    n = BITS_TO_LIMBS( nbits );

    if ( flags & MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR ) == 0
    {
        if nbits >= 1300 { rounds = 2; }
        else if nbits >= 850 { rounds = 3; }
        else if nbits >= 650 { rounds = 4; }
        else if nbits >= 350 { rounds = 8; }
        else if nbits >= 250 { rounds = 12; }
        else if nbits >= 150 { rounds = 18; }
        else { rounds = 27; }
    }
    else
    {
        if nbits >= 1450 { rounds = 4; }
        else if nbits >= 1150 { rounds = 5; }
        else if nbits >= 1000 { rounds = 6; }
        else if nbits >= 850 { rounds = 7; }
        else if nbits >= 750 { rounds = 8; }
        else if nbits >= 500 { rounds = 13; }
        else if nbits >= 250 { rounds = 28; }
        else if nbits >= 150 { rounds = 40; }
        else { rounds = 51; }
    }
    loop
    {
        mbedtls_mpi_fill_random( &mut X, n * ciL, f_rng, &mut p_rng ) ;
        if X.p[n-1] < CEIL_MAXUINT_DIV_SQRT2  { continue; }

        k = n * biL;
        if k > nbits { mbedtls_mpi_shift_r( &mut X, k - nbits ) ; }
        X.p[0] |= 1;
        if ( flags & MBEDTLS_MPI_GEN_PRIME_FLAG_DH ) == 0 
        {
            ret = mbedtls_mpi_is_prime_ext( &X, rounds, f_rng, &mut p_rng );
            if ret != MBEDTLS_ERR_MPI_NOT_ACCEPTABLE 
               {    mbedtls_mpi_free( &mut Y );
                    return ret ;
                }
        }
        else
        {
            X.p[0] |= 2;

            mbedtls_mpi_mod_int( &mut r, &X, 3 );
            if r == 0  {
				let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
				mbedtls_mpi_copy(&mut tmp, &X);
                mbedtls_mpi_add_int( &mut X, &tmp, 8 );
            }
            else if r == 1  {
				let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
				mbedtls_mpi_copy(&mut tmp, &X);
                mbedtls_mpi_add_int( &mut X, &tmp, 4 ); 
            }

            mbedtls_mpi_copy( &mut Y, &X );
            mbedtls_mpi_shift_r( &mut Y, 1 );

            loop
            {
                if mpi_check_small_factors(&X ) == 0 &&
                   mpi_check_small_factors(&Y ) == 0 &&
                   mpi_miller_rabin(  &X, rounds as usize, f_rng, &mut p_rng ) == 0 &&
                   mpi_miller_rabin( &Y, rounds as usize, f_rng, &mut p_rng ) == 0 
                    {     
						mbedtls_mpi_free( &mut Y );
                        return 0; 
                    }
                if ret != MBEDTLS_ERR_MPI_NOT_ACCEPTABLE
                    {    
						mbedtls_mpi_free( &mut Y );
                        return ret;
                    }
                let mut tmp: mbedtls_mpi = mbedtls_mpi{s:0, n:0, p:vec![]};
                mbedtls_mpi_copy(&mut tmp, &X);
                mbedtls_mpi_add_int( &mut X,  &tmp, 12 );
                mbedtls_mpi_copy(&mut tmp, &Y);
                mbedtls_mpi_add_int( &mut Y,  &tmp, 6  );
            }
        }
    }
    mbedtls_mpi_free( &mut Y );
    return ret;
}

const GCD_PAIR_COUNT : usize = 3;
const gcd_pairs: [[i64; 3]; GCD_PAIR_COUNT] = 
 [  [ 693, 609, 21 ],
    [ 1764, 868, 28 ],
    [ 768454923, 542167814, 1 ]
 ];                                      
fn mbedtls_mpi_is_prime_ext( X: &mbedtls_mpi, rounds: i32,
f_rng: fn (&mut Vec<u8>, &mut [u64], usize) -> i32, p_rng: &mut Vec<u8> ) -> i32
{
    let mut ret: i32 = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut XX: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
    XX.s = 1;
    XX.n = X.n;
    XX.p[..].copy_from_slice(&X.p[..]);

    if mbedtls_mpi_cmp_int( &XX, 0 ) == 0 ||
        mbedtls_mpi_cmp_int( &XX, 1 ) == 0 {
        return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE ;
        }
    if mbedtls_mpi_cmp_int( &XX, 2 ) == 0  {
        return 0;
    }
    ret = mpi_check_small_factors( &XX );
    if  ret  != 0 
    {
        if ret == 1 {
            return 0 ;
        }
        return ret ;
    }
    return mpi_miller_rabin( &XX, rounds as usize, f_rng, p_rng ) ;
}
fn mbedtls_mpi_self_test( verbose: i32 ) -> i32
{
    let mut ret: i32 = 0;
    let mut i: usize;
    let mut A: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut E: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut N: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
    let mut X: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut Y: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]}; let mut U: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};
    let mut V: mbedtls_mpi = mbedtls_mpi{s:0,n:0,p:vec![]};

    mbedtls_mpi_init( &mut A ); mbedtls_mpi_init( &mut E ); mbedtls_mpi_init( &mut N ); mbedtls_mpi_init( &mut X );
    mbedtls_mpi_init( &mut Y ); mbedtls_mpi_init( &mut U ); mbedtls_mpi_init( &mut V );

    let s1: &str = "EFE021C2645FD1DC586E69184AF4A31ED5F53E93B5F123FA41680867BA110131944FE7952E2517337780CB0DB80E61AAE7C8DDC6C5C6AADEB34EB38A2F40D5E6";
    let s2: &str = "B2E7EFD37075B9F03FF989C7C5051C2034D2A323810251127E7BF8625A4F49A5F3E27F4DA8BD59C47D6DAABA4C8127BD5B5C25763222FEFCCFC38B832366C29E";
    let s3: &str = "0066A198186C18C10B2F5ED9B522752A9830B69916E535C8F047518A889A43A594B6BED27A168D31D4A52F88925AA8F5";
    mbedtls_mpi_read_string( &mut A, 16, &s1 ) ;        

    mbedtls_mpi_read_string( &mut E, 16, &s2 ) ;

    mbedtls_mpi_read_string( &mut N, 16, &s3 ) ;

    mbedtls_mpi_mul_mpi( &mut X, &A, &N ) ;
    let s4: &str = "602AB7ECA597A3D6B56FF9829A5E8B859E857EA95A03512E2BAE7391688D264AA5663B0341DB9CCFD2C4C5F421FEC8148001B72E848A38CAE1C65F78E56ABDEFE12D3C039B8A02D6BE593F0BBBDA56F1ECF677152EF804370C1A305CAF3B5BF130879B56C61DE584A0F53A2447A51E";
    mbedtls_mpi_read_string( &mut U, 16, &s4 ) ;

    if verbose != 0 {
        println!( "  MPI test #1 (mul_mpi): " );
    }
    if mbedtls_mpi_cmp_mpi( &X, &U ) != 0 
    {
        if verbose != 0 {
            println!( "failed\n" );
        }
        ret = 1;
        
    }
    if verbose != 0 {
        println!( "passed\n" );
    }
    mbedtls_mpi_div_mpi( Some(&mut X), Some(&mut Y), &A, &N ) ;

    let s5: &str =  "256567336059E52CAE22925474705F39A94" ;
    mbedtls_mpi_read_string( &mut U, 16, &s5) ;

    let s6: &str =  "6613F26162223DF488E9CD48CC132C7A0AC93C701B001B092E4E5B9F73BCD27B9EE50D0657C77F374E903CDFA4C642" ;
    mbedtls_mpi_read_string( &mut V, 16, &s6) ;

    if verbose != 0  {
        println!( "  MPI test #2 (div_mpi): " );
    }
    if mbedtls_mpi_cmp_mpi( &X, &U ) != 0 ||
        mbedtls_mpi_cmp_mpi( &Y, &V ) != 0 
    {
        if verbose != 0 {
            println!( "failed\n" );
        }
        ret = 1;
        if ret != 0 && verbose != 0 {
            println!( "Unexpected error, return code = {}\n", ret as i32 );
        }

        mbedtls_mpi_free( &mut A ); mbedtls_mpi_free( &mut E ); mbedtls_mpi_free( &mut N ); mbedtls_mpi_free( &mut X );
        mbedtls_mpi_free( &mut Y ); mbedtls_mpi_free( &mut U ); mbedtls_mpi_free( &mut V );

        if verbose != 0 {
            println!( "\n" );
        }
        return ret ;
    }
    if verbose != 0  {
        println!( "passed\n" );
    }

    mbedtls_mpi_exp_mod( &mut X, &mut A, &E, &N, None ) ;   //todo

    let s7: &str =   "36E139AEA55215609D2816998ED020BBBD96C37890F65171D948E9BC7CBAA4D9325D24D6A3C12710F10A09FA08AB87";
    mbedtls_mpi_read_string( &mut U, 16, &s7 ) ;

    if verbose != 0  {
        println!( "  MPI test #3 (exp_mod): " );
    }
    if mbedtls_mpi_cmp_mpi( &X, &U ) != 0 
    {
        if verbose != 0  {
            println!( "failed\n" );
        }
        ret = 1;
        if ret != 0 && verbose != 0  {
        println!( "Unexpected error, return code = {}\n", ret as i32 );
        }

        mbedtls_mpi_free( &mut A ); mbedtls_mpi_free( &mut E ); mbedtls_mpi_free( &mut N ); mbedtls_mpi_free( &mut X );
        mbedtls_mpi_free( &mut Y ); mbedtls_mpi_free( &mut U ); mbedtls_mpi_free( &mut V );

        if verbose != 0  {
            println!( "\n" );
        }
        return ret ;
    }
    if verbose != 0 {
        println!( "passed\n" );
    }

    mbedtls_mpi_inv_mod( &mut X, &A, &N ) ;

    let s8: &str = "003A0AAEDD7E784FC07D8F9EC6E3BFD5C3DBA76456363A10869622EAC2DD84ECC5B8A74DAC4D09E03B5E0BE779F2DF61";
    mbedtls_mpi_read_string( &mut U, 16, &s8 ) ;

    if verbose != 0  {
        println!( "  MPI test #4 (inv_mod): " );
    }
    if mbedtls_mpi_cmp_mpi( &X, &U ) != 0 
    {
        if verbose != 0  {
           println!( "failed\n" );
        }
        ret = 1;
        if ret != 0 && verbose != 0  {
        println!( "Unexpected error, return code = {}\n", ret as i32 );
        }

        mbedtls_mpi_free( &mut A ); mbedtls_mpi_free( &mut E ); mbedtls_mpi_free( &mut N ); mbedtls_mpi_free( &mut X );
        mbedtls_mpi_free( &mut Y ); mbedtls_mpi_free( &mut U ); mbedtls_mpi_free( &mut V );

        if verbose != 0  {
            println!( "\n" );
        }
        return ret;
    }
    if verbose != 0  {
        println!( "passed\n" );
    }
    if verbose != 0  {
        println!( "  MPI test #5 (simple gcd): " );
    }

    i = 0;
    while i < GCD_PAIR_COUNT {
        mbedtls_mpi_lset( &mut X, gcd_pairs[i][0] ) ;
        mbedtls_mpi_lset( &mut Y, gcd_pairs[i][1] ) ;

        mbedtls_mpi_gcd( &mut A, &X, &Y ) ;

        if mbedtls_mpi_cmp_int( &A, gcd_pairs[i][2] ) != 0 
        {
            if verbose != 0 {
                println!( "failed at {}\n", i );
            }
            ret = 1;
            if ret != 0 && verbose != 0  {
            println!( "Unexpected error, return code = {}\n", ret as i32 );
            }

        mbedtls_mpi_free( &mut A ); mbedtls_mpi_free( &mut E ); mbedtls_mpi_free( &mut N ); mbedtls_mpi_free( &mut X );
        mbedtls_mpi_free( &mut Y ); mbedtls_mpi_free( &mut U ); mbedtls_mpi_free( &mut V );

        if verbose != 0  {
            println!( "\n" );
        }
        return ret ;
        }
        i += 1;
    }
    if verbose != 0 {
        println!( "passed\n" );
    }
    if ret != 0 && verbose != 0  {
        println!( "Unexpected error, return code = {}\n", ret as u32 );
    }
    mbedtls_mpi_free( &mut A ); mbedtls_mpi_free( &mut E ); mbedtls_mpi_free( &mut N ); mbedtls_mpi_free( &mut X );
    mbedtls_mpi_free( &mut Y ); mbedtls_mpi_free( &mut U ); mbedtls_mpi_free( &mut V );

    if verbose != 0 {
        println!( "\n" );
    }
    return ret;
}
fn main() {
	println!("hello");
	mbedtls_mpi_self_test(1);
}


