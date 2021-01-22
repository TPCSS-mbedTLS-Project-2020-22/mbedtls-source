mod bignum_dep;
mod diffie_hellman;

use bignum_dep::bignum1;
use diffie_hellman::dhm;

fn main()
{
    bignum1::print();
    dhm::print();
}