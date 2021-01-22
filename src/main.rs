mod test;
mod bignum_dep;
mod diffie_hellman;

use test::check;
use bignum_dep::bignum1;
use diffie_hellman::dhm;
// use test::check::ch;

fn main()
{
    test::check::print();
    check::checktwo();
    bignum1::print();
    dhm::print();
}