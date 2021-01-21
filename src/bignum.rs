/*
* \brief Multi-precision integer library
*/

pub struct Mpi {
    /// Sign: -1 if the mpi is negative, 1 otherwise
    s: i32,
    /// total # of limbs, (In rust we can discard this and instead use p.size)
    n: usize,
    /// vector of limbs
    p: Vec<MpiUint>,
}
///
/// \brief          Return the total size of an MPI value in bytes.
///
/// \param X        The MPI to use. This must point to an initialized MPI.
///
/// \note           The value returned by this function may be less than
///                 the number of bytes used to store \p X internally.
///                 This happens if and only if there are trailing bytes
///                 of value zero.
///
/// \return         The least number of bytes capable of storing
///                 the absolute value of \p X.
///
fn size(X: &Mpi) -> usize {
    0
}

fn write_binary(X: &Mpi, buf: &Vec<u8>, buflen: usize) -> i32 {
    0
}
