/*
* \brief Multi-precision integer library
*/ 

/// An error occurred while reading from or writing to a file.
pub const ERR_FILE_IO_ERROR     : i32 = -0x0002;
/// Bad input parameters to function.
pub const ERR_BAD_INPUT_DATA    : i32 = -0x0004;
/// There is an invalid character in the digit string.
pub const ERR_INVALID_CHARACTER : i32 = -0x0006;
/// The buffer is too small to write to.
pub const ERR_BUFFER_TOO_SMALL  : i32 = -0x0008;
/// The input arguments are negative or result in illegal output.
pub const ERR_NEGATIVE_VALUE    : i32 = -0x000A;
/// The input argument for division is zero, which is not allowed.
pub const ERR_DIVISION_BY_ZERO  : i32 = -0x000C;
/// The input arguments are not acceptable.
pub const ERR_NOT_ACCEPTABLE    : i32 = -0x000E;
/// Memory allocation failed.
pub const ERR_ALLOC_FAILED      : i32 = -0x0010;

/// Maximum size MPIs are allowed to grow to in number of limbs.
pub const MAX_LIMBS : i32 = 10000;

/// 
/// Maximum window size used for modular exponentiation. Default: 6
/// Minimum value: 1. Maximum value: 6.
/// 
/// Result is an array of ( 2 ** MBEDTLS_MPI_WINDOW_SIZE ) MPIs used
/// for the sliding window calculation. (So 64 by default)
/// 
/// Reduction in size, reduces speed.
///
/// Maximum window size used.
pub const WINDOW_SIZE : i32 = 6;

/// 
/// Maximum size of MPIs allowed in bits and bytes for user-MPIs.
/// ( Default: 512 bytes => 4096 bits, Maximum tested: 2048 bytes => 16384 bits )
/// 
/// Note: Calculations can temporarily result in larger MPIs. So the number
/// of limbs required (MBEDTLS_MPI_MAX_LIMBS) is higher.
/// 
/// Maximum number of bytes for usable MPIs.
pub const MAX_SIZE: i32 = 1024;

/// Maximum number of bits for usable MPIs.
pub const MAX_BITS: i32 = 8 * MAX_SIZE;


/// 
/// When reading from files with mbedtls_mpi_read_file() and writing to files with
/// mbedtls_mpi_write_file() the buffer should have space
/// for a (short) label, the MPI (in the provided radix), the newline
/// characters and the '\0'.
/// 
/// By default we assume at least a 10 char label, a minimum radix of 10
/// (decimal) and a maximum of 4096 bit numbers (1234 decimal chars).
/// Autosized at compile time for at least a 10 char label, a minimum radix
/// of 10 (decimal) for a number of MBEDTLS_MPI_MAX_BITS size.
/// 
/// This used to be statically sized to 1250 for a maximum of 4096 bit
/// numbers (1234 decimal chars).
/// 
/// Calculate using the formula:
///  MBEDTLS_MPI_RW_BUFFER_SIZE = ceil(MBEDTLS_MPI_MAX_BITS / ln(10) * ln(2)) +
///                                LabelSize + 6
/// 
pub const MAX_BITS_SCALE100       : i32 = 100 * MAX_BITS;
pub const LN_2_DIV_LN_10_SCALE100 : i32 = 332;
pub const RW_BUFFER_SIZE          : i32 = (MAX_BITS_SCALE100 + LN_2_DIV_LN_10_SCALE100 - 1) / LN_2_DIV_LN_10_SCALE100 + 10 + 6;


/// 
/// Define the base integer type, architecture-wise.
/// 
/// 32 or 64-bit integer types can be forced regardless of the underlying
/// architecture by defining MBEDTLS_HAVE_INT32 or MBEDTLS_HAVE_INT64
/// respectively and undefining MBEDTLS_HAVE_ASM.
/// 
/// Double-width integers (e.g. 128-bit in 64-bit architectures) can be
/// disabled by defining MBEDTLS_NO_UDBL_DIVISION.
/// 
/// Note: For now let's use only 32-bit integer.
pub type MpiSint = i32;
pub type MpiUint = u32;


/// 
/// \brief          MPI structure
/// 
pub struct Mpi{
    /// Sign: -1 if the mpi is negative, 1 otherwise
    s: i32,
    /// total # of limbs, (In rust we can discard this and instead use p.size)
    n: usize,
    /// vector of limbs
    p: Vec<MpiUint>,
}

/// 
/// \brief           Initialize an MPI context.
/// 
///                  This makes the MPI ready to be set or freed,
///                  but does not define a value for the MPI.
/// 
/// \param X         The MPI context to initialize. This must not be \c NULL.
/// 
fn init(x: &mut Mpi){
}

/// 
/// \brief          This function frees the components of an MPI context.
/// 
/// \param X        The MPI context to be cleared. This may be \c NULL,
///                 in which case this function is a no-op. If it is
///                 not \c NULL, it must point to an initialized MPI.
/// 
fn free(x: Mpi){
    // No need to do anything it will be freed by itself.
    // But you might want to zero out memory before that for safety.
}


/// 
/// \brief          Enlarge an MPI to the specified number of limbs.
/// 
/// \note           This function does nothing if the MPI is
///                 already large enough.
/// 
/// \param X        The MPI to grow. It must be initialized.
/// \param nblimbs  The target number of limbs.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         Another negative error code on other kinds of failure.
/// 
fn grow(X: &mut Mpi, nblimbs: usize) -> i32 {
    0
}

/// 
/// \brief          This function resizes an MPI downwards, keeping at least the
///                 specified number of limbs.
/// 
///                 If \c X is smaller than \c nblimbs, it is resized up
///                 instead.
/// 
/// \param X        The MPI to shrink. This must point to an initialized MPI.
/// \param nblimbs  The minimum number of limbs to keep.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
///                 (this can only happen when resizing up).
/// \return         Another negative error code on other kinds of failure.
/// 
fn shrink(X: &mut Mpi, nblimbs: usize) -> i32 {
    0
}


/// 
/// \brief          Make a copy of an MPI.
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param Y        The source MPI. This must point to an initialized MPI.
/// 
/// \note           The limb-buffer in the destination MPI is enlarged
///                 if necessary to hold the value in the source MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         Another negative error code on other kinds of failure.
/// 
fn copy(X: &mut Mpi, Y: &mut Mpi) -> i32 {
    0
}

/// 
/// \brief          Swap the contents of two MPIs.
/// 
/// \param X        The first MPI. It must be initialized.
/// \param Y        The second MPI. It must be initialized.
/// 
fn swap(X: &mut Mpi, Y: &mut Mpi) -> i32 {
    0
}

/// 
/// \brief          Perform a safe conditional copy of MPI which doesn't
///                 reveal whether the condition was true or not.
/// 
/// \param X        The MPI to conditionally assign to. This must point
///                 to an initialized MPI.
/// \param Y        The MPI to be assigned from. This must point to an
///                 initialized MPI.
/// \param assign   The condition deciding whether to perform the
///                 assignment or not. Possible values:
///                 * \c 1: Perform the assignment `X = Y`.
///                 * \c 0: Keep the original value of \p X.
/// 
/// \note           This function is equivalent to
///                      `if( assign ) mbedtls_mpi_copy( X, Y );`
///                 except that it avoids leaking any information about whether
///                 the assignment was done or not (the above code may leak
///                 information through branch prediction and/or memory access
///                 patterns analysis).
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         Another negative error code on other kinds of failure.
/// 
fn safe_cond_copy(X: &mut Mpi, Y: &mut Mpi, assign: bool) -> i32 {
    0
}

/// 
/// \brief          Perform a safe conditional swap which doesn't
///                 reveal whether the condition was true or not.
/// 
/// \param X        The first MPI. This must be initialized.
/// \param Y        The second MPI. This must be initialized.
/// \param assign   The condition deciding whether to perform
///                 the swap or not. Possible values:
///                 * \c 1: Swap the values of \p X and \p Y.
///                 * \c 0: Keep the original values of \p X and \p Y.
/// 
/// \note           This function is equivalent to
///                      if( assign ) mbedtls_mpi_swap( X, Y );
///                 except that it avoids leaking any information about whether
///                 the assignment was done or not (the above code may leak
///                 information through branch prediction and/or memory access
///                 patterns analysis).
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         Another negative error code on other kinds of failure.
/// 
fn safe_cond_swap(X: &mut Mpi, Y: &mut Mpi, assign: bool) -> i32 {
    0
}

/// 
/// \brief          Store integer value in MPI.
/// 
/// \param X        The MPI to set. This must be initialized.
/// \param z        The value to use.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         Another negative error code on other kinds of failure.
/// 
fn mpi_lset(X: &mut Mpi, z: MpiSint) -> i32 {
    0
}

/// 
/// \brief          Get a specific bit from an MPI.
/// 
/// \param X        The MPI to query. This must be initialized.
/// \param pos      Zero-based index of the bit to query.
/// 
/// \return         \c 0 or \c 1 on success, depending on whether bit \c pos
///                 of \c X is unset or set.
/// \return         A negative error code on failure.
/// 
fn get_bit(X: &Mpi, pos: usize) -> i32 {
    0
}

/// 
/// \brief          Modify a specific bit in an MPI.
/// 
/// \note           This function will grow the target MPI if necessary to set a
///                 bit to \c 1 in a not yet existing limb. It will not grow if
///                 the bit should be set to \c 0.
/// 
/// \param X        The MPI to modify. This must be initialized.
/// \param pos      Zero-based index of the bit to modify.
/// \param val      The desired value of bit \c pos: \c 0 or \c 1.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         Another negative error code on other kinds of failure.
/// 
fn set_bit(X: &Mpi, pos: usize, val: bool) -> i32 {
    0
}

/// 
/// \brief          Return the number of bits of value \c 0 before the
///                 least significant bit of value \c 1.
/// 
/// \note           This is the same as the zero-based index of
///                 the least significant bit of value \c 1.
/// 
/// \param X        The MPI to query.
/// 
/// \return         The number of bits of value \c 0 before the least significant
///                 bit of value \c 1 in \p X.
/// 
fn lsb(X: &Mpi) -> usize {
    0
}

/// 
/// \brief          Return the number of bits up to and including the most
///                 significant bit of value \c 1.
/// 
/// * \note         This is same as the one-based index of the most
///                 significant bit of value \c 1.
/// 
/// \param X        The MPI to query. This must point to an initialized MPI.
/// 
/// \return         The number of bits up to and including the most
///                 significant bit of value \c 1.
/// 
fn bitlen(X: &Mpi) -> usize {
    0
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

/// 
/// \brief          Import an MPI from an ASCII string.
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param radix    The numeric base of the input string.
/// \param s        string.
/// 
/// \return         \c 0 if successful.
/// \return         A negative error code on failure.
/// 
fn read_string(X: &mut Mpi, radix: i32, s: &str) -> i32 {
    0
}


/// 
/// \brief          Export an MPI to an ASCII string.
/// 
/// \param X        The source MPI. This must point to an initialized MPI.
/// \param radix    The numeric base of the output string.
/// \param buf      Reference of string to write to.
/// \param buflen   The available size in Bytes of \p buf. (We don't need this actually)
/// \param olen     The address at which to store the length of the string
///                 written, including the  final \c NULL byte. This must
///                 not be \c NULL.
/// 
/// \note           You can call this function with `buflen == 0` to obtain the
///                 minimum required buffer size in `*olen`.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if the target buffer \p buf
///                 is too small to hold the value of \p X in the desired base.
///                 In this case, `*olen` is nonetheless updated to contain the
///                 size of \p buf required for a successful call.
/// \return         Another negative error code on different kinds of failure.
/// 
fn write_string(X: &Mpi, radix: i32, buf: &String, buflen: usize, olen: &mut usize) -> i32 {
    0
}

/// 
/// \brief          Read an MPI from a line in an opened file.
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param radix    The numeric base of the string representation used
///                 in the source line.
/// \param fin      The input file handle to use. This must not be \c NULL.
/// 
/// \note           On success, this function advances the file stream
///                 to the end of the current line or to EOF.
/// 
///                 The function returns \c 0 on an empty line.
/// 
///                 Leading whitespaces are ignored, as is a
///                 '0x' prefix for radix \c 16.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if the file read buffer
///                 is too small.
/// \return         Another negative error code on failure.
/// 
fn read_file(X: &mut Mpi, radix: i32, fin: &mut std::fs::File) -> i32 {
    0
}

/// 
/// \brief          Export an MPI into an opened file.
/// 
/// \param p        A string prefix to emit prior to the MPI data.
///                 For example, this might be a label, or "0x" when
///                 printing in base \c 16. This may be \c NULL if no prefix
///                 is needed.
/// \param X        The source MPI. This must point to an initialized MPI.
/// \param radix    The numeric base to be used in the emitted string.
/// \param fout     The output file handle. This may be \c NULL, in which case
///                 the output is written to \c stdout.
/// 
/// \return         \c 0 if successful.
/// \return         A negative error code on failure.
/// 
fn write_file(p: &str, X: &Mpi, radix: i32, fout: &mut std::fs::File) -> i32 {
    0
}

/// 
/// \brief          Import an MPI from unsigned big endian binary data.
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param buf      The input buffer. This must be a readable buffer of length
///                 \p buflen Bytes.
/// \param buflen   The length of the input buffer \p p in Bytes.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
/// Note: Check if &Vec<u8> is appropriate for buf
fn read_binary(X: &mut Mpi, buf: &Vec<u8>, buflen: usize) -> i32 {
    0
}

/// 
/// \brief          Import X from unsigned binary data, little endian
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param buf      The input buffer. This must be a readable buffer of length
///                 \p buflen Bytes.
/// \param buflen   The length of the input buffer \p p in Bytes.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn read_binary_le(X: &mut Mpi, buf: &Vec<u8>, buflen: usize) -> i32 {
    0
}

/// 
/// \brief          Export X into unsigned binary data, big endian.
///                 Always fills the whole buffer, which will start with zeros
///                 if the number is smaller.
/// 
/// \param X        The source MPI. This must point to an initialized MPI.
/// \param buf      The output buffer. This must be a writable buffer of length
///                 \p buflen Bytes.
/// \param buflen   The size of the output buffer \p buf in Bytes.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p buf isn't
///                 large enough to hold the value of \p X.
/// \return         Another negative error code on different kinds of failure.
/// 
fn write_binary(X: &Mpi, buf: &Vec<u8>, buflen: usize) -> i32 {
    0
}

/// 
/// \brief          Export X into unsigned binary data, little endian.
///                 Always fills the whole buffer, which will end with zeros
///                 if the number is smaller.
/// 
/// \param X        The source MPI. This must point to an initialized MPI.
/// \param buf      The output buffer. This must be a writable buffer of length
///                 \p buflen Bytes.
/// \param buflen   The size of the output buffer \p buf in Bytes.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p buf isn't
///                 large enough to hold the value of \p X.
/// \return         Another negative error code on different kinds of failure.
/// 
fn write_binary_le(X: &Mpi, buf: &mut Vec<u8>, buflen: usize) -> i32 {
    0
}

/// 
/// \brief          Perform a left-shift on an MPI: X <<= count
/// 
/// \param X        The MPI to shift. This must point to an initialized MPI.
/// \param count    The number of bits to shift by.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn shift_l(X: &Mpi, count: usize) -> i32 {
    0
}

/// 
/// \brief          Perform a right-shift on an MPI: X >>= count
/// 
/// \param X        The MPI to shift. This must point to an initialized MPI.
/// \param count    The number of bits to shift by.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn shift_r(X: &Mpi, count: usize) -> i32 {
    0
}

/// 
/// \brief          Compare the absolute values of two MPIs.
/// 
/// \param X        The left-hand MPI. This must point to an initialized MPI.
/// \param Y        The right-hand MPI. This must point to an initialized MPI.
/// 
/// \return         \c 1 if `|X|` is greater than `|Y|`.
/// \return         \c -1 if `|X|` is lesser than `|Y|`.
/// \return         \c 0 if `|X|` is equal to `|Y|`.
/// 
fn cmp_abs(X: &Mpi, Y: &Mpi) -> i32 {
    0
}

/// 
/// \brief          Compare two MPIs.
/// 
/// \param X        The left-hand MPI. This must point to an initialized MPI.
/// \param Y        The right-hand MPI. This must point to an initialized MPI.
/// 
/// \return         \c 1 if \p X is greater than \p Y.
/// \return         \c -1 if \p X is lesser than \p Y.
/// \return         \c 0 if \p X is equal to \p Y.
/// 
fn cmp_mpi(X: &Mpi, Y: &Mpi) -> i32 {
    0
}

/// 
/// \brief          Check if an MPI is less than the other in constant time.
/// 
/// \param X        The left-hand MPI. This must point to an initialized MPI
///                 with the same allocated length as Y.
/// \param Y        The right-hand MPI. This must point to an initialized MPI
///                 with the same allocated length as X.
/// \param ret      The result of the comparison:
///                 \c 1 if \p X is less than \p Y.
///                 \c 0 if \p X is greater than or equal to \p Y.
/// 
/// \return         0 on success.
/// \return         MBEDTLS_ERR_MPI_BAD_INPUT_DATA if the allocated length of
///                 the two input MPIs is not the same.
/// 
fn lt_mpi_ct(X: &Mpi, Y: &Mpi, ret: &mut bool) -> i32 {
    0
}

/// 
/// \brief          Compare an MPI with an integer.
/// 
/// \param X        The left-hand MPI. This must point to an initialized MPI.
/// \param z        The integer value to compare \p X to.
/// 
/// \return         \c 1 if \p X is greater than \p z.
/// \return         \c -1 if \p X is lesser than \p z.
/// \return         \c 0 if \p X is equal to \p z.
/// 
fn cmp_int(X: &Mpi, z: MpiSint) -> i32 {
    0
}

/// 
/// \brief          Perform an unsigned addition of MPIs: X = |A| + |B|
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The first summand. This must point to an initialized MPI.
/// \param B        The second summand. This must point to an initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn add_abs(X: &mut Mpi, A: &Mpi, B: &Mpi) -> i32 {
    0
} 

/// 
/// \brief          Perform an unsigned subtraction of MPIs: X = |A| - |B|
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The minuend. This must point to an initialized MPI.
/// \param B        The subtrahend. This must point to an initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_NEGATIVE_VALUE if \p B is greater than \p A.
/// \return         Another negative error code on different kinds of failure.
/// 
/// 
fn sub_abs(X: &mut Mpi, A: &Mpi, B: &Mpi) -> i32 {
    0
} 

/// 
/// \brief          Perform a signed addition of MPIs: X = A + B
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The first summand. This must point to an initialized MPI.
/// \param B        The second summand. This must point to an initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn add_mpi(X: &mut Mpi, A: &Mpi, B: &Mpi) -> i32 {
    0
} 

/// 
/// \brief          Perform a signed subtraction of MPIs: X = A - B
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The minuend. This must point to an initialized MPI.
/// \param B        The subtrahend. This must point to an initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn sub_mpi(X: &mut Mpi, A: &Mpi, B: &Mpi) -> i32 {
    0
} 

/// 
/// \brief          Perform a signed addition of an MPI and an integer: X = A + b
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The first summand. This must point to an initialized MPI.
/// \param b        The second summand.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn add_int(X: &mut Mpi, A: &Mpi, b: MpiSint) -> i32 {
    0
}

/// 
/// \brief          Perform a signed subtraction of an MPI and an integer:
///                 X = A - b
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The minuend. This must point to an initialized MPI.
/// \param b        The subtrahend.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn sub_int(X: &mut Mpi, A: &Mpi, b: MpiSint) -> i32 {
    0
}

/// 
/// \brief          Perform a multiplication of two MPIs: X = A * B
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The first factor. This must point to an initialized MPI.
/// \param B        The second factor. This must point to an initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn mul_mpi(X: &mut Mpi, A: &Mpi, B: &Mpi) -> i32 {
    0
}

/// 
/// \brief          Perform a multiplication of an MPI with an unsigned integer:
///                 X = A * b
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The first factor. This must point to an initialized MPI.
/// \param b        The second factor.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn mul_int(X: &mut Mpi, A: &Mpi, b: MpiUint) -> i32 {
    0
}

/// 
/// \brief          Perform a division with remainder of two MPIs:
///                 A = Q * B + R
/// 
/// \param Q        The destination MPI for the quotient.
///                 This may be \c NULL if the value of the
///                 quotient is not needed.
/// \param R        The destination MPI for the remainder value.
///                 This may be \c NULL if the value of the
///                 remainder is not needed.
/// \param A        The dividend. This must point to an initialized MPi.
/// \param B        The divisor. This must point to an initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if \p B equals zero.
/// \return         Another negative error code on different kinds of failure.
/// 
fn div_mpi(Q: &mut Mpi, R: &mut Mpi, A: &Mpi, B: &Mpi) -> i32 {
    0
}

/// 
/// \brief          Perform a division with remainder of an MPI by an integer:
///                 A = Q * b + R
/// 
/// \param Q        The destination MPI for the quotient.
///                 This may be \c NULL if the value of the
///                 quotient is not needed.
/// \param R        The destination MPI for the remainder value.
///                 This may be \c NULL if the value of the
///                 remainder is not needed.
/// \param A        The dividend. This must point to an initialized MPi.
/// \param b        The divisor.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
/// \return         #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if \p b equals zero.
/// \return         Another negative error code on different kinds of failure.
/// 
fn div_int(Q: &mut Mpi, R: &mut Mpi, A: &Mpi, b: MpiSint) -> i32 {
    0
}

/// 
/// \brief          Perform a modular reduction. R = A mod B
/// 
/// \param R        The destination MPI for the residue value.
///                 This must point to an initialized MPI.
/// \param A        The MPI to compute the residue of.
///                 This must point to an initialized MPI.
/// \param B        The base of the modular reduction.
///                 This must point to an initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if \p B equals zero.
/// \return         #MBEDTLS_ERR_MPI_NEGATIVE_VALUE if \p B is negative.
/// \return         Another negative error code on different kinds of failure.
/// 
fn mod_mpi(R: &mut Mpi, A: &Mpi, B: &Mpi) -> i32 {
    0
}

/// 
/// \brief          Perform a modular reduction with respect to an integer.
///                 r = A mod b
/// 
/// \param r        The address at which to store the residue.
///                 This must not be \c NULL.
/// \param A        The MPI to compute the residue of.
///                 This must point to an initialized MPi.
/// \param b        The integer base of the modular reduction.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if \p b equals zero.
/// \return         #MBEDTLS_ERR_MPI_NEGATIVE_VALUE if \p b is negative.
/// \return         Another negative error code on different kinds of failure.
/// 
fn mod_int(r: &mut MpiUint, A: &Mpi, b: MpiSint) -> i32 {
    0
}

/// 
/// \brief          Perform a sliding-window exponentiation: X = A^E mod N
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The base of the exponentiation.
///                 This must point to an initialized MPI.
/// \param E        The exponent MPI. This must point to an initialized MPI.
/// \param N        The base for the modular reduction. This must point to an
///                 initialized MPI.
/// \param _RR      A helper MPI depending solely on \p N which can be used to
///                 speed-up multiple modular exponentiations for the same value
///                 of \p N. This may be \c NULL. If it is not \c NULL, it must
///                 point to an initialized MPI. If it hasn't been used after
///                 the call to mbedtls_mpi_init(), this function will compute
///                 the helper value and store it in \p _RR for reuse on
///                 subsequent calls to this function. Otherwise, the function
///                 will assume that \p _RR holds the helper value set by a
///                 previous call to mbedtls_mpi_exp_mod(), and reuse it.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if \c N is negative or
///                 even, or if \c E is negative.
/// \return         Another negative error code on different kinds of failures.
/// 
fn exp_mod(X: &mut Mpi, A: &Mpi, E: &Mpi, N: &Mpi, _RR: &mut Mpi) -> i32 {
    0
}


/// 
/// \brief          Fill an MPI with a number of random bytes.
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param size     The number of random bytes to generate.
/// \param f_rng    The RNG function to use. This must not be \c NULL.
/// \param p_rng    The RNG parameter to be passed to \p f_rng. This may be
///                 \c NULL if \p f_rng doesn't need a context argument.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on failure.
/// 
/// \note           The bytes obtained from the RNG are interpreted
///                 as a big-endian representation of an MPI; this can
///                 be relevant in applications like deterministic ECDSA.
/// 
fn fill_random(X: &mut Mpi, size: usize, f_rng: fn (&mut Vec<u8>, &mut Vec<u8>, usize) -> i32, p_rng: &mut Vec<u8>) -> i32 {
    0
}

/// 
/// \brief          Compute the greatest common divisor: G = gcd(A, B)
/// 
/// \param G        The destination MPI. This must point to an initialized MPI.
/// \param A        The first operand. This must point to an initialized MPI.
/// \param B        The second operand. This must point to an initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         Another negative error code on different kinds of failure.
/// 
fn gcd(G: &mut Mpi, A: &mut Mpi, B: &Mpi) -> i32 {
    0
}


/// 
/// \brief          Compute the modular inverse: X = A^-1 mod N
/// 
/// \param X        The destination MPI. This must point to an initialized MPI.
/// \param A        The MPI to calculate the modular inverse of. This must point
///                 to an initialized MPI.
/// \param N        The base of the modular inversion. This must point to an
///                 initialized MPI.
/// 
/// \return         \c 0 if successful.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if \p N is less than
///                 or equal to one.
/// \return         #MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if \p has no modular inverse
///                 with respect to \p N.
/// 
fn inv_mod(X: &mut Mpi, A: &Mpi, N: &Mpi) -> i32 {
    0
}

/// 
/// \brief          Miller-Rabin primality test.
/// 
/// \warning        If \p X is potentially generated by an adversary, for example
///                 when validating cryptographic parameters that you didn't
///                 generate yourself and that are supposed to be prime, then
///                 \p rounds should be at least the half of the security
///                 strength of the cryptographic algorithm. On the other hand,
///                 if \p X is chosen uniformly or non-adversially (as is the
///                 case when mbedtls_mpi_gen_prime calls this function), then
///                 \p rounds can be much lower.
/// 
/// \param X        The MPI to check for primality.
///                 This must point to an initialized MPI.
/// \param rounds   The number of bases to perform the Miller-Rabin primality
///                 test for. The probability of returning 0 on a composite is
///                 at most 2<sup>-2*\p rounds</sup>.
/// \param f_rng    The RNG function to use. This must not be \c NULL.
/// \param p_rng    The RNG parameter to be passed to \p f_rng.
///                 This may be \c NULL if \p f_rng doesn't use
///                 a context parameter.
/// 
/// \return         \c 0 if successful, i.e. \p X is probably prime.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         #MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if \p X is not prime.
/// \return         Another negative error code on other kinds of failure.
/// 
fn is_prime_ext(X: &Mpi, rounds: i32, f_rng: fn (&mut Vec<u8>, &mut Vec<u8>, usize) -> i32, p_rng: &mut Vec<u8>) -> i32 {
    0
}

/// 
/// \brief Flags for mbedtls_mpi_gen_prime()
/// 
/// Each of these flags is a constraint on the result X returned by
/// mbedtls_mpi_gen_prime().
/// 
pub enum GenPrimeFlagT{
    /// (X-1)/2 is prime too
    GenPrimeFlagDh =      0x0001,
    /// lower error rate from 2<sup>-80</sup> to 2<sup>-128</sup>
    GenPrimeFlagLowErr = 0x0002,
}

/// 
/// \brief          Generate a prime number.
/// 
/// \param X        The destination MPI to store the generated prime in.
///                 This must point to an initialized MPi.
/// \param nbits    The required size of the destination MPI in bits.
///                 This must be between \c 3 and #MBEDTLS_MPI_MAX_BITS.
/// \param flags    A mask of flags of type #mbedtls_mpi_gen_prime_flag_t.
/// \param f_rng    The RNG function to use. This must not be \c NULL.
/// \param p_rng    The RNG parameter to be passed to \p f_rng.
///                 This may be \c NULL if \p f_rng doesn't use
///                 a context parameter.
/// 
/// \return         \c 0 if successful, in which case \p X holds a
///                 probably prime number.
/// \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
/// \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if `nbits` is not between
///                 \c 3 and #MBEDTLS_MPI_MAX_BITS.
/// 
fn gen_prime(X: &mut Mpi, nbits: usize, flags: i32, 
    f_rng: fn (&mut Vec<u8>, &mut Vec<u8>, usize) -> i32,
    p_rng: &mut Vec<u8>) -> i32{
    0
}
