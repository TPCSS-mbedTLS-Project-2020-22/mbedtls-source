#[cfg(feature = "BIGNUM")]
use super::bignum;

///
/// \name ASN1 Error codes
/// These error codes are OR'ed to X509 error codes for
/// higher error granularity.
/// ASN1 is a standard to specify data structures.
/// 

/// Out of data when parsing an ASN1 data structure.
pub const ERR_OUT_OF_DATA     : i32 = -0x0060;
/// ASN1 tag was of an unexpected value.
pub const ERR_UNEXPECTED_TAG  : i32 = -0x0062;
/// Error when trying to determine the length or invalid length.
pub const ERR_INVALID_LENGTH  : i32 = -0x0064;
/// Actual length differs from expected length.
pub const ERR_LENGTH_MISMATCH : i32 = -0x0066;
/// Data is invalid.
pub const ERR_INVALID_DATA    : i32 = -0x0068;
/// Memory allocation failed
pub const ERR_ALLOC_FAILED    : i32 = -0x006A;
/// Buffer too small when writing ASN.1 data structure.
pub const ERR_BUF_TOO_SMALL   : i32 = -0x006C;

///
/// DER constants
/// These constants comply with the DER encoded ASN.1 type tags.
/// DER encoding uses hexadecimal representation.
/// An example DER sequence is:\n
/// - 0x02 -- tag indicating INTEGER
/// - 0x01 -- length in octets
/// - 0x05 -- value
/// Such sequences are typically read into \c ::mbedtls_x509_buf.
///

pub const BOOLEAN          : u8 = 0x01;
pub const INTEGER          : u8 = 0x02;
pub const BIT_STRING       : u8 = 0x03;
pub const OCTET_STRING     : u8 = 0x04;
pub const NULL             : u8 = 0x05;
pub const OID              : u8 = 0x06;
pub const ENUMERATED       : u8 = 0x0A;
pub const UTF8_STRING      : u8 = 0x0C;
pub const SEQUENCE         : u8 = 0x10;
pub const SET              : u8 = 0x11;
pub const PRINTABLE_STRING : u8 = 0x13;
pub const T61_STRING       : u8 = 0x14;
pub const IA5_STRING       : u8 = 0x16;
pub const UTC_TIME         : u8 = 0x17;
pub const GENERALIZED_TIME : u8 = 0x18;
pub const UNIVERSAL_STRING : u8 = 0x1C;
pub const BMP_STRING       : u8 = 0x1E;
pub const PRIMITIVE        : u8 = 0x00;
pub const CONSTRUCTED      : u8 = 0x20;
pub const CONTEXT_SPECIFIC : u8 = 0x80;

///
/// Bit masks for each of the components of an ASN.1 tag as specified in
/// ITU X.690 (08/2015), section 8.1 "General rules for encoding",
/// paragraph 8.1.2.2:
///
/// Bit  8     7   6   5          1
///     +-------+-----+------------+
///     | Class | P/C | Tag number |
///     +-------+-----+------------+
///
pub const TAG_CLASS_MASK : u8 = 0xC0;
pub const TAG_PC_MASK    : u8 = 0x20;
pub const TAG_VALUE_MASK : u8 = 0x1F;

/// Functions to parse ASN.1 data structures

/// Type-length-value structure that allows for ASN1 using DER.
pub struct Buf{
    /// ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING.
    tag: i32,
    /// ASN1 length, in octets.
    len: usize,
    /// ASN1 data, e.g. in ASCII.
    p: Vec<u8>
}

/// Container for ASN1 bit strings.
pub struct BitString{
    /// ASN1 length, in octets.
    len: usize,
    /// Number of unused bits at the end of the string
    unused_bits: u8,
    /// Raw ASN1 data for the bit string
    p: Vec<u8>
}

/// Container for a sequence of ASN.1 items
pub struct Sequence{
    /// Buffer containing the given ASN.1 item.
    buf: Buf,
    /// The next entry in the sequence.
    next: Option<Box<Sequence>>
}

/// Container for a sequence or list of 'named' ASN.1 data items
pub struct NamedData {
    /// The object identifier.
    oid: Buf,
    /// The named value.
    val: Buf,
    /// The next entry in the sequence.
    next: Option<Box<NamedData>>,
    /// Merge next item into the current one?
    next_merged: u8,
}

/// Structure used as a workaround for `unsigned char **p` in C.
///
/// In other words this buffer can be used in cases where calle might want to skip some 
/// bytes from front and subsequent calle continues to read from where last calle ended.
struct SkipBuffer{
    /// Buffer holding data
    buf: Vec<u8>,
    /// index for keeping track of location to be read
    ptr: usize,
}

///
/// \brief       Get the length of an ASN.1 element.
///              Updates the pointer to immediately behind the length.
/// 
/// \param p     On entry, \c *p points to the first byte of the length,
///              i.e. immediately after the tag.
///              On successful completion, \c *p points to the first byte
///              after the length, i.e. the first byte of the content.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param len   On successful completion, \c *len contains the length
///              read from the ASN.1 input.
/// 
/// \return      0 if successful.
/// \return      #MBEDTLS_ERR_ASN1_OUT_OF_DATA if the ASN.1 element
///              would end beyond \p end.
/// \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the length is unparseable.
/// 
fn get_len(p: &mut SkipBuffer, end: usize, len: &mut usize) -> i32 {
    0
}


/// 
/// \brief       Get the tag and length of the element.
///              Check for the requested tag.
///              Updates the pointer to immediately behind the tag and length.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p points to the first byte
///              after the length, i.e. the first byte of the content.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param len   On successful completion, \c *len contains the length
///              read from the ASN.1 input.
/// \param tag   The expected tag.
/// 
/// \return      0 if successful.
/// \return      #MBEDTLS_ERR_ASN1_UNEXPECTED_TAG if the data does not start
///              with the requested tag.
/// \return      #MBEDTLS_ERR_ASN1_OUT_OF_DATA if the ASN.1 element
///              would end beyond \p end.
/// \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the length is unparseable.
/// 
fn get_tag(p: &mut SkipBuffer, end: usize, len: &mut usize, tag: i32) -> i32 {
    0
}

/// 
/// \brief       Retrieve a boolean ASN.1 tag and its value.
///              Updates the pointer to immediately behind the full tag.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p points to the first byte
///              beyond the ASN.1 element.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param val   On success, the parsed value (\c 0 or \c 1).
/// 
/// \return      0 if successful.
/// \return      An ASN.1 error code if the input does not start with
///              a valid ASN.1 BOOLEAN.
/// 
fn get_bool(p: &mut SkipBuffer, end: usize, val: &mut i32) -> i32 {
    0
}


/// 
/// \brief       Retrieve an integer ASN.1 tag and its value.
///              Updates the pointer to immediately behind the full tag.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p points to the first byte
///              beyond the ASN.1 element.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param val   On success, the parsed value.
/// 
/// \return      0 if successful.
/// \return      An ASN.1 error code if the input does not start with
///              a valid ASN.1 INTEGER.
/// \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the parsed value does
///              not fit in an \c int.
/// 
fn get_int(p: &mut SkipBuffer, end: usize, val: &mut i32) -> i32 {
    0
}


/// 
/// \brief       Retrieve an enumerated ASN.1 tag and its value.
///              Updates the pointer to immediately behind the full tag.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p points to the first byte
///              beyond the ASN.1 element.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param val   On success, the parsed value.
/// 
/// \return      0 if successful.
/// \return      An ASN.1 error code if the input does not start with
///              a valid ASN.1 ENUMERATED.
/// \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the parsed value does
///              not fit in an \c int.
/// 
fn get_enum(p: &mut SkipBuffer, end: usize, val: &mut i32) -> i32 {
    0
}


/// 
/// \brief       Retrieve a bitstring ASN.1 tag and its value.
///              Updates the pointer to immediately behind the full tag.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p is equal to \p end.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param bs    On success, ::mbedtls_asn1_bitstring information about
///              the parsed value.
/// 
/// \return      0 if successful.
/// \return      #MBEDTLS_ERR_ASN1_LENGTH_MISMATCH if the input contains
///              extra data after a valid BIT STRING.
/// \return      An ASN.1 error code if the input does not start with
///              a valid ASN.1 BIT STRING.
/// 
fn get_bitstring(p: &mut SkipBuffer, end: usize, bs: &mut BitString) -> i32 {
    0
}

/// 
/// \brief       Retrieve a bitstring ASN.1 tag without unused bits and its
///              value.
///              Updates the pointer to the beginning of the bit/octet string.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p points to the first byte
///              of the content of the BIT STRING.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param len   On success, \c *len is the length of the content in bytes.
/// 
/// \return      0 if successful.
/// \return      #MBEDTLS_ERR_ASN1_INVALID_DATA if the input starts with
///              a valid BIT STRING with a nonzero number of unused bits.
/// \return      An ASN.1 error code if the input does not start with
///              a valid ASN.1 BIT STRING.
/// 
fn get_bitstring_null(p: &mut SkipBuffer, end: usize, len: &mut usize) -> i32 {
    0
}

/// 
/// \brief       Parses and splits an ASN.1 "SEQUENCE OF <tag>".
///              Updates the pointer to immediately behind the full sequence tag.
/// 
/// This function allocates memory for the sequence elements. You can free
/// the allocated memory with mbedtls_asn1_sequence_free().
/// 
/// \note        On error, this function may return a partial list in \p cur.
///              You must set `cur->next = NULL` before calling this function!
///              Otherwise it is impossible to distinguish a previously non-null
///              pointer from a pointer to an object allocated by this function.
/// 
/// \note        If the sequence is empty, this function does not modify
///              \c *cur. If the sequence is valid and non-empty, this
///              function sets `cur->buf.tag` to \p tag. This allows
///              callers to distinguish between an empty sequence and
///              a one-element sequence.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p is equal to \p end.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param cur   A ::mbedtls_asn1_sequence which this function fills.
///              When this function returns, \c *cur is the head of a linked
///              list. Each node in this list is allocated with
///              mbedtls_calloc() apart from \p cur itself, and should
///              therefore be freed with mbedtls_free().
///              The list describes the content of the sequence.
///              The head of the list (i.e. \c *cur itself) describes the
///              first element, `*cur->next` describes the second element, etc.
///              For each element, `buf.tag == tag`, `buf.len` is the length
///              of the content of the content of the element, and `buf.p`
///              points to the first byte of the content (i.e. immediately
///              past the length of the element).
///              Note that list elements may be allocated even on error.
/// \param tag   Each element of the sequence must have this tag.
/// 
/// \return      0 if successful.
/// \return      #MBEDTLS_ERR_ASN1_LENGTH_MISMATCH if the input contains
///              extra data after a valid SEQUENCE OF \p tag.
/// \return      #MBEDTLS_ERR_ASN1_UNEXPECTED_TAG if the input starts with
///              an ASN.1 SEQUENCE in which an element has a tag that
///              is different from \p tag.
/// \return      #MBEDTLS_ERR_ASN1_ALLOC_FAILED if a memory allocation failed.
/// \return      An ASN.1 error code if the input does not start with
///              a valid ASN.1 SEQUENCE.
/// 
fn get_sequence_of(p: &mut SkipBuffer, end: usize, cur: &mut Sequence, tag: i32) -> i32 {
    0
}

/// 
/// \brief          Free a heap-allocated linked list presentation of
///                 an ASN.1 sequence, including the first element.
/// 
/// There are two common ways to manage the memory used for the representation
/// of a parsed ASN.1 sequence:
/// - Allocate a head node `mbedtls_asn1_sequence *head` with mbedtls_calloc().
///   Pass this node as the `cur` argument to mbedtls_asn1_get_sequence_of().
///   When you have finished processing the sequence,
///   call mbedtls_asn1_sequence_free() on `head`.
/// - Allocate a head node `mbedtls_asn1_sequence *head` in any manner,
///   for example on the stack. Make sure that `head->next == NULL`.
///   Pass `head` as the `cur` argument to mbedtls_asn1_get_sequence_of().
///   When you have finished processing the sequence,
///   call mbedtls_asn1_sequence_free() on `head->cur`,
///   then free `head` itself in the appropriate manner.
/// 
/// \param seq      The address of the first sequence component. This may
///                 be \c NULL, in which case this functions returns
///                 immediately.
/// 
fn sequence_free(seq: &mut Sequence) -> i32 {
    0
}


/// 
/// \brief                Traverse an ASN.1 SEQUENCE container and
///                       call a callback for each entry.
/// 
/// This function checks that the input is a SEQUENCE of elements that
/// each have a "must" tag, and calls a callback function on the elements
/// that have a "may" tag.
/// 
/// For example, to validate that the input is a SEQUENCE of `tag1` and call
/// `cb` on each element, use
/// ```
/// mbedtls_asn1_traverse_sequence_of(&p, end, 0xff, tag1, 0, 0, cb, ctx);
/// ```
/// 
/// To validate that the input is a SEQUENCE of ANY and call `cb` on
/// each element, use
/// ```
/// mbedtls_asn1_traverse_sequence_of(&p, end, 0, 0, 0, 0, cb, ctx);
/// ```
/// 
/// To validate that the input is a SEQUENCE of CHOICE {NULL, OCTET STRING}
/// and call `cb` on each element that is an OCTET STRING, use
/// ```
/// mbedtls_asn1_traverse_sequence_of(&p, end, 0xfe, 0x04, 0xff, 0x04, cb, ctx);
/// ```
/// 
/// The callback is called on the elements with a "may" tag from left to
/// right. If the input is not a valid SEQUENCE of elements with a "must" tag,
/// the callback is called on the elements up to the leftmost point where
/// the input is invalid.
/// 
/// \warning              This function is still experimental and may change
///                       at any time.
/// 
/// \param p              The address of the pointer to the beginning of
///                       the ASN.1 SEQUENCE header. This is updated to
///                       point to the end of the ASN.1 SEQUENCE container
///                       on a successful invocation.
/// \param end            The end of the ASN.1 SEQUENCE container.
/// \param tag_must_mask  A mask to be applied to the ASN.1 tags found within
///                       the SEQUENCE before comparing to \p tag_must_value.
/// \param tag_must_val   The required value of each ASN.1 tag found in the
///                       SEQUENCE, after masking with \p tag_must_mask.
///                       Mismatching tags lead to an error.
///                       For example, a value of \c 0 for both \p tag_must_mask
///                       and \p tag_must_val means that every tag is allowed,
///                       while a value of \c 0xFF for \p tag_must_mask means
///                       that \p tag_must_val is the only allowed tag.
/// \param tag_may_mask   A mask to be applied to the ASN.1 tags found within
///                       the SEQUENCE before comparing to \p tag_may_value.
/// \param tag_may_val    The desired value of each ASN.1 tag found in the
///                       SEQUENCE, after masking with \p tag_may_mask.
///                       Mismatching tags will be silently ignored.
///                       For example, a value of \c 0 for \p tag_may_mask and
///                       \p tag_may_val means that any tag will be considered,
///                       while a value of \c 0xFF for \p tag_may_mask means
///                       that all tags with value different from \p tag_may_val
///                       will be ignored.
/// \param cb             The callback to trigger for each component
///                       in the ASN.1 SEQUENCE that matches \p tag_may_val.
///                       The callback function is called with the following
///                       parameters:
///                       - \p ctx.
///                       - The tag of the current element.
///                       - A pointer to the start of the current element's
///                         content inside the input.
///                       - The length of the content of the current element.
///                       If the callback returns a non-zero value,
///                       the function stops immediately,
///                       forwarding the callback's return value.
/// \param ctx            The context to be passed to the callback \p cb.
/// 
/// \return               \c 0 if successful the entire ASN.1 SEQUENCE
///                       was traversed without parsing or callback errors.
/// \return               #MBEDTLS_ERR_ASN1_LENGTH_MISMATCH if the input
///                       contains extra data after a valid SEQUENCE
///                       of elements with an accepted tag.
/// \return               #MBEDTLS_ERR_ASN1_UNEXPECTED_TAG if the input starts
///                       with an ASN.1 SEQUENCE in which an element has a tag
///                       that is not accepted.
/// \return               An ASN.1 error code if the input does not start with
///                       a valid ASN.1 SEQUENCE.
/// \return               A non-zero error code forwarded from the callback
///                       \p cb in case the latter returns a non-zero value.
/// 
fn traverse_sequence_of(
    p: &mut SkipBuffer, 
    end: usize, 
    tag_must_mask: u8,
    tag_must_val: u8,
    tag_may_mask: u8,
    tag_may_val: u8,
    cb: fn (
        // Note that `ctx` is `void *` in C code but we can anyway use Vec<u8>. 
        // So, you need to manually convert data in it as needed. 
        // Sorry for this but I found no other way to do this.
        ctx: &mut Vec<u8>,
        tag: i32,
        start: &mut Vec<u8>,
        len: usize 
        ) -> i32,
    ctx: &mut Vec<u8>
    ) -> i32{
    0
}

#[cfg(feature = "BIGNUM")]
/// 
/// \brief       Retrieve an integer ASN.1 tag and its value.
///              Updates the pointer to immediately behind the full tag.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p points to the first byte
///              beyond the ASN.1 element.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param X     On success, the parsed value.
/// 
/// \return      0 if successful.
/// \return      An ASN.1 error code if the input does not start with
///              a valid ASN.1 INTEGER.
/// \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the parsed value does
///              not fit in an \c int.
/// \return      An MPI error code if the parsed value is too large.
/// 
fn get_mpi(p: &mut SkipBuffer, end: usize, x: &mut bignum::mpi) -> i32 {
    0
}


/// 
/// \brief       Retrieve an AlgorithmIdentifier ASN.1 sequence.
///              Updates the pointer to immediately behind the full
///              AlgorithmIdentifier.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p points to the first byte
///              beyond the AlgorithmIdentifier element.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param alg   The buffer to receive the OID.
/// \param params The buffer to receive the parameters.
///              This is zeroized if there are no parameters.
/// 
/// \return      0 if successful or a specific ASN.1 or MPI error code.
/// 
fn get_alg(p: &mut SkipBuffer, end: usize, alg: &mut Buf, params: &mut Buf) -> i32{
    0
}


/// 
/// \brief       Retrieve an AlgorithmIdentifier ASN.1 sequence with NULL or no
///              params.
///              Updates the pointer to immediately behind the full
///              AlgorithmIdentifier.
/// 
/// \param p     On entry, \c *p points to the start of the ASN.1 element.
///              On successful completion, \c *p points to the first byte
///              beyond the AlgorithmIdentifier element.
///              On error, the value of \c *p is undefined.
/// \param end   End of data.
/// \param alg   The buffer to receive the OID.
/// 
/// \return      0 if successful or a specific ASN.1 or MPI error code.
/// 
fn get_alg_null(p: &mut SkipBuffer, end: usize, alg: &mut Buf) -> i32 {
    0
}


/// 
/// \brief       Find a specific named_data entry in a sequence or list based on
///              the OID.
/// 
/// \param list  The list to seek through
/// \param oid   The OID to look for
/// \param len   Size of the OID
/// 
/// \return      NULL if not found, or a pointer to the existing entry.
/// 
fn find_named_data<'a>(list: &'a mut NamedData, oid: &Vec<u8>, len: usize) -> &'a mut NamedData{
    // Note: following line is just a placeholder
    list
}

/// 
/// \brief       Free a mbedtls_asn1_named_data entry
/// 
/// \param entry The named data entry to free.
///              This function calls mbedtls_free() on
///              `entry->oid.p` and `entry->val.p`.
/// 
fn free_named_data(entry: NamedData) {   
    // In rust we just need to 
    // zero out this memory. 
    // Because once you leave
    // this function object will 
    // be automatically freed.
}


/// 
/// \brief       Free all entries in a mbedtls_asn1_named_data list.
/// 
/// \param head  Pointer to the head of the list of named data entries to free.
///              This function calls mbedtls_asn1_free_named_data() and
///              mbedtls_free() on each list element and
///              sets \c *head to \c NULL.
/// 
fn free_named_data_list(head: NamedData){
}