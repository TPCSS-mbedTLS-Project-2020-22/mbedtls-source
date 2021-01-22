# Encryption/Decryption(gcm.rs)
 It contains   various symmetric encryption and asymmetric encryption algorithms that are accessible via the generic cipher layer and various asymmetric encryption algorithms that are accessible via the generic public key layer.

# Contributors  
 - Anshul Kumrawat
 - Darshika Tiwari

---
# File Description:

This file contains implementation of Galois counter mode(GCM) of operation,which takes full advantage of parallel processing for symmetric-key cryptographic block ciphers.

The file contains various data structures and macros for authentication errors, used by various function in the file.Some of the functions are as follows:-
- gcm_init:Initializes GCM context (just makes references valid) 
- gcm_starts:Generic GCM stream start function
- gcm_crypt_and_tag: GCM buffer encryption/decryption using a block cipher
- gcm_free: Frees up a GCM context and underlying cipher sub-context
- gcm_finish: Wraps up the GCM stream and generates the tag

---
   Ref version to use is mbedTLS v2.24.0
   
   https://github.com/ARMmbed/mbedtls/tree/v2.24.0
   
   zip/tarballs are available from here: [release/tag/v2.24.0](https://github.com/ARMmbed/mbedtls/releases/tag/v2.24.0)
   - zip: [v2.24.0.zip](https://github.com/ARMmbed/mbedtls/archive/v2.24.0.zip)
   - tarball: [v2.24.0.tar.gz](https://github.com/ARMmbed/mbedtls/archive/v2.24.0.tar.gz)
   
---

# Project Strucuture
All mbed-tls modules will have their respective rust module in this single library crate. If the mbed-tls module has several files within, we will use folders to group such submodules within a single module (as in the case of ssl-tls module).

