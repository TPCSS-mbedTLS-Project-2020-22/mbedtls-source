# Encryption/Decryption
Files implemented: xtea.c, aria.c

# Contributors
Eikansh

---
   Ref version to use is mbedTLS v2.24.0
   
   https://github.com/ARMmbed/mbedtls/tree/v2.24.0
   
   zip/tarballs are available from here: [release/tag/v2.24.0](https://github.com/ARMmbed/mbedtls/releases/tag/v2.24.0)
   - zip: [v2.24.0.zip](https://github.com/ARMmbed/mbedtls/archive/v2.24.0.zip)
   - tarball: [v2.24.0.tar.gz](https://github.com/ARMmbed/mbedtls/archive/v2.24.0.tar.gz)
   
---

# Project Strucuture
All mbed-tls modules will have their respective rust module in this single library crate. If the mbed-tls module has several files within, we will use folders to group such submodules within a single module (as in the case of ssl-tls module).


