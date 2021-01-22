# mbedtls (Rust Implementation)
[![Build Status](https://travis-ci.org/TPCSS-mbedTLS-Project-2020-22/mbedtls-source.svg?branch=master)](https://travis-ci.org/TPCSS-mbedTLS-Project-2020-22/mbedtls-source)

* [Link](https://github.com/TPCSS-mbedTLS-Project-2020-22/source/wiki) to wiki page.

---
   Ref version to use is mbedTLS v2.24.0

   https://github.com/ARMmbed/mbedtls/tree/v2.24.0

   zip/tarballs are available from here: [release/tag/v2.24.0](https://github.com/ARMmbed/mbedtls/releases/tag/v2.24.0)
   - zip: [v2.24.0.zip](https://github.com/ARMmbed/mbedtls/archive/v2.24.0.zip)
   - tarball: [v2.24.0.tar.gz](https://github.com/ARMmbed/mbedtls/archive/v2.24.0.tar.gz)

---

# Project Strucuture
All mbed-tls modules will have their respective rust module in this single library crate. If the mbed-tls module has several files within, we will use folders to group such submodules within a single module (as in the case of ssl-tls module).

# Contributors

* Raj Jha
* Paras Lohani

# Entropy (RNG module)

We have implemented how to gather entropy and generate it from different strong sources and the code for them is in src/entropy.rs. The various test conducted are in the file src/main.rs. To check and compile the project, run command "cargo build" and for running the tests run command "cargo test".
