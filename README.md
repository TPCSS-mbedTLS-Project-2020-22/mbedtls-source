README

* [Link](https://github.com/TPCSS-mbedTLS-Project-2020-22/source/wiki) to wiki page.


# Project Strucuture
All mbed-tls modules will have their respective rust module in this single library crate. If the mbed-tls module has several files within, we will use folders to group such submodules within a single module (as in the case of ssl-tls module).

# Contributors

* Vimal Patel
* Gokulnath Pillai

# hashing module

**Tests** : To run tests, invoke `cargo test --features="MD2,MD4,SHA1,MD5"` from the project root directory.
