# mbedtls-source
Source code for the project
* [Link](https://github.com/TPCSS-mbedTLS-Project-2020-22/source/wiki) to wiki page.

# ASN.1 Format
An HTTPS certificate is a type of file that follows a format defined by RFC 5280. The definations are expressed in ASN.1. It defines the file format or data structure.

---
# Contributors
 - Aanchal Satpuri
 - Nandini Gour
 
 ---
 
 # File Description
 asn1write is implementation of buffer writing functionality.
 
 ---
   Ref version to use is mbedTLS v2.24.0
   
 ---
# Project Strucuture
All mbed-tls modules will have their respective rust module in this single library crate. If the mbed-tls module has several files within, we will use folders to group such submodules within a single module (as in the case of ssl-tls module).
