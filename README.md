# Encryption/Decryption(padlock.rs)
 It contains   various symmetric encryption and asymmetric encryption algorithms that are accessible via the generic cipher layer and various asymmetric encryption algorithms that are accessible via the generic public key layer.

# Contributors  
 - Anshul Kumrawat
 - Darshika Tiwari

---
# File Description:

The given file provides padlock ACE(Advanced Cryptographic Encryption)for faster hardware encryption/decryption. Padlock ACE was introduced to overcome the trade-off barrier of encryption/performance in systems.
In the main functioning of the entire program, the code instructs the compiler to load the given values of input, count and other parameters into the appropriate registers and then issues the encryption instruction sequence to finally return the value found in the eax register as a pointer.
The common functions used in the program are given as follows:-
- padlock_has_support: checks for the compatibility of the processor-padlock
- padlock_xcryptcbc: assigns every register a fixed operand for encryption
- padlock_xcryptecb: similar to cbc but encryption is ecb based

