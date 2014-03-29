probabilistic-proof-that-changing-one-bit-of-a-preimage-changes-half-the-bits-of-the-hash-value
===============================================================================================

"A single bit change in the pre-image changes, on the average, half of the 
bits in the hash value" --Bruce Schneier, _Applied Cryptography_

This script uses the pycrypto module to test the above statement for the MD2, 
MD4, MD5, RIPEMD-160, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 hash 
functions.
