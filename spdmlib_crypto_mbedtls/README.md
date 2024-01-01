## spdmlib_crypto_mbedtls library

This library wrapper mbedtls crypto interface for spdmlib.

## rust-mbedtls

This library depends on rust-mbedtls.

## Algorithms implemented

* Asymmetric algo
  * ECDSA-NIST_P384
  * ECDSA-NIST_P256
  * RSASSA-3072
* Hash
  * SHA2-384
  * SHA2-256
* Key Exchange 
  * ECDHE SECP 384r1
  * ECDHE SECP 256r1
* AEAD
  * AES-256-GCM

## no_std usage.

Disable ```std``` feature and provide ```calloc``` ```free``` ```snprintf``` implementation.
