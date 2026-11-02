## spdmlib_crypto_mbedtls library

This library wrapper mbedtls crypto interface for spdmlib.

## rust-mbedtls

This library depends on rust-mbedtls.

## Certificate validation

The backend provides `DEFAULT.verify_cert_chain_with_role_cb` for explicit
Requester or Responder leaf EKU validation. Signatures and certificate paths
are verified using the mbedTLS-backed X.509 validator. The legacy
`verify_cert_chain_cb` retains Responder-only behavior.

This backend capability does not change protocol acceptance or select a peer
role automatically. Protocol integration remains a separate change.
Other backends and test callbacks retain their existing behavior and initialize
the new optional callback to `None`. Custom `SpdmCertOperation` struct literals
must initialize it too; callers requiring a specific role must reject an absent
callback rather than fall back to Responder-only verification.

## Local testing

The released `mbedtls` bindings use an older bindgen that generates incomplete
structs with Clang 23. Use a compatible libclang (verified with 18.1.1) without
changing backend dependencies or replacing the system compiler:

```sh
python3 -m pip install --target /path/to/libclang18 libclang==18.1.1
LIBCLANG_PATH=/path/to/libclang18/clang/native \
  CARGO_TARGET_DIR=target/mbedtls-clang18 \
  cargo test -p spdmlib_crypto_mbedtls
LIBCLANG_PATH=/path/to/libclang18/clang/native \
  CARGO_TARGET_DIR=target/mbedtls-clang18 \
  cargo test -p spdmlib_crypto_mbedtls --no-default-features
```

The separate target directory avoids reusing bindings generated with an
incompatible libclang.

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
