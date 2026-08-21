# AWS-LC crypto backend

`spdmlib_crypto_aws_lc` provides classical and post-quantum cryptographic
primitives for `spdmlib`. The `full` profile is enabled by default and preserves
the complete backend.

## Algorithm profiles

The `full` profile includes:

* Hash: `sha256`, `sha384`, `sha512`
* AEAD: `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`
* Signature: `ecdsa-p256`, `ecdsa-p384`, `rsa-pkcs1`, `rsa-pss`, `ed25519`
* Key exchange: `ecdh-p256`, `ecdh-p384`
* PQC signature: `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`
* PQC key encapsulation: `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`

Consumers that need a smaller backend can disable default features and select
only the algorithms advertised by their SPDM configuration:

```toml
[dependencies.spdmlib_crypto_aws_lc]
path = "spdmlib_crypto_aws_lc"
default-features = false
features = [
    "small",
    "hashed-transcript-data",
    "sha256",
    "sha384",
    "aes-256-gcm",
    "ecdsa-p256",
    "ecdsa-p384",
    "rsa-pkcs1",
    "ecdh-p256",
    "ecdh-p384",
    "ml-dsa-87",
    "ml-kem-1024",
]
```

Callbacks return unsupported for algorithms that were not compiled. Runtime
SPDM configuration must therefore advertise only algorithms selected in the
Cargo feature set.

## Size optimization

`small` is independent of algorithm selection. It enables AWS-LC's
`OPENSSL_SMALL` mode, which favors code size over optimized implementations
without removing enabled algorithms. It can be combined with either `full` or
a reduced profile.

The per-parameter-set PQC features remove unused Rust dispatch paths. AWS-LC
currently compiles every parameter set in an enabled PQC family, so these
features do not provide complete C implementation granularity.
