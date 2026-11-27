// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Cryptographic backend abstraction for signature verification.
//!
//! This module provides a trait-based abstraction for different cryptographic
//! backends.  `spdm_x509` itself ships no production backend: each crypto crate
//! (e.g. spdmlib's `spdm_ring`, `spdmlib_crypto_mbedtls`, `spdmlib_crypto_aws_lc`)
//! defines its own [`CryptoBackend`] and passes it to the `*_with_backend`
//! entry points.  The bundled `ring` backend below is gated on `cfg(test)`
//! (with `ring` as a dev-dependency) purely so this crate's own unit tests can
//! run signature verification; there is no feature to enable it in production.

extern crate alloc;

use crate::error::{Error, Result};
use const_oid::ObjectIdentifier;
use der::Tagged;

// Test-only backend: gated on `cfg(test)` with `ring` as a dev-dependency, so it
// exists only in this crate's own test builds and can never be linked into a
// production build.  Production consumers supply their own `CryptoBackend`.
#[cfg(test)]
mod ring;
#[cfg(test)]
pub use self::ring::*;

/// Signature algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA with P-256 curve and SHA-256
    EcdsaP256Sha256,
    /// ECDSA with P-256 curve and SHA-384
    EcdsaP256Sha384,
    /// ECDSA with P-384 curve and SHA-256
    EcdsaP384Sha256,
    /// ECDSA with P-384 curve and SHA-384
    EcdsaP384Sha384,
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512
    RsaPkcs1Sha512,
    /// RSA PSS with SHA-256
    RsaPssSha256,
    /// RSA PSS with SHA-384
    RsaPssSha384,
    /// RSA PSS with SHA-512
    RsaPssSha512,
    /// EdDSA Ed25519 (hash is built-in to the algorithm)
    Ed25519,
    /// ML-DSA-44 (NIST FIPS 204, hash/context handled by the algorithm)
    MlDsa44,
    /// ML-DSA-65 (NIST FIPS 204, hash/context handled by the algorithm)
    MlDsa65,
    /// ML-DSA-87 (NIST FIPS 204, hash/context handled by the algorithm)
    MlDsa87,
}

impl SignatureAlgorithm {
    /// Convert an OID, optional curve OID, and optional algorithm parameters
    /// to a SignatureAlgorithm.
    ///
    /// For ECDSA, the curve must be provided from the public key algorithm
    /// parameters.  For RSA-PSS, the hash algorithm is extracted from the
    /// RSASSA-PSS-params in the signature AlgorithmIdentifier parameters.
    pub fn from_oid_with_params(
        sig_oid: &ObjectIdentifier,
        curve_oid: Option<&ObjectIdentifier>,
        params: Option<&der::Any>,
    ) -> Result<Self> {
        const ECDSA_WITH_SHA256: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        const ECDSA_WITH_SHA384: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        const RSA_WITH_SHA256: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        const RSA_WITH_SHA384: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
        const RSA_WITH_SHA512: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
        const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

        // NIST FIPS 204 ML-DSA (2.16.840.1.101.3.4.3.{17,18,19})
        const ML_DSA_44_OID: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
        const ML_DSA_65_OID: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
        const ML_DSA_87_OID: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

        const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

        let is_absent_or_null = |p: Option<&der::Any>| match p {
            None => true,
            Some(any) => any.tag() == der::Tag::Null && any.value().is_empty(),
        };
        let invalid_params = |msg: &str| {
            Error::AlgorithmError(crate::error::AlgorithmError::InvalidParameters(
                alloc::string::String::from(msg),
            ))
        };

        match *sig_oid {
            ECDSA_WITH_SHA256 => {
                // RFC 5758 §3.2: ECDSA signature AlgorithmIdentifier parameters MUST be absent.
                if params.is_some() {
                    return Err(invalid_params("ECDSA-SHA256 parameters must be absent"));
                }
                match curve_oid {
                    Some(&SECP256R1) => Ok(SignatureAlgorithm::EcdsaP256Sha256),
                    Some(&SECP384R1) => Ok(SignatureAlgorithm::EcdsaP384Sha256),
                    Some(oid) => Err(Error::unsupported_algorithm(alloc::format!(
                        "ECDSA-SHA256 with unsupported curve OID: {}",
                        oid
                    ))),
                    None => Err(Error::unsupported_algorithm(
                        "ECDSA-SHA256 requires a curve OID in the public key parameters",
                    )),
                }
            }
            ECDSA_WITH_SHA384 => {
                // RFC 5758 §3.2: ECDSA signature AlgorithmIdentifier parameters MUST be absent.
                if params.is_some() {
                    return Err(invalid_params("ECDSA-SHA384 parameters must be absent"));
                }
                match curve_oid {
                    Some(&SECP256R1) => Ok(SignatureAlgorithm::EcdsaP256Sha384),
                    Some(&SECP384R1) => Ok(SignatureAlgorithm::EcdsaP384Sha384),
                    Some(oid) => Err(Error::unsupported_algorithm(alloc::format!(
                        "ECDSA-SHA384 with unsupported curve OID: {}",
                        oid
                    ))),
                    None => Err(Error::unsupported_algorithm(
                        "ECDSA-SHA384 requires a curve OID in the public key parameters",
                    )),
                }
            }
            RSA_WITH_SHA256 => {
                if !is_absent_or_null(params) {
                    return Err(invalid_params(
                        "RSA PKCS#1 SHA-256 parameters must be NULL or absent",
                    ));
                }
                Ok(SignatureAlgorithm::RsaPkcs1Sha256)
            }
            RSA_WITH_SHA384 => {
                if !is_absent_or_null(params) {
                    return Err(invalid_params(
                        "RSA PKCS#1 SHA-384 parameters must be NULL or absent",
                    ));
                }
                Ok(SignatureAlgorithm::RsaPkcs1Sha384)
            }
            RSA_WITH_SHA512 => {
                if !is_absent_or_null(params) {
                    return Err(invalid_params(
                        "RSA PKCS#1 SHA-512 parameters must be NULL or absent",
                    ));
                }
                Ok(SignatureAlgorithm::RsaPkcs1Sha512)
            }
            RSA_PSS => Self::parse_rsa_pss_params(params),
            ED25519_OID => {
                // RFC 8410 §3: Ed25519 signature parameters MUST be absent.
                if params.is_some() {
                    return Err(invalid_params("Ed25519 parameters must be absent"));
                }
                Ok(SignatureAlgorithm::Ed25519)
            }
            ML_DSA_44_OID => {
                // RFC 9881: ML-DSA signature parameters MUST be absent.
                if params.is_some() {
                    return Err(invalid_params("ML-DSA-44 parameters must be absent"));
                }
                Ok(SignatureAlgorithm::MlDsa44)
            }
            ML_DSA_65_OID => {
                if params.is_some() {
                    return Err(invalid_params("ML-DSA-65 parameters must be absent"));
                }
                Ok(SignatureAlgorithm::MlDsa65)
            }
            ML_DSA_87_OID => {
                if params.is_some() {
                    return Err(invalid_params("ML-DSA-87 parameters must be absent"));
                }
                Ok(SignatureAlgorithm::MlDsa87)
            }
            _ => Err(Error::unsupported_algorithm(alloc::format!(
                "OID: {}", sig_oid
            ))),
        }
    }

    /// Convert an OID and optional curve OID to a SignatureAlgorithm.
    /// For ECDSA, the curve must be provided from the public key algorithm parameters.
    pub fn from_oid_with_curve(
        sig_oid: &ObjectIdentifier,
        curve_oid: Option<&ObjectIdentifier>,
    ) -> Result<Self> {
        Self::from_oid_with_params(sig_oid, curve_oid, None)
    }

    /// Convert an OID to a SignatureAlgorithm (without curve information).
    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        Self::from_oid_with_params(oid, None, None)
    }

    /// Map an SPDM negotiated algorithm pair to a [`SignatureAlgorithm`].
    ///
    /// This is used by the high-level `verify_signature` family to translate
    /// `(SpdmBaseHashAlgo, SpdmBaseAsymAlgo)` into the backend-agnostic enum
    /// without importing `ring` directly.
    pub fn from_spdm_algos(
        hash: crate::x509::signature::SpdmBaseHashAlgo,
        asym: crate::x509::signature::SpdmBaseAsymAlgo,
    ) -> Result<Self> {
        use crate::x509::signature::{SpdmBaseAsymAlgo as A, SpdmBaseHashAlgo as H};
        match (hash, asym) {
            // ECDSA
            (H::Sha256, A::EcdsaP256) => Ok(Self::EcdsaP256Sha256),
            (H::Sha384, A::EcdsaP256) => Ok(Self::EcdsaP256Sha384),
            (H::Sha256, A::EcdsaP384) => Ok(Self::EcdsaP384Sha256),
            (H::Sha384, A::EcdsaP384) => Ok(Self::EcdsaP384Sha384),
            // RSA PKCS#1 v1.5
            (H::Sha256, A::RsaSsa2048 | A::RsaSsa3072 | A::RsaSsa4096) => Ok(Self::RsaPkcs1Sha256),
            (H::Sha384, A::RsaSsa2048 | A::RsaSsa3072 | A::RsaSsa4096) => Ok(Self::RsaPkcs1Sha384),
            (H::Sha512, A::RsaSsa2048 | A::RsaSsa3072 | A::RsaSsa4096) => Ok(Self::RsaPkcs1Sha512),
            // RSA-PSS
            (H::Sha256, A::RsaPss2048 | A::RsaPss3072 | A::RsaPss4096) => Ok(Self::RsaPssSha256),
            (H::Sha384, A::RsaPss2048 | A::RsaPss3072 | A::RsaPss4096) => Ok(Self::RsaPssSha384),
            (H::Sha512, A::RsaPss2048 | A::RsaPss3072 | A::RsaPss4096) => Ok(Self::RsaPssSha512),
            // EdDSA (hash is intrinsic)
            (_, A::Ed25519) => Ok(Self::Ed25519),
            // Unsupported
            _ => Err(Error::unsupported_algorithm(alloc::format!(
                "Unsupported SPDM algorithm combination: hash={:?}, asym={:?}",
                hash,
                asym
            ))),
        }
    }

    /// Parse and strictly validate RSASSA-PSS-params per RFC 4055 §3.1.
    ///
    /// ```asn1
    /// RSASSA-PSS-params ::= SEQUENCE {
    ///     hashAlgorithm     [0] HashAlgorithm DEFAULT sha1,
    ///     maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
    ///     saltLength        [2] INTEGER DEFAULT 20,
    ///     trailerField      [3] TrailerField DEFAULT trailerFieldBC
    /// }
    /// ```
    ///
    /// Requires SHA-256/384/512, matching MGF1 hash, saltLength equal to the
    /// digest length (32/48/64), trailerField == 1 (or absent default), and no
    /// trailing fields.
    fn parse_rsa_pss_params(params: Option<&der::Any>) -> Result<Self> {
        use der::{Reader, SliceReader, Tag, TagMode, TagNumber};
        use spki::AlgorithmIdentifier;

        const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        const SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
        const SHA512_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
        const MGF1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

        let invalid = |msg: &str| {
            Error::AlgorithmError(crate::error::AlgorithmError::InvalidParameters(
                alloc::string::String::from(msg),
            ))
        };
        let is_absent_or_null = |p: Option<&der::Any>| match p {
            None => true,
            Some(any) => any.tag() == Tag::Null && any.value().is_empty(),
        };

        let params = match params {
            Some(p) => p,
            // No parameters at all — per RFC 4055 the ASN.1 defaults are all
            // SHA-1 based, which is insecure and MUST NOT be used in SPDM.
            None => {
                return Err(Error::unsupported_algorithm(
                    "RSA-PSS without parameters defaults to SHA-1, which is not allowed",
                ))
            }
        };

        if params.tag() != Tag::Sequence {
            return Err(invalid("RSA-PSS parameters must be a DER SEQUENCE"));
        }

        // The params Any holds the SEQUENCE contents. Parse every field in order.
        let mut reader = SliceReader::new(params.value())
            .map_err(|_| invalid("Invalid RSA-PSS parameters encoding"))?;

        // [0] EXPLICIT AlgorithmIdentifier (hashAlgorithm).
        let hash_ai = reader
            .context_specific::<AlgorithmIdentifier<der::Any>>(TagNumber::N0, TagMode::Explicit)
            .map_err(|_| invalid("Malformed RSA-PSS hashAlgorithm parameter"))?
            .ok_or_else(|| {
                Error::unsupported_algorithm(
                    "RSA-PSS with no hashAlgorithm parameter defaults to SHA-1, which is not allowed",
                )
            })?;

        if !is_absent_or_null(hash_ai.parameters.as_ref()) {
            return Err(invalid(
                "RSA-PSS hashAlgorithm parameters must be NULL or absent",
            ));
        }

        let (sig_algo, expected_salt_len) = match hash_ai.oid {
            SHA256_OID => (SignatureAlgorithm::RsaPssSha256, 32u32),
            SHA384_OID => (SignatureAlgorithm::RsaPssSha384, 48u32),
            SHA512_OID => (SignatureAlgorithm::RsaPssSha512, 64u32),
            oid => {
                return Err(Error::unsupported_algorithm(alloc::format!(
                    "RSA-PSS with unsupported hash OID: {}",
                    oid
                )))
            }
        };

        // [1] EXPLICIT AlgorithmIdentifier (maskGenAlgorithm).
        // Omitting [1] defaults to mgf1SHA1, which mismatches SHA-256/384/512.
        let mgf_ai = reader
            .context_specific::<AlgorithmIdentifier<der::Any>>(TagNumber::N1, TagMode::Explicit)
            .map_err(|_| invalid("Malformed RSA-PSS maskGenAlgorithm parameter"))?
            .ok_or_else(|| {
                invalid("RSA-PSS maskGenAlgorithm is required (omission defaults to mgf1SHA1)")
            })?;

        if mgf_ai.oid != MGF1_OID {
            return Err(Error::unsupported_algorithm(alloc::format!(
                "RSA-PSS unsupported maskGenAlgorithm OID: {}",
                mgf_ai.oid
            )));
        }

        let mgf_hash_ai = mgf_ai
            .parameters
            .as_ref()
            .ok_or_else(|| invalid("RSA-PSS MGF1 missing hash AlgorithmIdentifier"))?
            .decode_as::<AlgorithmIdentifier<der::Any>>()
            .map_err(|_| invalid("Malformed RSA-PSS MGF1 hash AlgorithmIdentifier"))?;

        if mgf_hash_ai.oid != hash_ai.oid {
            return Err(invalid(
                "RSA-PSS MGF1 hash algorithm does not match hashAlgorithm",
            ));
        }
        if !is_absent_or_null(mgf_hash_ai.parameters.as_ref()) {
            return Err(invalid(
                "RSA-PSS MGF1 hash parameters must be NULL or absent",
            ));
        }

        // [2] EXPLICIT INTEGER (saltLength).
        // Omitting [2] defaults to 20 bytes, which mismatches SHA-256/384/512.
        let salt_len = reader
            .context_specific::<u32>(TagNumber::N2, TagMode::Explicit)
            .map_err(|_| invalid("Malformed RSA-PSS saltLength parameter"))?
            .ok_or_else(|| {
                invalid("RSA-PSS saltLength is required (omission defaults to 20 bytes)")
            })?;

        if salt_len != expected_salt_len {
            return Err(invalid("RSA-PSS saltLength must match digest length"));
        }

        // [3] EXPLICIT INTEGER (trailerField) — optional, default 1 (0xBC).
        if let Some(trailer) = reader
            .context_specific::<u32>(TagNumber::N3, TagMode::Explicit)
            .map_err(|_| invalid("Malformed RSA-PSS trailerField parameter"))?
        {
            if trailer != 1 {
                return Err(invalid("RSA-PSS trailerField must be 1 (0xBC)"));
            }
        }

        if !reader.is_finished() {
            return Err(invalid("Trailing data in RSA-PSS parameters"));
        }

        Ok(sig_algo)
    }
}

/// Crypto backend trait for signature verification.
///
/// Implementations of this trait provide the cryptographic operations needed
/// for X.509 certificate validation, allowing different crypto libraries to be used.
pub trait CryptoBackend {
    /// Verify a signature.
    fn verify_signature(
        &self,
        algorithm: SignatureAlgorithm,
        tbs_data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<()>;
}

// =============================================================================
// Post-Quantum (PQC) verifier hook
//
// The built-in crypto backends (ring, mbedtls) cannot verify post-quantum
// (e.g. ML-DSA / FIPS 204) signatures.  Rather than pulling a PQC crypto
// dependency into this crate, we expose a runtime-registered verification
// hook.  A downstream crate that links a PQC-capable backend (e.g.
// `spdmlib_crypto_aws_lc` over aws-lc-rs) registers a verifier once at startup
// via [`register_pqc_verifier`], and every backend's `verify_signature`
// transparently dispatches PQC signatures to it.  This keeps SPDM
// certificate-chain validation backend-agnostic while enabling PQC certificate
// chains (DSP0274 1.4).
// =============================================================================

/// A registered PQC signature-verification callback.
///
/// # Arguments
/// * `algorithm`  - the PQC signature algorithm (e.g.
///   [`SignatureAlgorithm::MlDsa44`] / `MlDsa65` / `MlDsa87`)
/// * `tbs_data`   - the TBSCertificate bytes that were signed
/// * `signature`  - the raw PQC signature bytes
/// * `public_key` - the signer's public key, either the raw public key or a
///   DER-encoded SubjectPublicKeyInfo (the callback must accept both)
pub type PqcVerifyFn = fn(
    algorithm: SignatureAlgorithm,
    tbs_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<()>;

static PQC_VERIFIER: conquer_once::spin::OnceCell<PqcVerifyFn> =
    conquer_once::spin::OnceCell::uninit();

/// Register the global PQC signature-verification callback.
///
/// Returns `true` if this call installed the verifier, `false` if one was
/// already registered (the first registration wins, mirroring the rest of the
/// spdm-rs crypto registration model).
pub fn register_pqc_verifier(verifier: PqcVerifyFn) -> bool {
    PQC_VERIFIER.try_init_once(|| verifier).is_ok()
}

/// Dispatch a PQC signature verification to the registered hook.
///
/// Returns an "unsupported algorithm" error if no verifier has been
/// registered, so that PQC certificate chains fail closed when the PQC
/// backend is absent.
pub(crate) fn verify_pqc_signature(
    algorithm: SignatureAlgorithm,
    tbs_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<()> {
    match PQC_VERIFIER.try_get() {
        Ok(verifier) => verifier(algorithm, tbs_data, signature, public_key),
        Err(_) => Err(Error::unsupported_algorithm(
            "PQC signature verification requires a registered PQC verifier",
        )),
    }
}

/// Returns `true` if the given algorithm is a post-quantum signature algorithm.
pub(crate) fn is_pqc(algorithm: SignatureAlgorithm) -> bool {
    matches!(
        algorithm,
        SignatureAlgorithm::MlDsa44 | SignatureAlgorithm::MlDsa65 | SignatureAlgorithm::MlDsa87
    )
}

/// Returns `true` if a runtime PQC verifier hook has been registered.
///
/// When a PQC-capable `CryptoBackend` (e.g. the aws-lc backend, which verifies
/// ML-DSA itself) is in use, no hook is registered and PQC signatures are
/// dispatched to the backend directly — the runtime hook is only used when a
/// classical backend (ring/mbedtls) that cannot do ML-DSA is paired with a
/// separately-registered PQC verifier.
pub(crate) fn pqc_verifier_registered() -> bool {
    PQC_VERIFIER.try_get().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::signature::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo};

    // ── from_oid_with_params: ECDSA ──

    #[test]
    fn test_ecdsa_sha256_with_p256() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        let curve = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        let result = SignatureAlgorithm::from_oid_with_params(&sig, Some(&curve), None);
        assert_eq!(result.unwrap(), SignatureAlgorithm::EcdsaP256Sha256);
    }

    #[test]
    fn test_ecdsa_sha256_with_p384() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        let curve = ObjectIdentifier::new_unwrap("1.3.132.0.34");
        let result = SignatureAlgorithm::from_oid_with_params(&sig, Some(&curve), None);
        assert_eq!(result.unwrap(), SignatureAlgorithm::EcdsaP384Sha256);
    }

    #[test]
    fn test_ecdsa_sha256_unknown_curve_rejected() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4.5");
        let result = SignatureAlgorithm::from_oid_with_params(&sig, Some(&unknown), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdsa_sha256_missing_curve_rejected() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        let result = SignatureAlgorithm::from_oid_with_params(&sig, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdsa_sha384_with_p256() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        let curve = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        let result = SignatureAlgorithm::from_oid_with_params(&sig, Some(&curve), None);
        assert_eq!(result.unwrap(), SignatureAlgorithm::EcdsaP256Sha384);
    }

    #[test]
    fn test_ecdsa_sha384_with_p384() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        let curve = ObjectIdentifier::new_unwrap("1.3.132.0.34");
        let result = SignatureAlgorithm::from_oid_with_params(&sig, Some(&curve), None);
        assert_eq!(result.unwrap(), SignatureAlgorithm::EcdsaP384Sha384);
    }

    #[test]
    fn test_ecdsa_sha384_unknown_curve_rejected() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4.5");
        let result = SignatureAlgorithm::from_oid_with_params(&sig, Some(&unknown), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdsa_sha384_missing_curve_rejected() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        let result = SignatureAlgorithm::from_oid_with_params(&sig, None, None);
        assert!(result.is_err());
    }

    // ── from_oid_with_params: RSA PKCS#1 ──

    #[test]
    fn test_rsa_pkcs1_sha256() {
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        assert_eq!(
            SignatureAlgorithm::from_oid(&oid).unwrap(),
            SignatureAlgorithm::RsaPkcs1Sha256
        );
    }

    #[test]
    fn test_rsa_pkcs1_sha384() {
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
        assert_eq!(
            SignatureAlgorithm::from_oid(&oid).unwrap(),
            SignatureAlgorithm::RsaPkcs1Sha384
        );
    }

    #[test]
    fn test_rsa_pkcs1_sha512() {
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
        assert_eq!(
            SignatureAlgorithm::from_oid(&oid).unwrap(),
            SignatureAlgorithm::RsaPkcs1Sha512
        );
    }

    // ── from_oid_with_params: Ed25519 ──

    #[test]
    fn test_ed25519() {
        let oid = ObjectIdentifier::new_unwrap("1.3.101.112");
        assert_eq!(
            SignatureAlgorithm::from_oid(&oid).unwrap(),
            SignatureAlgorithm::Ed25519
        );
    }

    // ── from_oid_with_params: ML-DSA (FIPS 204) ──

    #[test]
    fn test_ml_dsa_44_oid() {
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
        assert_eq!(
            SignatureAlgorithm::from_oid(&oid).unwrap(),
            SignatureAlgorithm::MlDsa44
        );
    }

    #[test]
    fn test_ml_dsa_65_oid() {
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
        assert_eq!(
            SignatureAlgorithm::from_oid(&oid).unwrap(),
            SignatureAlgorithm::MlDsa65
        );
    }

    #[test]
    fn test_ml_dsa_87_oid() {
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");
        assert_eq!(
            SignatureAlgorithm::from_oid(&oid).unwrap(),
            SignatureAlgorithm::MlDsa87
        );
    }

    #[test]
    fn test_is_pqc() {
        assert!(super::is_pqc(SignatureAlgorithm::MlDsa44));
        assert!(super::is_pqc(SignatureAlgorithm::MlDsa65));
        assert!(super::is_pqc(SignatureAlgorithm::MlDsa87));
        assert!(!super::is_pqc(SignatureAlgorithm::Ed25519));
        assert!(!super::is_pqc(SignatureAlgorithm::EcdsaP256Sha256));
    }

    #[test]
    fn test_pqc_verify_without_registered_hook_errors() {
        // With no PQC verifier registered, PQC signature verification must fail
        // closed rather than silently pass.
        let result =
            super::verify_pqc_signature(SignatureAlgorithm::MlDsa87, b"tbs", b"sig", b"pubkey");
        assert!(result.is_err());
    }

    // ── from_oid_with_params: unknown OID ──

    #[test]
    fn test_unknown_sig_oid_rejected() {
        let oid = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7");
        assert!(SignatureAlgorithm::from_oid(&oid).is_err());
    }

    // ── RSA-PSS and signature AlgorithmIdentifier parameter parsing ──

    fn build_rsa_pss_params(
        hash_oid: ObjectIdentifier,
        mgf_oid: Option<ObjectIdentifier>,
        mgf_hash_oid: Option<ObjectIdentifier>,
        salt_len: Option<u32>,
        trailer: Option<u32>,
    ) -> der::Any {
        use der::asn1::ContextSpecific;
        use der::{Encode, TagMode, TagNumber};
        use spki::AlgorithmIdentifier;

        let mut body = alloc::vec::Vec::new();
        let hash_ai = AlgorithmIdentifier::<der::Any> {
            oid: hash_oid,
            parameters: None,
        };
        body.extend_from_slice(
            &ContextSpecific {
                tag_number: TagNumber::N0,
                tag_mode: TagMode::Explicit,
                value: hash_ai,
            }
            .to_der()
            .unwrap(),
        );

        if let Some(mgf_oid) = mgf_oid {
            let mgf_params = mgf_hash_oid.map(|oid| {
                der::Any::encode_from(&AlgorithmIdentifier::<der::Any> {
                    oid,
                    parameters: None,
                })
                .unwrap()
            });
            let mgf_ai = AlgorithmIdentifier::<der::Any> {
                oid: mgf_oid,
                parameters: mgf_params,
            };
            body.extend_from_slice(
                &ContextSpecific {
                    tag_number: TagNumber::N1,
                    tag_mode: TagMode::Explicit,
                    value: mgf_ai,
                }
                .to_der()
                .unwrap(),
            );
        }

        if let Some(salt_len) = salt_len {
            body.extend_from_slice(
                &ContextSpecific {
                    tag_number: TagNumber::N2,
                    tag_mode: TagMode::Explicit,
                    value: salt_len,
                }
                .to_der()
                .unwrap(),
            );
        }

        if let Some(trailer) = trailer {
            body.extend_from_slice(
                &ContextSpecific {
                    tag_number: TagNumber::N3,
                    tag_mode: TagMode::Explicit,
                    value: trailer,
                }
                .to_der()
                .unwrap(),
            );
        }

        der::Any::new(der::Tag::Sequence, body).unwrap()
    }

    #[test]
    fn test_rsa_pss_no_params_rejected() {
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        // from_oid passes None for params
        let result = SignatureAlgorithm::from_oid(&oid);
        assert!(result.is_err(), "RSA-PSS without params must be rejected");
    }

    #[test]
    fn test_rsa_pss_sha256_384_512_valid_params() {
        const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
        const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
        const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

        for (hash, salt, expected) in [
            (SHA256, 32, SignatureAlgorithm::RsaPssSha256),
            (SHA384, 48, SignatureAlgorithm::RsaPssSha384),
            (SHA512, 64, SignatureAlgorithm::RsaPssSha512),
        ] {
            for trailer in [None, Some(1)] {
                let any = build_rsa_pss_params(hash, Some(MGF1), Some(hash), Some(salt), trailer);
                let result = SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&any));
                assert_eq!(result.unwrap(), expected);
            }
        }
    }

    #[test]
    fn test_rsa_pss_invalid_params_rejected() {
        const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
        const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

        // Missing [1] maskGenAlgorithm (defaults to mgf1SHA1)
        let missing_mgf = build_rsa_pss_params(SHA256, None, None, Some(32), None);
        assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&missing_mgf)).is_err());

        // Mismatched MGF1 hash (SHA-256 hash + MGF1-SHA384)
        let mismatch_mgf = build_rsa_pss_params(SHA256, Some(MGF1), Some(SHA384), Some(32), None);
        assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&mismatch_mgf)).is_err());

        // Unknown maskGenAlgorithm OID
        let bad_mgf_oid = build_rsa_pss_params(
            SHA256,
            Some(ObjectIdentifier::new_unwrap("1.2.3.4")),
            Some(SHA256),
            Some(32),
            None,
        );
        assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&bad_mgf_oid)).is_err());

        // Missing [2] saltLength (defaults to 20 bytes)
        let missing_salt = build_rsa_pss_params(SHA256, Some(MGF1), Some(SHA256), None, None);
        assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&missing_salt)).is_err());

        // Wrong [2] saltLength (0, 20, 48 for SHA-256)
        for bad_salt in [0, 20, 48] {
            let any = build_rsa_pss_params(SHA256, Some(MGF1), Some(SHA256), Some(bad_salt), None);
            assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&any)).is_err());
        }

        // Wrong [3] trailerField (must be 1)
        let bad_trailer = build_rsa_pss_params(SHA256, Some(MGF1), Some(SHA256), Some(32), Some(2));
        assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&bad_trailer)).is_err());

        // Non-SEQUENCE params tag
        let non_seq = der::Any::null();
        assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&non_seq)).is_err());

        // Trailing bytes inside RSASSA-PSS-params
        let valid = build_rsa_pss_params(SHA256, Some(MGF1), Some(SHA256), Some(32), Some(1));
        let mut trailing_body = valid.value().to_vec();
        trailing_body.extend_from_slice(&[0x05, 0x00]);
        let trailing = der::Any::new(der::Tag::Sequence, trailing_body).unwrap();
        assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&trailing)).is_err());
    }

    #[test]
    fn test_non_pss_signature_algorithm_parameter_rules() {
        let null_param = der::Any::null();
        let bad_param = der::Any::new(der::Tag::Sequence, &[][..]).unwrap();
        let p256 = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

        // ECDSA, Ed25519, ML-DSA MUST reject any parameters (including NULL).
        for (oid_str, curve) in [
            ("1.2.840.10045.4.3.2", Some(&p256)),
            ("1.2.840.10045.4.3.3", Some(&p256)),
            ("1.3.101.112", None),
            ("2.16.840.1.101.3.4.3.17", None),
            ("2.16.840.1.101.3.4.3.18", None),
            ("2.16.840.1.101.3.4.3.19", None),
        ] {
            let oid = ObjectIdentifier::new_unwrap(oid_str);
            assert!(SignatureAlgorithm::from_oid_with_params(&oid, curve, None).is_ok());
            assert!(
                SignatureAlgorithm::from_oid_with_params(&oid, curve, Some(&null_param)).is_err(),
                "{} must reject NULL params",
                oid_str
            );
            assert!(
                SignatureAlgorithm::from_oid_with_params(&oid, curve, Some(&bad_param)).is_err(),
                "{} must reject SEQUENCE params",
                oid_str
            );
        }

        // RSA PKCS#1 v1.5 accepts absent or NULL params, rejects non-NULL params.
        for oid_str in [
            "1.2.840.113549.1.1.11",
            "1.2.840.113549.1.1.12",
            "1.2.840.113549.1.1.13",
        ] {
            let oid = ObjectIdentifier::new_unwrap(oid_str);
            assert!(SignatureAlgorithm::from_oid_with_params(&oid, None, None).is_ok());
            assert!(
                SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&null_param)).is_ok()
            );
            assert!(
                SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&bad_param)).is_err(),
                "{} must reject non-NULL params",
                oid_str
            );
        }
    }

    #[test]
    fn test_rsa_pss_empty_params_sha1_rejected() {
        // Empty SEQUENCE → no [0] → defaults to SHA-1 → must be rejected
        let params_der: &[u8] = &[]; // empty SEQUENCE content
        let any = der::Any::new(der::Tag::Sequence, params_der).unwrap();
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        let result = SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&any));
        assert!(
            result.is_err(),
            "RSA-PSS with empty params (SHA-1 default) must be rejected"
        );
    }

    // ── from_spdm_algos ──

    #[test]
    fn test_from_spdm_algos_ecdsa_p256_sha256() {
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sha256,
            SpdmBaseAsymAlgo::EcdsaP256,
        );
        assert_eq!(result.unwrap(), SignatureAlgorithm::EcdsaP256Sha256);
    }

    #[test]
    fn test_from_spdm_algos_ecdsa_p384_sha384() {
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sha384,
            SpdmBaseAsymAlgo::EcdsaP384,
        );
        assert_eq!(result.unwrap(), SignatureAlgorithm::EcdsaP384Sha384);
    }

    #[test]
    fn test_from_spdm_algos_rsa_pkcs1_sha256() {
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sha256,
            SpdmBaseAsymAlgo::RsaSsa2048,
        );
        assert_eq!(result.unwrap(), SignatureAlgorithm::RsaPkcs1Sha256);
    }

    #[test]
    fn test_from_spdm_algos_rsa_pkcs1_sha384_3072() {
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sha384,
            SpdmBaseAsymAlgo::RsaSsa3072,
        );
        assert_eq!(result.unwrap(), SignatureAlgorithm::RsaPkcs1Sha384);
    }

    #[test]
    fn test_from_spdm_algos_rsa_pss_sha512_4096() {
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sha512,
            SpdmBaseAsymAlgo::RsaPss4096,
        );
        assert_eq!(result.unwrap(), SignatureAlgorithm::RsaPssSha512);
    }

    #[test]
    fn test_from_spdm_algos_ed25519_any_hash() {
        // Ed25519 should work with any hash since hash is intrinsic
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sha256,
            SpdmBaseAsymAlgo::Ed25519,
        );
        assert_eq!(result.unwrap(), SignatureAlgorithm::Ed25519);
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sha384,
            SpdmBaseAsymAlgo::Ed25519,
        );
        assert_eq!(result.unwrap(), SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_from_spdm_algos_unsupported_combo() {
        // SHA3 with RSA is not mapped
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sha3_256,
            SpdmBaseAsymAlgo::RsaSsa2048,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_from_spdm_algos_sm3_ecdsa_unsupported() {
        let result = SignatureAlgorithm::from_spdm_algos(
            SpdmBaseHashAlgo::Sm3_256,
            SpdmBaseAsymAlgo::EcdsaP256,
        );
        assert!(result.is_err());
    }

    // ── convenience wrappers ──

    #[test]
    fn test_from_oid_with_curve() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        let curve = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        let result = SignatureAlgorithm::from_oid_with_curve(&sig, Some(&curve));
        assert_eq!(result.unwrap(), SignatureAlgorithm::EcdsaP256Sha256);
    }

    #[test]
    fn test_from_oid_rsa_ignores_curve() {
        let sig = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        // curve_oid is irrelevant for RSA
        let result = SignatureAlgorithm::from_oid_with_curve(&sig, None);
        assert_eq!(result.unwrap(), SignatureAlgorithm::RsaPkcs1Sha256);
    }
}
