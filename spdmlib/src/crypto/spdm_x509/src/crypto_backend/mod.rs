// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Cryptographic backend abstraction for signature verification.
//!
//! This module provides a trait-based abstraction for different cryptographic backends,
//! allowing spdm_x509 to work with multiple crypto implementations (ring, mbedtls, etc.).

extern crate alloc;

use crate::error::{Error, Result};
use const_oid::ObjectIdentifier;

#[cfg(feature = "ring-backend")]
mod ring;
#[cfg(feature = "ring-backend")]
pub use self::ring::*;

#[cfg(feature = "mbedtls-backend")]
mod mbedtls;
#[cfg(feature = "mbedtls-backend")]
pub use self::mbedtls::*;

// The default crypto backend used by the convenience entry points
// (`verify_cert_chain`, `Validator::new`, etc.).  `ring` and `mbedtls` are
// mutually exclusive in practice, but Cargo features are additive; if both are
// enabled the ring backend wins so behavior stays deterministic.
#[cfg(feature = "ring-backend")]
pub type DefaultBackend = RingBackend;
#[cfg(all(feature = "mbedtls-backend", not(feature = "ring-backend")))]
pub type DefaultBackend = MbedtlsBackend;

/// Construct the default crypto backend (see [`DefaultBackend`]).
#[cfg(feature = "ring-backend")]
pub fn default_backend() -> DefaultBackend {
    RingBackend
}

/// Construct the default crypto backend (see [`DefaultBackend`]).
#[cfg(all(feature = "mbedtls-backend", not(feature = "ring-backend")))]
pub fn default_backend() -> DefaultBackend {
    MbedtlsBackend
}

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

        match *sig_oid {
            ECDSA_WITH_SHA256 => match curve_oid {
                Some(&SECP256R1) => Ok(SignatureAlgorithm::EcdsaP256Sha256),
                Some(&SECP384R1) => Ok(SignatureAlgorithm::EcdsaP384Sha256),
                Some(oid) => Err(Error::unsupported_algorithm(alloc::format!(
                    "ECDSA-SHA256 with unsupported curve OID: {}",
                    oid
                ))),
                None => Err(Error::unsupported_algorithm(
                    "ECDSA-SHA256 requires a curve OID in the public key parameters",
                )),
            },
            ECDSA_WITH_SHA384 => match curve_oid {
                Some(&SECP256R1) => Ok(SignatureAlgorithm::EcdsaP256Sha384),
                Some(&SECP384R1) => Ok(SignatureAlgorithm::EcdsaP384Sha384),
                Some(oid) => Err(Error::unsupported_algorithm(alloc::format!(
                    "ECDSA-SHA384 with unsupported curve OID: {}",
                    oid
                ))),
                None => Err(Error::unsupported_algorithm(
                    "ECDSA-SHA384 requires a curve OID in the public key parameters",
                )),
            },
            RSA_WITH_SHA256 => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
            RSA_WITH_SHA384 => Ok(SignatureAlgorithm::RsaPkcs1Sha384),
            RSA_WITH_SHA512 => Ok(SignatureAlgorithm::RsaPkcs1Sha512),
            RSA_PSS => Self::parse_rsa_pss_params(params),
            ED25519_OID => Ok(SignatureAlgorithm::Ed25519),
            ML_DSA_44_OID => Ok(SignatureAlgorithm::MlDsa44),
            ML_DSA_65_OID => Ok(SignatureAlgorithm::MlDsa65),
            ML_DSA_87_OID => Ok(SignatureAlgorithm::MlDsa87),
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

    /// Parse RSASSA-PSS-params to determine the hash algorithm.
    ///
    /// ```asn1
    /// RSASSA-PSS-params ::= SEQUENCE {
    ///     hashAlgorithm     [0] HashAlgorithm DEFAULT sha1,
    ///     maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
    ///     saltLength        [2] INTEGER DEFAULT 20,
    ///     trailerField      [3] TrailerField DEFAULT trailerFieldBC
    /// }
    /// ```
    fn parse_rsa_pss_params(params: Option<&der::Any>) -> Result<Self> {
        use der::{Reader, SliceReader, TagMode, TagNumber};
        use spki::AlgorithmIdentifier;

        const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        const SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
        const SHA512_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

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

        // The params Any holds the SEQUENCE contents.  Parse the inner fields.
        let mut reader = SliceReader::new(params.value())
            .map_err(|_| Error::unsupported_algorithm("Invalid RSA-PSS parameters encoding"))?;

        // Try to read [0] EXPLICIT AlgorithmIdentifier (hash algorithm).
        let hash_oid: Option<ObjectIdentifier> = reader
            .context_specific::<AlgorithmIdentifier<der::Any>>(TagNumber::N0, TagMode::Explicit)
            .ok()
            .flatten()
            .map(|ai| ai.oid);

        match hash_oid {
            Some(oid) if oid == SHA256_OID => Ok(SignatureAlgorithm::RsaPssSha256),
            Some(oid) if oid == SHA384_OID => Ok(SignatureAlgorithm::RsaPssSha384),
            Some(oid) if oid == SHA512_OID => Ok(SignatureAlgorithm::RsaPssSha512),
            Some(oid) => Err(Error::unsupported_algorithm(alloc::format!(
                "RSA-PSS with unsupported hash OID: {}",
                oid
            ))),
            // [0] absent — per RFC 4055 the ASN.1 default is SHA-1, which
            // is insecure and MUST NOT be used in SPDM.  Reject explicitly.
            None => Err(Error::unsupported_algorithm(
                "RSA-PSS with no hashAlgorithm parameter defaults to SHA-1, which is not allowed",
            )),
        }
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

    // ── RSA-PSS parameter parsing ──

    #[test]
    fn test_rsa_pss_no_params_rejected() {
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        // from_oid passes None for params
        let result = SignatureAlgorithm::from_oid(&oid);
        assert!(result.is_err(), "RSA-PSS without params must be rejected");
    }

    #[test]
    fn test_rsa_pss_sha256_params() {
        // Build RSASSA-PSS-params with [0] EXPLICIT AlgorithmIdentifier { SHA-256 }
        // SEQUENCE {
        //   [0] EXPLICIT SEQUENCE { OID 2.16.840.1.101.3.4.2.1 }
        // }
        let params_der: &[u8] = &[
            0xa0, 0x0d, // [0] EXPLICIT, length 13
            0x30, 0x0b, // SEQUENCE, length 11
            0x06, 0x09, // OID, length 9
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // 2.16.840.1.101.3.4.2.1
        ];
        let any = der::Any::new(der::Tag::Sequence, params_der).unwrap();
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        let result = SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&any));
        assert_eq!(result.unwrap(), SignatureAlgorithm::RsaPssSha256);
    }

    #[test]
    fn test_rsa_pss_sha384_params() {
        let params_der: &[u8] = &[
            0xa0, 0x0d, // [0] EXPLICIT, length 13
            0x30, 0x0b, // SEQUENCE, length 11
            0x06, 0x09, // OID, length 9
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, // 2.16.840.1.101.3.4.2.2
        ];
        let any = der::Any::new(der::Tag::Sequence, params_der).unwrap();
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        let result = SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&any));
        assert_eq!(result.unwrap(), SignatureAlgorithm::RsaPssSha384);
    }

    #[test]
    fn test_rsa_pss_sha512_params() {
        let params_der: &[u8] = &[
            0xa0, 0x0d, // [0] EXPLICIT, length 13
            0x30, 0x0b, // SEQUENCE, length 11
            0x06, 0x09, // OID, length 9
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, // 2.16.840.1.101.3.4.2.3
        ];
        let any = der::Any::new(der::Tag::Sequence, params_der).unwrap();
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        let result = SignatureAlgorithm::from_oid_with_params(&oid, None, Some(&any));
        assert_eq!(result.unwrap(), SignatureAlgorithm::RsaPssSha512);
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
