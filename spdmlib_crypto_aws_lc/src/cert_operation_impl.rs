// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Certificate-chain operations for the standalone aws-lc backend.
//!
//! Provides an `AwsLcBackend` implementing spdm_x509's `CryptoBackend` trait
//! that verifies BOTH traditional (RSA/ECDSA/Ed25519) AND post-quantum
//! (ML-DSA, FIPS 204) certificate signatures via aws-lc-rs. Because a single
//! backend now covers ML-DSA, the runtime PQC verifier hook
//! (`register_pqc_verifier`) is unnecessary on this path — cert-chain
//! validation goes through the normal `CryptoBackend::verify_signature`.

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use spdm_x509::crypto_backend::{CryptoBackend, SignatureAlgorithm};
use spdm_x509::error::{Error, Result};
use spdmlib::crypto::SpdmCertOperation;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};

fn classical_verification_algorithm(
    algorithm: &SignatureAlgorithm,
) -> Option<&'static dyn signature::VerificationAlgorithm> {
    match algorithm {
        #[cfg(all(feature = "ecdsa-p256", feature = "sha256"))]
        SignatureAlgorithm::EcdsaP256Sha256 => Some(&signature::ECDSA_P256_SHA256_ASN1),
        #[cfg(all(feature = "ecdsa-p256", feature = "sha384"))]
        SignatureAlgorithm::EcdsaP256Sha384 => Some(&signature::ECDSA_P256_SHA384_ASN1),
        #[cfg(all(feature = "ecdsa-p384", feature = "sha256"))]
        SignatureAlgorithm::EcdsaP384Sha256 => Some(&signature::ECDSA_P384_SHA256_ASN1),
        #[cfg(all(feature = "ecdsa-p384", feature = "sha384"))]
        SignatureAlgorithm::EcdsaP384Sha384 => Some(&signature::ECDSA_P384_SHA384_ASN1),
        #[cfg(all(feature = "rsa-pkcs1", feature = "sha256"))]
        SignatureAlgorithm::RsaPkcs1Sha256 => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
        #[cfg(all(feature = "rsa-pkcs1", feature = "sha384"))]
        SignatureAlgorithm::RsaPkcs1Sha384 => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
        #[cfg(all(feature = "rsa-pkcs1", feature = "sha512"))]
        SignatureAlgorithm::RsaPkcs1Sha512 => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
        #[cfg(all(feature = "rsa-pss", feature = "sha256"))]
        SignatureAlgorithm::RsaPssSha256 => Some(&signature::RSA_PSS_2048_8192_SHA256),
        #[cfg(all(feature = "rsa-pss", feature = "sha384"))]
        SignatureAlgorithm::RsaPssSha384 => Some(&signature::RSA_PSS_2048_8192_SHA384),
        #[cfg(all(feature = "rsa-pss", feature = "sha512"))]
        SignatureAlgorithm::RsaPssSha512 => Some(&signature::RSA_PSS_2048_8192_SHA512),
        #[cfg(feature = "ed25519")]
        SignatureAlgorithm::Ed25519 => Some(&signature::ED25519),
        _ => None,
    }
}

fn verify_ml_dsa_signature(
    algorithm: &SignatureAlgorithm,
    tbs_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Option<Result<()>> {
    let _ = (tbs_data, signature, public_key);
    match algorithm {
        #[cfg(feature = "ml-dsa-44")]
        SignatureAlgorithm::MlDsa44 => Some(
            UnparsedPublicKey::new(&aws_lc_rs::unstable::signature::ML_DSA_44, public_key)
                .verify(tbs_data, signature)
                .map_err(|_| {
                    Error::SignatureError(spdm_x509::error::SignatureError::VerificationFailed)
                }),
        ),
        #[cfg(feature = "ml-dsa-65")]
        SignatureAlgorithm::MlDsa65 => Some(
            UnparsedPublicKey::new(&aws_lc_rs::unstable::signature::ML_DSA_65, public_key)
                .verify(tbs_data, signature)
                .map_err(|_| {
                    Error::SignatureError(spdm_x509::error::SignatureError::VerificationFailed)
                }),
        ),
        #[cfg(feature = "ml-dsa-87")]
        SignatureAlgorithm::MlDsa87 => Some(
            UnparsedPublicKey::new(&aws_lc_rs::unstable::signature::ML_DSA_87, public_key)
                .verify(tbs_data, signature)
                .map_err(|_| {
                    Error::SignatureError(spdm_x509::error::SignatureError::VerificationFailed)
                }),
        ),
        _ => None,
    }
}

/// aws-lc-rs implementation of spdm_x509's `CryptoBackend` — classical + ML-DSA.
#[derive(Clone, Copy)]
pub struct AwsLcBackend;

impl CryptoBackend for AwsLcBackend {
    fn verify_signature(
        &self,
        algorithm: SignatureAlgorithm,
        tbs_data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<()> {
        if let Some(result) = verify_ml_dsa_signature(&algorithm, tbs_data, signature, public_key) {
            return result;
        }

        let classical = classical_verification_algorithm(&algorithm)
            .ok_or_else(|| Error::unsupported_algorithm("signature algorithm"))?;
        UnparsedPublicKey::new(classical, public_key)
            .verify(tbs_data, signature)
            .map_err(|_| {
                Error::SignatureError(spdm_x509::error::SignatureError::VerificationFailed)
            })
    }
}

pub static DEFAULT: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: get_cert_from_cert_chain,
    verify_cert_chain_cb: verify_cert_chain,
};

fn get_cert_from_cert_chain(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    spdm_x509::x509::chain::get_cert_from_cert_chain(cert_chain, index)
        .map_err(|_| SPDM_STATUS_INVALID_CERT)
}

fn verify_cert_chain(
    cert_chain: &[u8],
    base_asym_algo: Option<u32>,
    base_hash_algo: Option<u32>,
) -> SpdmResult {
    spdm_x509::x509::chain::verify_cert_chain_with_backend(
        cert_chain,
        AwsLcBackend,
        base_asym_algo,
        base_hash_algo,
    )
    .map_err(|_| SPDM_STATUS_INVALID_CERT)
}

#[cfg(all(
    test,
    any(feature = "ecdsa-p384", feature = "rsa-pkcs1", feature = "ml-dsa-87")
))]
mod tests {
    use super::*;

    #[cfg(feature = "ecdsa-p384")]
    #[test]
    fn test_verify_cert_chain_ecp384() {
        let chain = &include_bytes!("../../test_key/ecp384/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain(chain, None, None).is_ok());
    }

    #[cfg(feature = "rsa-pkcs1")]
    #[test]
    fn test_verify_cert_chain_rsa3072() {
        let chain = &include_bytes!("../../test_key/rsa3072/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain(chain, None, None).is_ok());
    }

    #[cfg(feature = "ml-dsa-87")]
    #[test]
    fn test_verify_cert_chain_mldsa87() {
        let chain = &include_bytes!("../../test_key/mldsa87/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain(chain, None, None).is_ok());
    }
}
