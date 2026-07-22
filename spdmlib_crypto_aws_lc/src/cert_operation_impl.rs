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
        // ML-DSA: aws-lc-rs accepts a raw or SPKI-DER public key; empty context
        // for X.509 certificate signatures.
        use aws_lc_rs::unstable::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87};

        let classical: &dyn signature::VerificationAlgorithm = match algorithm {
            SignatureAlgorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
            SignatureAlgorithm::EcdsaP256Sha384 => &signature::ECDSA_P256_SHA384_ASN1,
            SignatureAlgorithm::EcdsaP384Sha256 => &signature::ECDSA_P384_SHA256_ASN1,
            SignatureAlgorithm::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
            SignatureAlgorithm::RsaPkcs1Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RsaPkcs1Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            SignatureAlgorithm::RsaPkcs1Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            SignatureAlgorithm::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
            SignatureAlgorithm::RsaPssSha384 => &signature::RSA_PSS_2048_8192_SHA384,
            SignatureAlgorithm::RsaPssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
            SignatureAlgorithm::Ed25519 => &signature::ED25519,
            SignatureAlgorithm::MlDsa44
            | SignatureAlgorithm::MlDsa65
            | SignatureAlgorithm::MlDsa87 => {
                let algo = match algorithm {
                    SignatureAlgorithm::MlDsa44 => &ML_DSA_44,
                    SignatureAlgorithm::MlDsa65 => &ML_DSA_65,
                    SignatureAlgorithm::MlDsa87 => &ML_DSA_87,
                    _ => unreachable!(),
                };
                let pk = UnparsedPublicKey::new(algo, public_key);
                return pk.verify(tbs_data, signature).map_err(|_| {
                    Error::SignatureError(spdm_x509::error::SignatureError::VerificationFailed)
                });
            }
        };

        let pk = UnparsedPublicKey::new(classical, public_key);
        pk.verify(tbs_data, signature).map_err(|_| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_cert_chain_ecp384() {
        let chain = &include_bytes!("../../test_key/ecp384/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain(chain, None, None).is_ok());
    }

    #[test]
    fn test_verify_cert_chain_rsa3072() {
        let chain = &include_bytes!("../../test_key/rsa3072/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain(chain, None, None).is_ok());
    }

    #[test]
    fn test_verify_cert_chain_mldsa87() {
        let chain = &include_bytes!("../../test_key/mldsa87/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain(chain, None, None).is_ok());
    }
}
