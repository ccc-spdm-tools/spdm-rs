// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Ring cryptographic backend implementation.

use super::{CryptoBackend, SignatureAlgorithm};
use crate::error::{Error, Result};
use ring::signature::{self, UnparsedPublicKey};

/// Ring-based cryptographic backend.
pub struct RingBackend;

impl CryptoBackend for RingBackend {
    fn verify_signature(
        &self,
        algorithm: SignatureAlgorithm,
        tbs_data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<()> {
        log::trace!("Verifying signature with algorithm {:?}", algorithm);

        let ring_algo: &dyn signature::VerificationAlgorithm = match algorithm {
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
        };

        let pk = UnparsedPublicKey::new(ring_algo, public_key);

        pk.verify(tbs_data, signature).map_err(|_| {
            log::error!("Signature verification failed");
            Error::SignatureError(crate::error::SignatureError::VerificationFailed)
        })?;

        log::trace!("Signature verification successful");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_backend_creation() {
        let _backend = RingBackend;
    }
}
