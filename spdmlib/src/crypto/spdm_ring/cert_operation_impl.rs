// Copyright (c) 2021, 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;

use crate::crypto::SpdmCertOperation;
use crate::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};
use ring::signature::{self, UnparsedPublicKey};
use spdm_x509::crypto_backend::{CryptoBackend, SignatureAlgorithm};
use spdm_x509::error::{Error as X509Error, Result as X509Result, SignatureError};

// =============================================================================
// ring CryptoBackend for spdm_x509 certificate-chain validation.
//
// spdm_x509 ships no built-in backend; each crypto crate supplies its own. This
// backend verifies classical (RSA/ECDSA/Ed25519) certificate signatures via
// ring. Post-quantum (ML-DSA / FIPS 204) signatures are dispatched by
// spdm_x509's validator to the registered PQC verifier hook (e.g. from
// spdmlib_crypto_aws_lc) and never reach this backend.
// =============================================================================

/// ring-based crypto backend for X.509 signature verification.
#[derive(Clone, Copy)]
pub struct RingBackend;

impl CryptoBackend for RingBackend {
    fn verify_signature(
        &self,
        algorithm: SignatureAlgorithm,
        tbs_data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> X509Result<()> {
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
            SignatureAlgorithm::MlDsa44
            | SignatureAlgorithm::MlDsa65
            | SignatureAlgorithm::MlDsa87 => {
                return Err(X509Error::unsupported_algorithm(
                    "ML-DSA is not supported by the ring backend",
                ));
            }
        };

        let pk = UnparsedPublicKey::new(ring_algo, public_key);
        pk.verify(tbs_data, signature)
            .map_err(|_| X509Error::SignatureError(SignatureError::VerificationFailed))
    }
}

pub static DEFAULT: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: get_cert_from_cert_chain_x509,
    verify_cert_chain_cb: verify_cert_chain_x509,
};

fn get_cert_from_cert_chain_x509(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    spdm_x509::x509::chain::get_cert_from_cert_chain(cert_chain, index)
        .map_err(|_| SPDM_STATUS_INVALID_CERT)
}

fn verify_cert_chain_x509(
    cert_chain: &[u8],
    base_asym_algo: Option<u32>,
    base_hash_algo: Option<u32>,
) -> SpdmResult {
    spdm_x509::x509::chain::verify_cert_chain_with_backend(
        cert_chain,
        RingBackend,
        base_asym_algo,
        base_hash_algo,
    )
    .map_err(|_| SPDM_STATUS_INVALID_CERT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain_x509(cert_chain, -1).is_ok();
        assert!(status);
    }

    #[test]
    fn test_case1_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain_x509(cert_chain, 0).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case2_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain_x509(cert_chain, 1).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case3_cert_from_cert_chain() {
        let cert_chain = &mut [0x1u8; 4096];
        cert_chain[0] = 0x00;
        cert_chain[1] = 0x00;
        let status = get_cert_from_cert_chain_x509(cert_chain, 0).is_err();
        assert!(status);
    }
    #[test]
    fn test_case4_cert_from_cert_chain() {
        let cert_chain = &mut [0x11u8; 3];
        let status = get_cert_from_cert_chain_x509(cert_chain, 0).is_err();
        assert!(status);
    }
    #[test]
    fn test_case5_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain_x509(cert_chain, -1).is_ok();
        assert!(status);

        let status = verify_cert_chain_x509(cert_chain, None, None).is_ok();
        assert!(status);
    }

    /// verfiy cert chain
    #[test]
    fn test_verify_cert_chain_case1() {
        let bundle_certs_der =
            &include_bytes!("../../../../test_key/crypto_chains/ca_selfsigned.crt.der")[..];
        assert!(verify_cert_chain_x509(bundle_certs_der, None, None).is_ok());

        let bundle_certs_der =
            &include_bytes!("../../../../test_key/crypto_chains/bundle_two_level_cert.der")[..];
        assert!(verify_cert_chain_x509(bundle_certs_der, None, None).is_ok());

        let bundle_certs_der =
            &include_bytes!("../../../../test_key/ecp384/bundle_requester.certchain.der")[..];
        assert!(verify_cert_chain_x509(bundle_certs_der, None, None).is_ok());

        let bundle_certs_der =
            &include_bytes!("../../../../test_key/crypto_chains/bundle_cert.der")[..];
        assert!(verify_cert_chain_x509(bundle_certs_der, None, None).is_ok());

        // Flipping bits to test signature hash is invalid.
        let mut cert_chain = bundle_certs_der.to_vec();
        // offset 3140 is in signature range.
        cert_chain[3140] ^= 0xFE;
        assert!(verify_cert_chain_x509(&cert_chain, None, None).is_err());

        // Invalid Intermediate cert
        let mut cert_chain = bundle_certs_der.to_vec();
        // Change intermediate cert data
        cert_chain[1380] = 0xFF;
        assert!(verify_cert_chain_x509(&cert_chain, None, None).is_err());
    }

    #[test]
    fn test_certificate_eku_v3_end_with_eku_example_1() {
        let cert_der = &include_bytes!("../../../../test_key/test_spdm_eku/example/cert1.der")[..];
        assert!(verify_cert_chain_x509(cert_der, None, None).is_ok());
    }

    #[test]
    fn test_certificate_eku_v3_end_with_eku_spdm_oid_3() {
        let cert_der = &include_bytes!(
            "../../../../test_key/test_spdm_eku/gen/v3_end_with_eku_spdm_oid_3/cert.der"
        )[..];
        assert!(verify_cert_chain_x509(cert_der, None, None).is_ok());
    }

    #[test]
    fn test_certificate_eku_v3_end_with_eku_spdm_oid_4() {
        let cert_der = &include_bytes!(
            "../../../../test_key/test_spdm_eku/gen/v3_end_with_eku_spdm_oid_4/cert.der"
        )[..];
        assert!(verify_cert_chain_x509(cert_der, None, None).is_err());
    }

    #[test]
    fn test_certificate_eku_v3_end_with_eku_spdm_oid_3_and_4() {
        let cert_der = &include_bytes!(
            "../../../../test_key/test_spdm_eku/gen/v3_end_with_eku_spdm_oid_3_and_4/cert.der"
        )[..];
        assert!(verify_cert_chain_x509(cert_der, None, None).is_ok());
    }

    #[test]
    fn test_certificate_eku_v3_end_without_eku() {
        let cert_der = &include_bytes!(
            "../../../../test_key/test_spdm_eku/gen/v3_end_without_eku/cert.der"
        )[..];
        assert!(verify_cert_chain_x509(cert_der, None, None).is_ok());
    }

    #[test]
    fn test_certificate_eku_v3_end_with_eku_spdm_without_spdm_oid() {
        let cert_der = &include_bytes!(
            "../../../../test_key/test_spdm_eku/gen/v3_end_with_eku_spdm_without_spdm_oid/cert.der"
        )[..];
        assert!(verify_cert_chain_x509(cert_der, None, None).is_ok());
    }
}
