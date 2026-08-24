// Copyright (c) 2023, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Certificate-chain operations for the mbedtls backend.
//!
//! These delegate to the spdm_x509 library rather than the mbedtls C X.509
//! verifier. spdm_x509 ships no built-in backend, so this module supplies its
//! own `MbedtlsBackend`: classical (RSA/ECC) certificate signatures are verified
//! by mbedtls and no ring is linked. spdm_x509 parses the chain itself and
//! dispatches classical signatures to this backend and post-quantum (ML-DSA /
//! FIPS 204) signatures to the registered PQC verifier hook — mbedtls cannot
//! verify ML-DSA, so delegating here is what lets PQC certificate chains work
//! with the mbedtls backend.
//!
//! `Validator::verify_signature` hands this backend the *raw* subjectPublicKey
//! BIT STRING content of the issuer (an EC point for ECDSA, a PKCS#1
//! `RSAPublicKey` for RSA), whereas mbedtls' `Pk::from_public_key` parses a full
//! DER-encoded `SubjectPublicKeyInfo`. We therefore wrap the raw key back into a
//! `SubjectPublicKeyInfo` (using the algorithm implied by the negotiated
//! [`SignatureAlgorithm`]) before handing it to mbedtls.

extern crate alloc;

use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use der::asn1::BitString;
use der::{Any, Encode};
use mbedtls::hash::Type as MdType;
use mbedtls::pk::{Options, Pk, RsaPadding};
use spdm_x509::crypto_backend::{CryptoBackend, SignatureAlgorithm};
use spdm_x509::error::{Error, Result};
use spdmlib::crypto::SpdmCertOperation;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

// Public-key algorithm OIDs (RFC 5480 / RFC 8017).
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
// Named-curve OIDs, used as the AlgorithmIdentifier parameters for EC keys.
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// mbedtls-based cryptographic backend.
#[derive(Clone, Copy)]
pub struct MbedtlsBackend;

impl CryptoBackend for MbedtlsBackend {
    fn verify_signature(
        &self,
        algorithm: SignatureAlgorithm,
        tbs_data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<()> {
        log::trace!("Verifying signature with algorithm {:?}", algorithm);

        let md = md_type(algorithm)?;

        // Rebuild a SubjectPublicKeyInfo DER around the raw public key so
        // mbedtls can parse it.
        let spki_der = build_spki_der(algorithm, public_key)?;
        let mut pk = Pk::from_public_key(&spki_der).map_err(|_| {
            Error::unsupported_algorithm("mbedtls could not parse the issuer public key")
        })?;

        // RSA-PSS must be verified with PSS padding (mbedtls defaults an RSA key
        // to PKCS#1 v1.5).  The MGF-1 hash matches the message-digest hash for
        // all PSS variants SPDM uses.
        if is_rsa_pss(algorithm) {
            pk.set_options(Options::Rsa {
                padding: RsaPadding::Pkcs1V21 { mgf: md },
            });
        }

        // mbedtls' pk_verify takes the message digest, not the message.
        let digest = digest(md, tbs_data)?;

        pk.verify(md, &digest, signature).map_err(|_| {
            log::error!("Signature verification failed");
            Error::SignatureError(spdm_x509::error::SignatureError::VerificationFailed)
        })?;

        log::trace!("Signature verification successful");
        Ok(())
    }
}

/// Map a [`SignatureAlgorithm`] to the mbedtls message-digest type.
fn md_type(algorithm: SignatureAlgorithm) -> Result<MdType> {
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256
        | SignatureAlgorithm::EcdsaP384Sha256
        | SignatureAlgorithm::RsaPkcs1Sha256
        | SignatureAlgorithm::RsaPssSha256 => Ok(MdType::Sha256),
        SignatureAlgorithm::EcdsaP256Sha384
        | SignatureAlgorithm::EcdsaP384Sha384
        | SignatureAlgorithm::RsaPkcs1Sha384
        | SignatureAlgorithm::RsaPssSha384 => Ok(MdType::Sha384),
        SignatureAlgorithm::RsaPkcs1Sha512 | SignatureAlgorithm::RsaPssSha512 => Ok(MdType::Sha512),
        SignatureAlgorithm::Ed25519 => Err(Error::unsupported_algorithm(
            "Ed25519 is not supported by the mbedtls backend",
        )),
        SignatureAlgorithm::MlDsa44 | SignatureAlgorithm::MlDsa65 | SignatureAlgorithm::MlDsa87 => {
            Err(Error::unsupported_algorithm(
                "ML-DSA is not supported by the mbedtls backend",
            ))
        }
    }
}

/// Whether the algorithm is one of the RSA-PSS variants.
fn is_rsa_pss(algorithm: SignatureAlgorithm) -> bool {
    matches!(
        algorithm,
        SignatureAlgorithm::RsaPssSha256
            | SignatureAlgorithm::RsaPssSha384
            | SignatureAlgorithm::RsaPssSha512
    )
}

/// Compute a one-shot digest of `data` with the given mbedtls hash type.
fn digest(md: MdType, data: &[u8]) -> Result<Vec<u8>> {
    // SHA-512 output (64 bytes) is the largest we use.
    let mut out = [0u8; 64];
    let len = mbedtls::hash::Md::hash(md, data, &mut out)
        .map_err(|_| Error::unsupported_algorithm("mbedtls digest failed"))?;
    Ok(out[..len].to_vec())
}

/// Wrap a raw subjectPublicKey BIT STRING back into a DER `SubjectPublicKeyInfo`
/// so mbedtls' `Pk::from_public_key` can parse it.
fn build_spki_der(algorithm: SignatureAlgorithm, raw_public_key: &[u8]) -> Result<Vec<u8>> {
    let (oid, parameters) =
        match algorithm {
            // RSA keys carry ASN.1 NULL parameters.
            SignatureAlgorithm::RsaPkcs1Sha256
            | SignatureAlgorithm::RsaPkcs1Sha384
            | SignatureAlgorithm::RsaPkcs1Sha512
            | SignatureAlgorithm::RsaPssSha256
            | SignatureAlgorithm::RsaPssSha384
            | SignatureAlgorithm::RsaPssSha512 => (RSA_ENCRYPTION, Some(Any::null())),
            // ECDSA keys carry the named-curve OID as parameters.
            SignatureAlgorithm::EcdsaP256Sha256 | SignatureAlgorithm::EcdsaP256Sha384 => (
                EC_PUBLIC_KEY,
                Some(Any::encode_from(&SECP256R1).map_err(|_| {
                    Error::unsupported_algorithm("failed to encode P-256 curve OID")
                })?),
            ),
            SignatureAlgorithm::EcdsaP384Sha256 | SignatureAlgorithm::EcdsaP384Sha384 => (
                EC_PUBLIC_KEY,
                Some(Any::encode_from(&SECP384R1).map_err(|_| {
                    Error::unsupported_algorithm("failed to encode P-384 curve OID")
                })?),
            ),
            SignatureAlgorithm::Ed25519
            | SignatureAlgorithm::MlDsa44
            | SignatureAlgorithm::MlDsa65
            | SignatureAlgorithm::MlDsa87 => {
                return Err(Error::unsupported_algorithm(
                    "unsupported public-key algorithm for the mbedtls backend",
                ));
            }
        };

    let subject_public_key = BitString::from_bytes(raw_public_key)
        .map_err(|_| Error::unsupported_algorithm("invalid subjectPublicKey BIT STRING"))?;

    let spki = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier { oid, parameters },
        subject_public_key,
    };

    spki.to_der()
        .map_err(|_| Error::unsupported_algorithm("failed to encode SubjectPublicKeyInfo"))
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
        MbedtlsBackend,
        base_asym_algo,
        base_hash_algo,
    )
    .map_err(|_| SPDM_STATUS_INVALID_CERT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_cert_chain_rsa3072() {
        let cert_chain =
            &include_bytes!("../../test_key/rsa3072/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain_x509(cert_chain, None, None).is_ok());
    }

    #[test]
    fn test_verify_cert_chain_ecp384() {
        let cert_chain =
            &include_bytes!("../../test_key/ecp384/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain_x509(cert_chain, None, None).is_ok());
    }

    #[test]
    fn test_get_cert_from_cert_chain_leaf() {
        let cert_chain =
            &include_bytes!("../../test_key/ecp384/bundle_responder.certchain.der")[..];
        assert!(get_cert_from_cert_chain_x509(cert_chain, -1).is_ok());
    }

    #[test]
    fn test_mbedtls_backend_creation() {
        let _backend = MbedtlsBackend;
    }
}
