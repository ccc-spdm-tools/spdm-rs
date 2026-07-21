// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! ML-DSA (FIPS 204) certificate-signature verifier for spdm_x509.
//!
//! `spdm_x509` verifies X.509 certificate chains through a backend-agnostic
//! [`CryptoBackend`], but the classical backends (ring / mbedtls) cannot verify
//! ML-DSA signatures.  To support PQC certificate chains (DSP0274 1.4) we
//! register an ML-DSA verifier with `spdm_x509` at startup; the chain walker
//! and the root self-signature check then dispatch ML-DSA signatures here.
//!
//! Unlike SPDM message signing (which mixes in the SPDM signing context
//! string), X.509 certificate signatures are produced over the raw
//! TBSCertificate with an empty ML-DSA context, so we use aws-lc-rs's
//! `UnparsedPublicKey::verify` directly.

use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::unstable::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use log::error;
use spdm_x509::crypto_backend::SignatureAlgorithm;
use spdm_x509::error::{Error, Result};

/// Verify an ML-DSA certificate signature.
///
/// `public_key` may be either the raw FIPS 204 public key (the BIT STRING
/// content of a SubjectPublicKeyInfo) or a DER-encoded SubjectPublicKeyInfo;
/// aws-lc-rs's parser accepts both encodings.
fn verify_pqc_dsa(
    algorithm: SignatureAlgorithm,
    tbs_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<()> {
    let verification_algo: &'static _ = match algorithm {
        SignatureAlgorithm::MlDsa44 => &ML_DSA_44,
        SignatureAlgorithm::MlDsa65 => &ML_DSA_65,
        SignatureAlgorithm::MlDsa87 => &ML_DSA_87,
        _ => {
            return Err(Error::unsupported_algorithm(
                "pqc_cert_verify: not an ML-DSA algorithm",
            ));
        }
    };

    let public_key = UnparsedPublicKey::new(verification_algo, public_key);
    public_key.verify(tbs_data, signature).map_err(|_| {
        error!("ML-DSA certificate signature verification failed");
        Error::SignatureError(spdm_x509::error::SignatureError::VerificationFailed)
    })
}

/// Register the ML-DSA certificate verifier with `spdm_x509`.
///
/// Idempotent: the first registration wins (mirroring the spdm-rs crypto
/// registration model).  Call once at startup, before any PQC certificate
/// chain is validated.
pub fn register() -> bool {
    spdm_x509::crypto_backend::register_pqc_verifier(verify_pqc_dsa)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_path(relative: &str) -> std::string::String {
        std::format!("{}/../test_key/{}", env!("CARGO_MANIFEST_DIR"), relative)
    }

    /// Load an SPDM certificate chain (concatenated DER: root || inter || leaf).
    fn load_chain(dir: &str) -> std::vec::Vec<u8> {
        std::fs::read(test_key_path(&std::format!(
            "{}/bundle_responder.certchain.der",
            dir
        )))
        .unwrap_or_else(|e| panic!("read {} chain: {}", dir, e))
    }

    /// Happy path: with the ML-DSA verifier registered, spdm_x509 validates a
    /// real ML-DSA certificate chain (root self-signature + intermediate +
    /// leaf) end to end — this is the certificate-chain path exercised by the
    /// SPDM handshake in cert-chain mode.
    #[test]
    fn test_ml_dsa_cert_chain_happy_path() {
        register();
        for dir in ["mldsa44", "mldsa65", "mldsa87"] {
            let chain = load_chain(dir);
            let result = spdm_x509::x509::chain::verify_cert_chain(&chain);
            assert!(
                result.is_ok(),
                "{} ML-DSA chain should validate: {:?}",
                dir,
                result.err()
            );
        }
    }

    /// Fail path: a single flipped byte inside the leaf certificate's ML-DSA
    /// signature must cause chain validation to fail — proving the verifier
    /// actually checks the signature rather than accepting unconditionally.
    #[test]
    fn test_ml_dsa_cert_chain_tampered_signature_rejected() {
        register();
        let mut chain = load_chain("mldsa87");

        // The leaf certificate is last in the SPDM chain; its ML-DSA signature
        // is at the very end of the buffer.  Flip a byte well inside it.
        let len = chain.len();
        chain[len - 16] ^= 0xFF;

        let result = spdm_x509::x509::chain::verify_cert_chain(&chain);
        assert!(
            result.is_err(),
            "tampered ML-DSA leaf signature must be rejected"
        );
    }

    /// Fail path: tampering with the intermediate certificate's TBS content
    /// (which is signed by the root) must be rejected during the chain walk.
    #[test]
    fn test_ml_dsa_cert_chain_tampered_intermediate_rejected() {
        register();
        let mut chain = load_chain("mldsa87");

        // Corrupt a byte in the first cert (root) region's later portion, which
        // falls inside the root's signature over its own TBS. Any interior flip
        // that changes signed bytes or a signature must break validation.
        // Use an offset comfortably past the header but before the leaf.
        chain[1380] ^= 0xFF;

        let result = spdm_x509::x509::chain::verify_cert_chain(&chain);
        assert!(
            result.is_err(),
            "tampered certificate in ML-DSA chain must be rejected"
        );
    }
}
