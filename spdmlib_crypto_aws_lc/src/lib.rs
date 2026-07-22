// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! spdm-rs crypto backend using aws-lc-rs.
//!
//! Historically this crate supplied only the post-quantum primitives (ML-KEM,
//! ML-DSA) as an overlay on the ring/mbedtls classical backends. It now also
//! provides the traditional primitives (hash, HMAC, AEAD, ECDHE, RSA/ECDSA
//! verify, HKDF, rand, certificate-chain verification), so aws-lc-rs can be
//! used as a **standalone** backend for both traditional and PQC crypto on
//! std targets (no ring, no mbedtls). See `register_crypto_callbacks` in the
//! emulator layer.

// PQC (post-quantum) primitives.
pub mod kem_impl;
pub mod pqc_asym_sign_impl;
pub mod pqc_asym_verify_impl;
pub mod pqc_cert_verify_impl;

// Traditional primitives (standalone aws-lc backend).
pub mod aead_impl;
pub mod asym_verify_impl;
pub mod cert_operation_impl;
pub mod dhe_impl;
pub mod hash_impl;
pub mod hkdf_impl;
pub mod hmac_impl;
pub mod rand_impl;

#[cfg(test)]
mod tests {
    use super::*;
    use spdmlib::protocol::SpdmKemAlgo;

    #[test]
    fn test_kem_512_roundtrip() {
        kem_roundtrip(SpdmKemAlgo::ALG_MLKEM_512);
    }

    #[test]
    fn test_kem_768_roundtrip() {
        kem_roundtrip(SpdmKemAlgo::ALG_MLKEM_768);
    }

    #[test]
    fn test_kem_1024_roundtrip() {
        kem_roundtrip(SpdmKemAlgo::ALG_MLKEM_1024);
    }

    fn kem_roundtrip(algo: SpdmKemAlgo) {
        // Generate key pair (responder side)
        let (encap_key_struct, decap_exchange) =
            (kem_impl::DEFAULT_DECAP.generate_key_pair_cb)(algo).expect("generate_key_pair failed");

        // Encapsulate (requester side)
        let encap_exchange =
            (kem_impl::DEFAULT_ENCAP.new_key_cb)(algo, &encap_key_struct).expect("new_key failed");
        let (cipher_text, shared_secret_enc) =
            encap_exchange.encap_key().expect("encap_key failed");

        // Decapsulate (responder side)
        let shared_secret_dec = decap_exchange
            .decap_key(&cipher_text)
            .expect("decap_key failed");

        // Shared secrets must match
        assert_eq!(shared_secret_enc.data_size, shared_secret_dec.data_size);
        assert_eq!(
            &shared_secret_enc.data[..shared_secret_enc.data_size as usize],
            &shared_secret_dec.data[..shared_secret_dec.data_size as usize],
        );
    }

    #[test]
    fn test_mldsa_44_sign_verify() {
        mldsa_sign_verify_roundtrip(
            &aws_lc_rs::unstable::signature::ML_DSA_44_SIGNING,
            spdmlib::protocol::SpdmPqcAsymAlgo::ALG_MLDSA_44,
        );
    }

    #[test]
    fn test_mldsa_65_sign_verify() {
        mldsa_sign_verify_roundtrip(
            &aws_lc_rs::unstable::signature::ML_DSA_65_SIGNING,
            spdmlib::protocol::SpdmPqcAsymAlgo::ALG_MLDSA_65,
        );
    }

    #[test]
    fn test_mldsa_87_sign_verify() {
        mldsa_sign_verify_roundtrip(
            &aws_lc_rs::unstable::signature::ML_DSA_87_SIGNING,
            spdmlib::protocol::SpdmPqcAsymAlgo::ALG_MLDSA_87,
        );
    }

    fn mldsa_sign_verify_roundtrip(
        signing_algo: &'static aws_lc_rs::unstable::signature::PqdsaSigningAlgorithm,
        pqc_algo: spdmlib::protocol::SpdmPqcAsymAlgo,
    ) {
        use aws_lc_rs::signature::KeyPair;
        use aws_lc_rs::unstable::signature::PqdsaKeyPair;
        use spdmlib::protocol::SpdmSignatureStruct;

        // Generate a signing key pair
        let key_pair = PqdsaKeyPair::generate(signing_algo).expect("keygen failed");
        let pub_key_bytes = key_pair.public_key().as_ref().to_vec();

        // Sign a message
        let message = b"SPDM PQC test message for ML-DSA";
        let sig_len = signing_algo.signature_len();
        let mut sig_buf = vec![0u8; sig_len];
        let written = key_pair.sign(message, &mut sig_buf).expect("sign failed");

        // Build SpdmSignatureStruct
        let mut sig_struct = SpdmSignatureStruct {
            data_size: written as u16,
            ..SpdmSignatureStruct::default()
        };
        sig_struct.data[..written].copy_from_slice(&sig_buf[..written]);

        // Verify using our callback
        let result = (pqc_asym_verify_impl::DEFAULT.verify_cb)(
            spdmlib::protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            pqc_algo,
            &pub_key_bytes,
            message,
            &sig_struct,
        );
        assert!(
            result.is_ok(),
            "{:?} verification failed: {:?}",
            pqc_algo,
            result
        );

        // Verify with wrong message should fail
        let wrong_msg = b"wrong message";
        let result_bad = (pqc_asym_verify_impl::DEFAULT.verify_cb)(
            spdmlib::protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            pqc_algo,
            &pub_key_bytes,
            wrong_msg,
            &sig_struct,
        );
        assert!(
            result_bad.is_err(),
            "Verification should fail with wrong message"
        );
    }
}
