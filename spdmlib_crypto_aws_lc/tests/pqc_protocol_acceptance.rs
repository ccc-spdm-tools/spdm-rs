// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PSS_SHA256};
use der::asn1::{BitString, ContextSpecific, ObjectIdentifier};
use der::{Any, Encode, Tag, TagMode, TagNumber};
use spdm_x509::certificate::Certificate;
use spdm_x509::crypto_backend::SignatureAlgorithm;
use spdm_x509::error::{AlgorithmError, Error, SignatureError};
use spdm_x509::x509::chain::verify_cert_chain_with_backend;
use spdm_x509::x509::oids;
use spdmlib::crypto;
use spdmlib::error::SPDM_STATUS_INVALID_CERT;
use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmPqcAsymAlgo, SpdmPqcReqAsymAlgo};
use spdmlib_crypto_aws_lc::cert_operation_impl::{self, AwsLcBackend};
use spdmlib_crypto_aws_lc::hash_impl;
use std::sync::Once;

fn init_aws_lc_callbacks() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        crypto::hash::register(hash_impl::DEFAULT.clone());
        crypto::cert_operation::register(cert_operation_impl::DEFAULT.clone());
    });
}

const MLDSA44_CHAIN: &[u8] =
    include_bytes!("../../test_key/mldsa44/bundle_responder.certchain.der");
const MLDSA65_CHAIN: &[u8] =
    include_bytes!("../../test_key/mldsa65/bundle_responder.certchain.der");
const MLDSA87_CHAIN: &[u8] =
    include_bytes!("../../test_key/mldsa87/bundle_responder.certchain.der");
const ECP384_CHAIN: &[u8] = include_bytes!("../../test_key/ecp384/bundle_responder.certchain.der");
const RSA2048_CA: &[u8] = include_bytes!("../../test_key/rsa2048/ca.cert.der");

#[test]
fn pqc_mldsa_protocol_acceptance_matrix_both_roles() {
    init_aws_lc_callbacks();

    let cases = [
        (
            "ML-DSA-44",
            MLDSA44_CHAIN,
            SpdmPqcAsymAlgo::ALG_MLDSA_44,
            SpdmPqcReqAsymAlgo::ALG_MLDSA_44,
        ),
        (
            "ML-DSA-65",
            MLDSA65_CHAIN,
            SpdmPqcAsymAlgo::ALG_MLDSA_65,
            SpdmPqcReqAsymAlgo::ALG_MLDSA_65,
        ),
        (
            "ML-DSA-87",
            MLDSA87_CHAIN,
            SpdmPqcAsymAlgo::ALG_MLDSA_87,
            SpdmPqcReqAsymAlgo::ALG_MLDSA_87,
        ),
    ];

    for (name, chain, rsp_pqc, req_pqc) in cases {
        // 1. Matching Responder and Requester PQC selections succeed.
        for (role_label, pqc_algo, is_requester_cert) in [
            ("Responder", rsp_pqc, false),
            ("Requester", req_pqc.to_base(), true),
        ] {
            assert_eq!(
                crypto::cert_operation::verify_cert_chain(
                    chain,
                    SpdmBaseAsymAlgo::empty(),
                    pqc_algo,
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                ),
                Ok(()),
                "{} {} chain must verify",
                name,
                role_label
            );

            let (root_begin, root_end) =
                crypto::cert_operation::get_cert_from_cert_chain(chain, 0).unwrap();
            assert_eq!(
                crypto::is_root_certificate(&chain[root_begin..root_end]),
                Ok(())
            );

            let (leaf_begin, leaf_end) =
                crypto::cert_operation::get_cert_from_cert_chain(chain, -1).unwrap();
            assert_eq!(
                crypto::check_leaf_certificate(
                    &chain[leaf_begin..leaf_end],
                    false,
                    is_requester_cert
                ),
                Ok(()),
                "{} {} leaf check must pass",
                name,
                role_label
            );
        }

        // 2. Cross-parameter-set PQC mismatches must fail in both roles.
        for (_, _, other_rsp, other_req) in cases {
            if other_rsp == rsp_pqc {
                continue;
            }
            for mismatched in [other_rsp, other_req.to_base()] {
                assert_eq!(
                    crypto::cert_operation::verify_cert_chain(
                        chain,
                        SpdmBaseAsymAlgo::empty(),
                        mismatched,
                        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    ),
                    Err(SPDM_STATUS_INVALID_CERT),
                    "{} must fail under mismatched {:?}",
                    name,
                    mismatched
                );
            }
        }

        // 3. Classical chain presented when ML-DSA is negotiated must fail.
        assert_eq!(
            crypto::cert_operation::verify_cert_chain(
                ECP384_CHAIN,
                SpdmBaseAsymAlgo::empty(),
                rsp_pqc,
                SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            ),
            Err(SPDM_STATUS_INVALID_CERT),
            "classical chain must fail when {} is negotiated",
            name
        );

        // 4. ML-DSA chain presented when classical ECDSA is negotiated must fail.
        assert_eq!(
            crypto::cert_operation::verify_cert_chain(
                chain,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                SpdmPqcAsymAlgo::empty(),
                SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            ),
            Err(SPDM_STATUS_INVALID_CERT),
            "{} chain must fail when classical P-384 is negotiated",
            name
        );

        // 5. Corrupting signature at every position (root, intermediate, leaf) must fail.
        for cert_idx in [0isize, 1, 2] {
            let (_begin, end) =
                crypto::cert_operation::get_cert_from_cert_chain(chain, cert_idx).unwrap();
            let mut corrupt = chain.to_vec();
            corrupt[end - 1] ^= 0x01;
            assert_eq!(
                crypto::cert_operation::verify_cert_chain(
                    &corrupt,
                    SpdmBaseAsymAlgo::empty(),
                    rsp_pqc,
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                ),
                Err(SPDM_STATUS_INVALID_CERT),
                "{} must reject corrupted signature at cert index {}",
                name,
                cert_idx
            );
        }
    }
}

fn build_rsa_pss_sha256_params(
    mgf_hash_oid: ObjectIdentifier,
    salt_len: Option<u32>,
    trailer: Option<u32>,
) -> Any {
    const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

    #[derive(der::Sequence)]
    struct AlgId {
        oid: ObjectIdentifier,
        parameters: Option<Any>,
    }

    let mut body = Vec::new();
    let hash_ai = AlgId {
        oid: oids::SHA256,
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

    let mgf_ai = AlgId {
        oid: MGF1,
        parameters: Some(
            Any::encode_from(&AlgId {
                oid: mgf_hash_oid,
                parameters: None,
            })
            .unwrap(),
        ),
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

    Any::new(Tag::Sequence, body).unwrap()
}

#[test]
fn signed_rsa_pss_certificate_and_parameter_validation_with_aws_lc() {
    // Generate an ephemeral RSA-2048 keypair in memory (no committed private keys).
    let priv_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    let pkcs8 = aws_lc_rs::encoding::AsDer::as_der(&priv_key).unwrap();
    let key_pair = RsaKeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_pkcs1 = key_pair.public_key().as_ref();

    // Reuse the structural template from test_key/rsa2048/ca.cert.der, replacing
    // public key and signatureAlgorithm with RSA-PSS-SHA256, then sign with aws-lc.
    let mut cert = Certificate::from_der(RSA2048_CA).unwrap();
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key = BitString::from_bytes(pub_pkcs1).unwrap();

    let pss_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    cert.tbs_certificate.signature.oid = pss_oid;
    cert.tbs_certificate.signature.parameters =
        Some(build_rsa_pss_sha256_params(oids::SHA256, Some(32), None));
    cert.signature_algorithm = cert.tbs_certificate.signature.clone();

    let tbs_der = cert.tbs_certificate.to_der().unwrap();
    let mut sig = vec![0u8; key_pair.public_modulus_len()];
    key_pair
        .sign(&RSA_PSS_SHA256, &SystemRandom::new(), &tbs_der, &mut sig)
        .unwrap();
    cert.signature_value = BitString::from_bytes(&sig).unwrap();

    let signed_der = cert.to_der().unwrap();
    assert!(
        verify_cert_chain_with_backend(&signed_der, AwsLcBackend, None, None).is_ok(),
        "valid signed RSA-PSS-SHA256 self-signed cert must verify"
    );

    // Corrupting the RSA-PSS signature must fail with SignatureError.
    let mut bad_sig_cert = cert.clone();
    let mut bad_sig = sig;
    *bad_sig.last_mut().unwrap() ^= 0x01;
    bad_sig_cert.signature_value = BitString::from_bytes(&bad_sig).unwrap();
    let bad_sig_der = bad_sig_cert.to_der().unwrap();
    assert!(matches!(
        verify_cert_chain_with_backend(&bad_sig_der, AwsLcBackend, None, None),
        Err(Error::SignatureError(SignatureError::VerificationFailed))
    ));

    // Invalid RSA-PSS parameters (mismatched MGF1 hash, wrong saltLength, bad trailerField)
    // must fail with AlgorithmError::InvalidParameters before cryptographic verification.
    for bad_params in [
        build_rsa_pss_sha256_params(oids::SHA384, Some(32), None),
        build_rsa_pss_sha256_params(oids::SHA256, None, None),
        build_rsa_pss_sha256_params(oids::SHA256, Some(20), None),
        build_rsa_pss_sha256_params(oids::SHA256, Some(32), Some(2)),
    ] {
        let mut mutated = cert.clone();
        mutated.tbs_certificate.signature.oid = pss_oid;
        mutated.tbs_certificate.signature.parameters = Some(bad_params);
        mutated.signature_algorithm = mutated.tbs_certificate.signature.clone();
        let mutated_der = mutated.to_der().unwrap();
        assert!(matches!(
            verify_cert_chain_with_backend(&mutated_der, AwsLcBackend, None, None),
            Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
        ));
    }

    // Confirm SignatureAlgorithm::from_oid_with_params also rejects non-absent ML-DSA params.
    let null_param = Any::null();
    for mldsa_oid in [oids::ML_DSA_44, oids::ML_DSA_65, oids::ML_DSA_87] {
        assert!(matches!(
            SignatureAlgorithm::from_oid_with_params(&mldsa_oid, None, Some(&null_param)),
            Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
        ));
    }
}
