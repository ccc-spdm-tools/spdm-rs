// Copyright (c) 2025, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use alloc::vec::Vec;
use core::ffi::{c_int, c_uchar};
use der::Decode;
use log::error;
use spdm_x509::certificate::SubjectPublicKeyInfo;
use spdm_x509::x509::oids;
use spdmlib::crypto::SpdmPqcAsymVerify;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDer, SpdmPqcAsymAlgo, SpdmSignatureStruct};

// Raw public key sizes for ML-DSA variants (without SPKI DER header)
const MLDSA_44_KEY_SIZE: usize = 1312;
const MLDSA_65_KEY_SIZE: usize = 1952;
const MLDSA_87_KEY_SIZE: usize = 2592;

// SPDM signing prefix is 64 bytes, followed by 36 bytes of (zeropad + context_string).
const SPDM_SIGNING_PREFIX_LEN: usize = 64;
const SPDM_SIGNING_CONTEXT_FIELD_LEN: usize = 36;

// These context-verification functions are not exposed by the safe aws-lc-rs
// API. Their prefixed names are tied to the aws-lc-sys revision pinned in
// external/patches/aws-lc-rs/README.md and must be updated with that pin.
extern "C" {
    #[link_name = "aws_lc_0_43_0_ml_dsa_44_verify"]
    fn ml_dsa_44_verify(
        public_key: *const c_uchar,
        sig: *const c_uchar,
        sig_len: usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_65_verify"]
    fn ml_dsa_65_verify(
        public_key: *const c_uchar,
        sig: *const c_uchar,
        sig_len: usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_87_verify"]
    fn ml_dsa_87_verify(
        public_key: *const c_uchar,
        sig: *const c_uchar,
        sig_len: usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;
}

pub static DEFAULT: SpdmPqcAsymVerify = SpdmPqcAsymVerify {
    verify_cb: pqc_asym_verify,
    #[cfg(feature = "fips")]
    fips_self_test_cb: Some(crate::fips_cavp_impl::ml_dsa_87_cavp),
    #[cfg(not(feature = "fips"))]
    fips_self_test_cb: None,
};

/// Extract the raw ML-DSA public key from a DER-encoded certificate chain.
///
/// The certificate key must match the negotiated algorithm exactly.
fn extract_public_key_from_cert_chain(
    public_cert_der: &[u8],
    pqc_asym_algo: SpdmPqcAsymAlgo,
) -> Result<Vec<u8>, spdmlib::error::SpdmStatus> {
    // Use spdm_x509 to get the leaf certificate (index -1 = last cert)
    let (leaf_begin, leaf_end) =
        spdm_x509::x509::chain::get_cert_from_cert_chain(public_cert_der, -1).map_err(|e| {
            error!("Failed to get leaf cert from chain: {:?}", e);
            SPDM_STATUS_INVALID_CERT
        })?;

    let leaf_cert_der = &public_cert_der[leaf_begin..leaf_end];

    // Parse the certificate to extract SubjectPublicKeyInfo
    let cert = spdm_x509::Certificate::from_der(leaf_cert_der).map_err(|e| {
        error!("Failed to parse leaf certificate: {:?}", e);
        SPDM_STATUS_INVALID_CERT
    })?;

    extract_public_key_from_spki(&cert.tbs_certificate.subject_public_key_info, pqc_asym_algo)
}

fn extract_public_key_from_spki(
    spki: &SubjectPublicKeyInfo,
    pqc_asym_algo: SpdmPqcAsymAlgo,
) -> SpdmResult<Vec<u8>> {
    let (expected_oid, expected_raw_size) = match pqc_asym_algo {
        SpdmPqcAsymAlgo::ALG_MLDSA_44 => (oids::ML_DSA_44, MLDSA_44_KEY_SIZE),
        SpdmPqcAsymAlgo::ALG_MLDSA_65 => (oids::ML_DSA_65, MLDSA_65_KEY_SIZE),
        SpdmPqcAsymAlgo::ALG_MLDSA_87 => (oids::ML_DSA_87, MLDSA_87_KEY_SIZE),
        _ => return Err(SPDM_STATUS_VERIF_FAIL),
    };
    let public_key = spki.subject_public_key.raw_bytes();
    if spki.algorithm.oid != expected_oid
        || spki.algorithm.parameters.is_some()
        || spki.subject_public_key.unused_bits() != 0
        || public_key.len() != expected_raw_size
    {
        error!(
            "Invalid ML-DSA public key: algorithm {}, size {}, expected {}",
            spki.algorithm.oid,
            public_key.len(),
            expected_raw_size
        );
        return Err(SPDM_STATUS_INVALID_CERT);
    }
    Ok(public_key.to_vec())
}

fn extract_public_key(der: SpdmDer, pqc_asym_algo: SpdmPqcAsymAlgo) -> SpdmResult<Vec<u8>> {
    match der {
        SpdmDer::SpdmDerCertChain(chain) => {
            extract_public_key_from_cert_chain(chain, pqc_asym_algo)
        }
        SpdmDer::SpdmDerPubKeyRfc7250(public_key_der) => {
            let spki = SubjectPublicKeyInfo::from_der(public_key_der).map_err(|e| {
                error!("Failed to parse ML-DSA SubjectPublicKeyInfo: {:?}", e);
                SPDM_STATUS_INVALID_CERT
            })?;
            extract_public_key_from_spki(&spki, pqc_asym_algo)
        }
    }
}

/// Extract the SPDM signing context string from the data buffer.
///
/// The SPDM 1.2+ signing message has the following structure:
///   [0..64)   : signing prefix ("dmtf-spdm-v1.x.*" repeated 4 times)
///   [64..100) : zero-padding + signing context string (36 bytes total)
///   [100..)   : hash
///
/// The signing context string is at the end of the 36-byte field (after
/// zero-padding). Per SPDM spec, this context string is also used as the
/// ML-DSA context parameter (ctx) in FIPS 204 sign/verify operations.
fn extract_signing_context(data: &[u8]) -> &[u8] {
    if data.len() < SPDM_SIGNING_PREFIX_LEN + SPDM_SIGNING_CONTEXT_FIELD_LEN {
        return &[];
    }
    let field =
        &data[SPDM_SIGNING_PREFIX_LEN..SPDM_SIGNING_PREFIX_LEN + SPDM_SIGNING_CONTEXT_FIELD_LEN];
    // The context string follows zero-padding. Find the first non-zero byte.
    for i in 0..field.len() {
        if field[i] != 0 {
            return &field[i..];
        }
    }
    &[]
}

fn pqc_asym_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    pqc_asym_algo: SpdmPqcAsymAlgo,
    der: SpdmDer,
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    let verify_fn: unsafe extern "C" fn(_, _, _, _, _, _, _) -> _ = match pqc_asym_algo {
        SpdmPqcAsymAlgo::ALG_MLDSA_44 => ml_dsa_44_verify,
        SpdmPqcAsymAlgo::ALG_MLDSA_65 => ml_dsa_65_verify,
        SpdmPqcAsymAlgo::ALG_MLDSA_87 => ml_dsa_87_verify,
        _ => return Err(SPDM_STATUS_VERIF_FAIL),
    };
    if signature.data_size != pqc_asym_algo.get_sig_size() {
        return Err(SPDM_STATUS_VERIF_FAIL);
    }
    let sig_bytes = signature
        .data
        .get(..signature.data_size as usize)
        .ok_or(SPDM_STATUS_VERIF_FAIL)?;
    let ctx_string = extract_signing_context(data);

    let raw_key = extract_public_key(der, pqc_asym_algo)?;

    let ctx_ptr = if ctx_string.is_empty() {
        core::ptr::null()
    } else {
        ctx_string.as_ptr()
    };

    // SAFETY: extraction checks the ML-DSA OID and exact fixed public-key size;
    // signature bounds are checked above and all slices remain live for the call.
    let result = unsafe {
        verify_fn(
            raw_key.as_ptr(),
            sig_bytes.as_ptr(),
            sig_bytes.len(),
            data.as_ptr(),
            data.len(),
            ctx_ptr,
            ctx_string.len(),
        )
    };

    if result == 1 {
        Ok(())
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use der::{asn1::BitString, Encode};

    fn leaf() -> spdm_x509::Certificate {
        spdm_x509::Certificate::from_der(include_bytes!(
            "../../test_key/mldsa87/end_responder.cert.der"
        ))
        .unwrap()
    }

    fn verify(der: SpdmDer, algo: SpdmPqcAsymAlgo) -> SpdmResult {
        let signature = SpdmSignatureStruct {
            data_size: algo.get_sig_size(),
            ..Default::default()
        };
        pqc_asym_verify(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            algo,
            der,
            b"test",
            &signature,
        )
    }

    #[test]
    fn rejects_classical_certificate_chains() {
        for chain in [
            &include_bytes!("../../test_key/ecp256/bundle_responder.certchain.der")[..],
            &include_bytes!("../../test_key/rsa3072/bundle_responder.certchain.der")[..],
        ] {
            assert_eq!(
                verify(
                    SpdmDer::SpdmDerCertChain(chain),
                    SpdmPqcAsymAlgo::ALG_MLDSA_87
                ),
                Err(SPDM_STATUS_INVALID_CERT)
            );
        }
    }

    #[test]
    fn rejects_unstructured_keys_and_malformed_chains() {
        for size in [
            0,
            1,
            MLDSA_87_KEY_SIZE - 1,
            MLDSA_87_KEY_SIZE,
            MLDSA_87_KEY_SIZE + 1,
        ] {
            let input = vec![0; size];
            for der in [
                SpdmDer::SpdmDerCertChain(&input),
                SpdmDer::SpdmDerPubKeyRfc7250(&input),
            ] {
                assert_eq!(
                    verify(der, SpdmPqcAsymAlgo::ALG_MLDSA_87),
                    Err(SPDM_STATUS_INVALID_CERT)
                );
            }
        }
    }

    #[test]
    fn checks_exact_key_size_for_each_mldsa_variant() {
        for (algo, oid, size) in [
            (
                SpdmPqcAsymAlgo::ALG_MLDSA_44,
                oids::ML_DSA_44,
                MLDSA_44_KEY_SIZE,
            ),
            (
                SpdmPqcAsymAlgo::ALG_MLDSA_65,
                oids::ML_DSA_65,
                MLDSA_65_KEY_SIZE,
            ),
            (
                SpdmPqcAsymAlgo::ALG_MLDSA_87,
                oids::ML_DSA_87,
                MLDSA_87_KEY_SIZE,
            ),
        ] {
            for actual_size in [size - 1, size, size + 1] {
                let mut cert = leaf();
                let spki = &mut cert.tbs_certificate.subject_public_key_info;
                spki.algorithm.oid = oid;
                spki.subject_public_key = BitString::from_bytes(&vec![0; actual_size]).unwrap();
                let spki_der = spki.to_der().unwrap();
                let cert_der = cert.to_der().unwrap();
                for der in [
                    SpdmDer::SpdmDerPubKeyRfc7250(&spki_der),
                    SpdmDer::SpdmDerCertChain(&cert_der),
                ] {
                    let result = extract_public_key(der, algo);
                    if actual_size == size {
                        assert_eq!(result.unwrap().len(), size);
                    } else {
                        assert_eq!(result, Err(SPDM_STATUS_INVALID_CERT));
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_wrong_oid_even_with_correct_key_size() {
        let mut cert = leaf();
        cert.tbs_certificate.subject_public_key_info.algorithm.oid = oids::ML_DSA_65;
        assert_eq!(
            verify(
                SpdmDer::SpdmDerCertChain(&cert.to_der().unwrap()),
                SpdmPqcAsymAlgo::ALG_MLDSA_87
            ),
            Err(SPDM_STATUS_INVALID_CERT)
        );
    }

    #[test]
    fn rejects_non_byte_aligned_key() {
        let mut cert = leaf();
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::new(1, vec![0; MLDSA_87_KEY_SIZE]).unwrap();
        assert_eq!(
            verify(
                SpdmDer::SpdmDerCertChain(&cert.to_der().unwrap()),
                SpdmPqcAsymAlgo::ALG_MLDSA_87
            ),
            Err(SPDM_STATUS_INVALID_CERT)
        );
    }

    #[test]
    fn rejects_invalid_signature_size_without_panicking() {
        let signature = SpdmSignatureStruct {
            data_size: u16::MAX,
            ..Default::default()
        };
        assert_eq!(
            pqc_asym_verify(
                SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                SpdmPqcAsymAlgo::ALG_MLDSA_87,
                SpdmDer::SpdmDerCertChain(&[]),
                b"test",
                &signature,
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }
}
