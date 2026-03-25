// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::unstable::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use spdmlib::crypto::SpdmPqcAsymVerify;
use spdmlib::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmPqcAsymAlgo, SpdmSignatureStruct};

// Raw public key sizes for ML-DSA variants (without SPKI DER header)
const MLDSA_44_KEY_SIZE: usize = 1312;
const MLDSA_65_KEY_SIZE: usize = 1952;
const MLDSA_87_KEY_SIZE: usize = 2592;

pub static DEFAULT: SpdmPqcAsymVerify = SpdmPqcAsymVerify {
    verify_cb: pqc_asym_verify,
};

/// Extract the raw public key from a SubjectPublicKeyInfo (SPKI) DER encoding.
/// If the input is already the expected raw key size, return it as-is.
fn extract_raw_public_key(public_key_der: &[u8], expected_raw_size: usize) -> &[u8] {
    if public_key_der.len() == expected_raw_size {
        return public_key_der;
    }
    // SPKI DER: SEQUENCE { SEQUENCE { OID, ... }, BIT STRING { 0x00, raw_key } }
    // The raw key is at the end; strip the SPKI header.
    if public_key_der.len() > expected_raw_size {
        &public_key_der[public_key_der.len() - expected_raw_size..]
    } else {
        public_key_der
    }
}

fn pqc_asym_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    pqc_asym_algo: SpdmPqcAsymAlgo,
    public_key_der: &[u8],
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    let sig_bytes = &signature.data[..signature.data_size as usize];

    let result = match pqc_asym_algo {
        SpdmPqcAsymAlgo::ALG_MLDSA_44 => {
            let raw_key = extract_raw_public_key(public_key_der, MLDSA_44_KEY_SIZE);
            let public_key = UnparsedPublicKey::new(&ML_DSA_44, raw_key);
            public_key.verify(data, sig_bytes)
        }
        SpdmPqcAsymAlgo::ALG_MLDSA_65 => {
            let raw_key = extract_raw_public_key(public_key_der, MLDSA_65_KEY_SIZE);
            let public_key = UnparsedPublicKey::new(&ML_DSA_65, raw_key);
            public_key.verify(data, sig_bytes)
        }
        SpdmPqcAsymAlgo::ALG_MLDSA_87 => {
            let raw_key = extract_raw_public_key(public_key_der, MLDSA_87_KEY_SIZE);
            let public_key = UnparsedPublicKey::new(&ML_DSA_87, raw_key);
            public_key.verify(data, sig_bytes)
        }
        _ => return Err(SPDM_STATUS_VERIF_FAIL),
    };

    result.map_err(|_| SPDM_STATUS_VERIF_FAIL)
}
