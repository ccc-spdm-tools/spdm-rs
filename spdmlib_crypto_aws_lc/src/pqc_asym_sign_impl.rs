// Copyright (c) 2025, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::ffi::{c_int, c_uchar};
use spdmlib::protocol::{SpdmPqcAsymAlgo, SpdmSignatureStruct, SPDM_MAX_ASYM_SIG_SIZE};

// SPDM signing prefix is 64 bytes, followed by 36 bytes of (zeropad + context_string).
const SPDM_SIGNING_PREFIX_LEN: usize = 64;
const SPDM_SIGNING_CONTEXT_FIELD_LEN: usize = 36;

// ML-DSA signature sizes
const MLDSA_44_SIG_SIZE: usize = 2420;
const MLDSA_65_SIG_SIZE: usize = 3309;
const MLDSA_87_SIG_SIZE: usize = 4627;

// Raw ML-DSA private key sizes (FIPS 204)
const MLDSA_44_PRIVATE_KEY_SIZE: usize = 2560;
const MLDSA_65_PRIVATE_KEY_SIZE: usize = 4032;
const MLDSA_87_PRIVATE_KEY_SIZE: usize = 4896;

// These context-signing functions are not exposed by the safe aws-lc-rs API.
// Their prefixed names are tied to the aws-lc-sys revision pinned in
// external/patches/aws-lc-rs/README.md and must be updated with that pin.
extern "C" {
    #[link_name = "aws_lc_0_43_0_ml_dsa_44_sign"]
    fn ml_dsa_44_sign(
        private_key: *const c_uchar,
        sig: *mut c_uchar,
        sig_len: *mut usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_65_sign"]
    fn ml_dsa_65_sign(
        private_key: *const c_uchar,
        sig: *mut c_uchar,
        sig_len: *mut usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_87_sign"]
    fn ml_dsa_87_sign(
        private_key: *const c_uchar,
        sig: *mut c_uchar,
        sig_len: *mut usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;
}

/// Extract the SPDM signing context string from the data buffer.
fn extract_signing_context(data: &[u8]) -> &[u8] {
    if data.len() < SPDM_SIGNING_PREFIX_LEN + SPDM_SIGNING_CONTEXT_FIELD_LEN {
        return &[];
    }
    let field =
        &data[SPDM_SIGNING_PREFIX_LEN..SPDM_SIGNING_PREFIX_LEN + SPDM_SIGNING_CONTEXT_FIELD_LEN];
    for i in 0..field.len() {
        if field[i] != 0 {
            return &field[i..];
        }
    }
    &[]
}

/// Sign data using ML-DSA with the SPDM signing context string passed as
/// the ML-DSA context parameter (FIPS 204 `ctx`).
///
/// `raw_private_key` is the raw ML-DSA private key bytes (not PKCS#8).
/// `data` is the SPDM signing message (prefix + context + hash).
pub fn pqc_sign_with_context(
    pqc_asym_algo: SpdmPqcAsymAlgo,
    raw_private_key: &[u8],
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    let ctx_string = extract_signing_context(data);
    let ctx_ptr = if ctx_string.is_empty() {
        core::ptr::null()
    } else {
        ctx_string.as_ptr()
    };

    let (sig_size, private_key_size) = match pqc_asym_algo {
        SpdmPqcAsymAlgo::ALG_MLDSA_44 => (MLDSA_44_SIG_SIZE, MLDSA_44_PRIVATE_KEY_SIZE),
        SpdmPqcAsymAlgo::ALG_MLDSA_65 => (MLDSA_65_SIG_SIZE, MLDSA_65_PRIVATE_KEY_SIZE),
        SpdmPqcAsymAlgo::ALG_MLDSA_87 => (MLDSA_87_SIG_SIZE, MLDSA_87_PRIVATE_KEY_SIZE),
        _ => return None,
    };
    // The AWS-LC sign API takes no key length and reads a fixed-size key.
    if raw_private_key.len() != private_key_size {
        return None;
    }

    let sign_fn: unsafe extern "C" fn(_, _, _, _, _, _, _) -> _ = match pqc_asym_algo {
        SpdmPqcAsymAlgo::ALG_MLDSA_44 => ml_dsa_44_sign,
        SpdmPqcAsymAlgo::ALG_MLDSA_65 => ml_dsa_65_sign,
        SpdmPqcAsymAlgo::ALG_MLDSA_87 => ml_dsa_87_sign,
        _ => return None,
    };

    let mut sig_buf = vec![0u8; sig_size];
    let mut sig_len = sig_size;

    let result = unsafe {
        sign_fn(
            raw_private_key.as_ptr(),
            sig_buf.as_mut_ptr(),
            &mut sig_len,
            data.as_ptr(),
            data.len(),
            ctx_ptr,
            ctx_string.len(),
        )
    };

    if result != 1 {
        return None;
    }

    let mut full_signature = [0u8; SPDM_MAX_ASYM_SIG_SIZE];
    full_signature[..sig_len].copy_from_slice(&sig_buf[..sig_len]);

    Some(SpdmSignatureStruct {
        data_size: sig_len as u16,
        data: full_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsRawBytes;
    use aws_lc_rs::unstable::signature::{
        PqdsaKeyPair, PqdsaSigningAlgorithm, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING,
        ML_DSA_87_SIGNING,
    };

    #[test]
    fn test_pqc_sign_rejects_wrong_private_key_size() {
        let cases: [(&'static PqdsaSigningAlgorithm, SpdmPqcAsymAlgo); 3] = [
            (&ML_DSA_44_SIGNING, SpdmPqcAsymAlgo::ALG_MLDSA_44),
            (&ML_DSA_65_SIGNING, SpdmPqcAsymAlgo::ALG_MLDSA_65),
            (&ML_DSA_87_SIGNING, SpdmPqcAsymAlgo::ALG_MLDSA_87),
        ];
        let data = [0u8; 64];
        for (signing_algo, pqc_asym_algo) in cases {
            let key_pair = PqdsaKeyPair::generate(signing_algo).unwrap();
            let raw_private_key = key_pair.private_key().as_raw_bytes().unwrap();
            let raw_private_key = raw_private_key.as_ref();

            assert!(pqc_sign_with_context(pqc_asym_algo, raw_private_key, &data).is_some());
            assert!(pqc_sign_with_context(pqc_asym_algo, &[], &data).is_none());
            assert!(pqc_sign_with_context(
                pqc_asym_algo,
                &raw_private_key[..raw_private_key.len() - 1],
                &data
            )
            .is_none());
            let mut oversized = raw_private_key.to_vec();
            oversized.push(0);
            assert!(pqc_sign_with_context(pqc_asym_algo, &oversized, &data).is_none());
        }
    }
}
