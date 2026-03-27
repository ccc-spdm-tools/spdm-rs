// Copyright (c) 2025 Intel Corporation
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

extern "C" {
    #[link_name = "aws_lc_0_39_0_ml_dsa_44_sign"]
    fn ml_dsa_44_sign(
        private_key: *const c_uchar,
        sig: *mut c_uchar,
        sig_len: *mut usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_39_0_ml_dsa_65_sign"]
    fn ml_dsa_65_sign(
        private_key: *const c_uchar,
        sig: *mut c_uchar,
        sig_len: *mut usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_39_0_ml_dsa_87_sign"]
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

    let sig_size = match pqc_asym_algo {
        SpdmPqcAsymAlgo::ALG_MLDSA_44 => MLDSA_44_SIG_SIZE,
        SpdmPqcAsymAlgo::ALG_MLDSA_65 => MLDSA_65_SIG_SIZE,
        SpdmPqcAsymAlgo::ALG_MLDSA_87 => MLDSA_87_SIG_SIZE,
        _ => return None,
    };

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
