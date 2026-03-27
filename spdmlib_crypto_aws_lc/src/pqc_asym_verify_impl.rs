// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::ffi::{c_int, c_uchar};
use spdmlib::crypto::SpdmPqcAsymVerify;
use spdmlib::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmPqcAsymAlgo, SpdmSignatureStruct};

// Raw public key sizes for ML-DSA variants (without SPKI DER header)
const MLDSA_44_KEY_SIZE: usize = 1312;
const MLDSA_65_KEY_SIZE: usize = 1952;
const MLDSA_87_KEY_SIZE: usize = 2592;

// SPDM signing prefix is 64 bytes, followed by 36 bytes of (zeropad + context_string).
const SPDM_SIGNING_PREFIX_LEN: usize = 64;
const SPDM_SIGNING_CONTEXT_FIELD_LEN: usize = 36;

extern "C" {
    #[link_name = "aws_lc_0_39_0_ml_dsa_44_verify"]
    fn ml_dsa_44_verify(
        public_key: *const c_uchar,
        sig: *const c_uchar,
        sig_len: usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_39_0_ml_dsa_65_verify"]
    fn ml_dsa_65_verify(
        public_key: *const c_uchar,
        sig: *const c_uchar,
        sig_len: usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_39_0_ml_dsa_87_verify"]
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
    public_key_der: &[u8],
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    let sig_bytes = &signature.data[..signature.data_size as usize];
    let ctx_string = extract_signing_context(data);

    let (raw_key, verify_fn): (&[u8], unsafe extern "C" fn(_, _, _, _, _, _, _) -> _) =
        match pqc_asym_algo {
            SpdmPqcAsymAlgo::ALG_MLDSA_44 => (
                extract_raw_public_key(public_key_der, MLDSA_44_KEY_SIZE),
                ml_dsa_44_verify,
            ),
            SpdmPqcAsymAlgo::ALG_MLDSA_65 => (
                extract_raw_public_key(public_key_der, MLDSA_65_KEY_SIZE),
                ml_dsa_65_verify,
            ),
            SpdmPqcAsymAlgo::ALG_MLDSA_87 => (
                extract_raw_public_key(public_key_der, MLDSA_87_KEY_SIZE),
                ml_dsa_87_verify,
            ),
            _ => return Err(SPDM_STATUS_VERIF_FAIL),
        };

    let ctx_ptr = if ctx_string.is_empty() {
        core::ptr::null()
    } else {
        ctx_string.as_ptr()
    };

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
