// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::hmac;
use crate::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct, SPDM_MAX_HASH_SIZE};

use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};

use crate::crypto::fips::cavs_vectors::hmac_sha256;
use crate::crypto::fips::cavs_vectors::hmac_sha384;
use crate::crypto::fips::cavs_vectors::hmac_sha512;

pub fn run_self_tests() -> SpdmResult {
    // SHA2-256
    {
        let cavs_vectors = hmac_sha256::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            let mut mac = SpdmDigestStruct {
                data_size: cv.mac.len() as u16,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            let mut vecc = [0u8; SPDM_MAX_HASH_SIZE];
            let copy_len = core::cmp::min(cv.mac.len(), SPDM_MAX_HASH_SIZE);
            vecc[..copy_len].copy_from_slice(&cv.mac[..copy_len]);
            mac.data.copy_from_slice(&vecc);

            if hmac::hmac_verify(SpdmBaseHashAlgo::TPM_ALG_SHA_256, cv.key, cv.msg, &mac).is_err() {
                assert!(false, "Failed to run verify");
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    // SHA2-384
    {
        let cavs_vectors = hmac_sha384::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            let mut mac = SpdmDigestStruct {
                data_size: cv.mac.len() as u16,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            let mut vecc = [0u8; SPDM_MAX_HASH_SIZE];
            let copy_len = core::cmp::min(cv.mac.len(), SPDM_MAX_HASH_SIZE);
            vecc[..copy_len].copy_from_slice(&cv.mac[..copy_len]);
            mac.data.copy_from_slice(&vecc);

            if hmac::hmac_verify(SpdmBaseHashAlgo::TPM_ALG_SHA_384, cv.key, cv.msg, &mac).is_err() {
                assert!(false, "Failed to run verify");
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    // SHA2-512
    {
        let cavs_vectors = hmac_sha512::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            let mut mac = SpdmDigestStruct {
                data_size: cv.mac.len() as u16,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            let mut vecc = [0u8; SPDM_MAX_HASH_SIZE];
            let copy_len = core::cmp::min(cv.mac.len(), SPDM_MAX_HASH_SIZE);
            vecc[..copy_len].copy_from_slice(&cv.mac[..copy_len]);
            mac.data.copy_from_slice(&vecc);

            if hmac::hmac_verify(SpdmBaseHashAlgo::TPM_ALG_SHA_512, cv.key, cv.msg, &mac).is_err() {
                assert!(false, "Failed to run verify");
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    Ok(())
}
