// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

use super::hash;

use crate::protocol::SpdmBaseHashAlgo;

use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};

use crate::crypto::fips::cavs_vectors::sha256_short_msg;
use crate::crypto::fips::cavs_vectors::sha384_short_msg;

pub fn run_self_tests() -> SpdmResult {
    // SHA2-256
    {
        let cavs_vectors = sha256_short_msg::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            let res = hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, cv.msg).unwrap();

            if res.as_ref() != cv.md {
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    // SHA2-384
    {
        let cavs_vectors = sha384_short_msg::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            let res = hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_384, cv.msg).unwrap();

            if res.as_ref() != cv.md {
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    Ok(())
}
