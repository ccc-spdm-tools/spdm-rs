// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

use std::{vec, vec::Vec};

use super::hash;
use crate::protocol::SpdmBaseHashAlgo;

use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};

use crate::crypto::fips::cavs_vectors::SHA256ShortMsg;

pub fn run_self_tests() -> SpdmResult {
    let cavs_vectors = SHA256ShortMsg::get_cavs_vectors();
    for cv in cavs_vectors.iter() {
        let mut ctx = hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_256).unwrap();
        hash::hash_ctx_update(&mut ctx, &cv.msg).unwrap();
        let res = hash::hash_ctx_finalize(ctx).unwrap();

        if res.as_ref() != &cv.md {
            return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
        }
    }

    Ok(())
}
