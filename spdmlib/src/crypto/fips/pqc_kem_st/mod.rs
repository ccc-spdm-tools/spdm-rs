// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::kem_decap;
use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};
use crate::protocol::SpdmKemAlgo;

pub fn run_self_tests(configured: SpdmKemAlgo) -> SpdmResult<bool> {
    if !configured.contains(SpdmKemAlgo::ALG_MLKEM_1024) {
        return Ok(false);
    }

    let Some(result) = kem_decap::run_fips_self_test() else {
        return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
    };

    result?;
    Ok(true)
}
