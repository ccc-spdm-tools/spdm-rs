// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::pqc_asym_verify;
use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};
use crate::protocol::SpdmPqcAsymAlgo;

pub fn run_self_tests(configured: SpdmPqcAsymAlgo) -> SpdmResult<bool> {
    let mut tested = false;

    if configured.contains(SpdmPqcAsymAlgo::ALG_MLDSA_87) {
        tested = true;
        let Some(result) = pqc_asym_verify::run_fips_self_test() else {
            return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
        };

        result?;
    }

    Ok(tested)
}
