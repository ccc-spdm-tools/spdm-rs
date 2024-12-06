// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};

fn ecdhe_secp_p256_self_test() -> SpdmResult {
    Ok(())
}

fn ecdhe_secp_p384_self_test() -> SpdmResult {
    Ok(())
}

pub fn run_self_tests() -> SpdmResult {
    match ecdhe_secp_p256_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    match ecdhe_secp_p384_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    Ok(())
}
