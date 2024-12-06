// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

use super::*;

use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};

fn ecdsa_ecc_nist_p256_self_test() -> SpdmResult {
    Ok(())
}

fn ecdsa_ecc_nist_p384_self_test() -> SpdmResult {
    Ok(())
}

fn rsassa_3072_self_test() -> SpdmResult {
    Ok(())
}

pub fn run_self_tests() -> SpdmResult {
    match ecdsa_ecc_nist_p256_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    match ecdsa_ecc_nist_p384_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    match rsassa_3072_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    Ok(())
}
