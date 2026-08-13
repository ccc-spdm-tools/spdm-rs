// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::kem_decap;
use crate::error::SpdmResult;

pub fn run_self_tests() -> SpdmResult<bool> {
    let Some(result) = kem_decap::run_fips_self_test() else {
        return Ok(false);
    };

    result?;
    Ok(true)
}
