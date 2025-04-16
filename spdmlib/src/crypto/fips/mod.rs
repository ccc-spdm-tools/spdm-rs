// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

use super::*;

mod aead_st;
mod asym_verify_st;
mod cavs_vectors;
mod dhe_st;
mod hash_st;
mod hkdf_st;
mod hmac_st;

#[derive(Debug)]
pub enum SelfTestError {
    SelfTestFailed,
    Unsupported,
}

pub fn run_self_tests() -> Result<(), SelfTestError> {
    // aead
    // TBD

    // asym_verify
    // TBD

    // dhe
    // TBD

    // hash
    match hash_st::run_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // hkdf
    // TBD

    // hmac
    match hmac_st::run_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    Ok(())
}
