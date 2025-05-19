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

use crate::error::SpdmResult;

pub fn run_self_tests() -> SpdmResult {
    aead_st::run_self_tests()?;
    asym_verify_st::run_self_tests()?;
    dhe_st::run_self_tests()?;
    hash_st::run_self_tests()?;

    Ok(())
}
