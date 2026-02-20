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
mod hmac_st;

use crate::error::SpdmResult;

/// Drop guard that restores the previous log level on scope exit,
/// even if an early return (e.g. `?`) occurs.
struct LogLevelGuard(log::LevelFilter);

impl Drop for LogLevelGuard {
    fn drop(&mut self) {
        log::set_max_level(self.0);
    }
}

pub fn run_self_tests() -> SpdmResult {
    // Temporarily suppress logging during self-tests.
    // The CAVS negative vectors intentionally trigger verification failures
    // that produce error!() messages — those are expected
    // and not indicative of a real problem.
    let _guard = LogLevelGuard(log::max_level());
    log::set_max_level(log::LevelFilter::Off);

    aead_st::run_self_tests()?;
    asym_verify_st::run_self_tests()?;
    dhe_st::run_self_tests()?;
    hash_st::run_self_tests()?;
    hmac_st::run_self_tests()?;

    Ok(())
}
