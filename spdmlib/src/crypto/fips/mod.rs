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

fn run_silenced<T>(test: impl FnOnce() -> SpdmResult<T>) -> SpdmResult<T> {
    let _guard = LogLevelGuard(log::max_level());
    log::set_max_level(log::LevelFilter::Off);
    test()
}

pub fn run_self_tests() -> SpdmResult {
    {
        run_silenced(aead_st::run_self_tests)?;
        log::info!("AES-256-GCM FIPS CAVP passed");
    }
    {
        run_silenced(asym_verify_st::run_self_tests)?;
        log::info!("Asymmetric verification FIPS CAVP passed");
    }
    {
        run_silenced(dhe_st::run_self_tests)?;
        log::info!("DHE FIPS CAVP passed");
    }
    {
        run_silenced(hash_st::run_self_tests)?;
        log::info!("Hash FIPS CAVP passed");
    }
    {
        run_silenced(hmac_st::run_self_tests)?;
        log::info!("HMAC FIPS CAVP passed");
    }

    Ok(())
}
