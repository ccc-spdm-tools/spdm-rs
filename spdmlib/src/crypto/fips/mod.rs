// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

#[cfg(any(
    feature = "sha256",
    feature = "sha384",
    feature = "sha512",
    feature = "aes-256-gcm",
    feature = "rsa-pkcs1",
    feature = "ecdsa-p256",
    feature = "ecdsa-p384",
    feature = "ecdh-p256",
    feature = "ecdh-p384"
))]
use super::*;

#[cfg(feature = "aes-256-gcm")]
mod aead_st;
#[cfg(any(feature = "rsa-pkcs1", feature = "ecdsa-p256", feature = "ecdsa-p384"))]
mod asym_verify_st;
mod cavs_vectors;
#[cfg(any(feature = "ecdh-p256", feature = "ecdh-p384"))]
mod dhe_st;
#[cfg(any(feature = "sha256", feature = "sha384"))]
mod hash_st;
#[cfg(any(feature = "sha256", feature = "sha384", feature = "sha512"))]
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

    #[cfg(feature = "aes-256-gcm")]
    aead_st::run_self_tests()?;
    #[cfg(any(feature = "rsa-pkcs1", feature = "ecdsa-p256", feature = "ecdsa-p384"))]
    asym_verify_st::run_self_tests()?;
    #[cfg(any(feature = "ecdh-p256", feature = "ecdh-p384"))]
    dhe_st::run_self_tests()?;
    #[cfg(any(feature = "sha256", feature = "sha384"))]
    hash_st::run_self_tests()?;
    #[cfg(any(feature = "sha256", feature = "sha384", feature = "sha512"))]
    hmac_st::run_self_tests()?;

    Ok(())
}
