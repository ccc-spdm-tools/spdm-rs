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
pub mod cavs_vectors;
#[cfg(any(feature = "ecdh-p256", feature = "ecdh-p384"))]
mod dhe_st;
#[cfg(any(feature = "sha256", feature = "sha384"))]
mod hash_st;
#[cfg(any(feature = "sha256", feature = "sha384", feature = "sha512"))]
mod hmac_st;
mod pqc_asym_verify_st;
mod pqc_kem_st;

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
    #[cfg(feature = "aes-256-gcm")]
    {
        run_silenced(aead_st::run_self_tests)?;
        log::info!("AES-256-GCM FIPS CAVP passed");
    }
    #[cfg(any(feature = "rsa-pkcs1", feature = "ecdsa-p256", feature = "ecdsa-p384"))]
    {
        run_silenced(asym_verify_st::run_self_tests)?;
        log::info!("Asymmetric verification FIPS CAVP passed");
    }
    #[cfg(any(feature = "ecdh-p256", feature = "ecdh-p384"))]
    {
        run_silenced(dhe_st::run_self_tests)?;
        log::info!("DHE FIPS CAVP passed");
    }
    #[cfg(any(feature = "sha256", feature = "sha384"))]
    {
        run_silenced(hash_st::run_self_tests)?;
        log::info!("Hash FIPS CAVP passed");
    }
    #[cfg(any(feature = "sha256", feature = "sha384", feature = "sha512"))]
    {
        run_silenced(hmac_st::run_self_tests)?;
        log::info!("HMAC FIPS CAVP passed");
    }

    let ml_dsa_tested = run_silenced(pqc_asym_verify_st::run_self_tests)?;
    if ml_dsa_tested {
        log::info!("ML-DSA FIPS CAVP passed");
    }

    let ml_kem_tested = run_silenced(pqc_kem_st::run_self_tests)?;
    if ml_kem_tested {
        log::info!("ML-KEM FIPS CAVP passed");
    }

    Ok(())
}
