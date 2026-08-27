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

use crate::{
    common::SpdmConfigInfo,
    error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL},
    protocol::{
        SpdmAeadAlgo, SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDheAlgo, SpdmMeasurementHashAlgo,
    },
};

/// Classical algorithms covered by startup known-answer tests.
struct SupportedAlgorithms {
    base_hash: SpdmBaseHashAlgo,
    measurement_hash: SpdmMeasurementHashAlgo,
    asym: SpdmBaseAsymAlgo,
    dhe: SpdmDheAlgo,
    aead: SpdmAeadAlgo,
}

const SUPPORTED_ALGORITHMS: SupportedAlgorithms = SupportedAlgorithms {
    base_hash: SpdmBaseHashAlgo::from_bits_truncate(
        SpdmBaseHashAlgo::TPM_ALG_SHA_256.bits() | SpdmBaseHashAlgo::TPM_ALG_SHA_384.bits(),
    ),
    measurement_hash: SpdmMeasurementHashAlgo::from_bits_truncate(
        SpdmMeasurementHashAlgo::TPM_ALG_SHA_256.bits()
            | SpdmMeasurementHashAlgo::TPM_ALG_SHA_384.bits(),
    ),
    asym: SpdmBaseAsymAlgo::from_bits_truncate(
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048.bits()
            | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072.bits()
            | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096.bits()
            | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256.bits()
            | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384.bits(),
    ),
    dhe: SpdmDheAlgo::from_bits_truncate(
        SpdmDheAlgo::SECP_256_R1.bits() | SpdmDheAlgo::SECP_384_R1.bits(),
    ),
    aead: SpdmAeadAlgo::AES_256_GCM,
};

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

fn configured_hash_algorithms(config: &SpdmConfigInfo) -> SpdmBaseHashAlgo {
    let mut algorithms = config.base_hash_algo;

    if config
        .measurement_hash_algo
        .contains(SpdmMeasurementHashAlgo::TPM_ALG_SHA_256)
    {
        algorithms |= SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    }
    if config
        .measurement_hash_algo
        .contains(SpdmMeasurementHashAlgo::TPM_ALG_SHA_384)
    {
        algorithms |= SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    }
    if config
        .measurement_hash_algo
        .contains(SpdmMeasurementHashAlgo::TPM_ALG_SHA_512)
    {
        algorithms |= SpdmBaseHashAlgo::TPM_ALG_SHA_512;
    }

    algorithms
}

fn configured_asym_algorithms(config: &SpdmConfigInfo) -> SpdmBaseAsymAlgo {
    config.base_asym_algo | config.req_asym_algo.to_base()
}

impl SupportedAlgorithms {
    fn supports(&self, config: &SpdmConfigInfo) -> bool {
        self.base_hash.contains(config.base_hash_algo)
            && self.measurement_hash.contains(config.measurement_hash_algo)
            && self.asym.contains(configured_asym_algorithms(config))
            && self.dhe.contains(config.dhe_algo)
            && self.aead.contains(config.aead_algo)
    }
}

fn ensure_self_test_coverage(config: &SpdmConfigInfo) -> SpdmResult {
    if SUPPORTED_ALGORITHMS.supports(config) {
        Ok(())
    } else {
        Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL)
    }
}

/// Run startup known-answer tests for the classical algorithms enabled by `config`.
///
/// Requester and responder authentication capabilities are combined because
/// they use the same verification primitives. Hash tests cover both base and
/// measurement hashes, while HMAC tests cover only configured base hashes.
pub fn run_self_tests(config: &SpdmConfigInfo) -> SpdmResult {
    ensure_self_test_coverage(config)?;

    let hash_algorithms = configured_hash_algorithms(config);
    let asym_algorithms = configured_asym_algorithms(config);

    if run_silenced(|| aead_st::run_self_tests(config.aead_algo))? {
        log::info!("AEAD FIPS CAVP passed");
    }
    if run_silenced(|| asym_verify_st::run_self_tests(hash_algorithms, asym_algorithms))? {
        log::info!("Asymmetric verification FIPS CAVP passed");
    }
    if run_silenced(|| dhe_st::run_self_tests(config.dhe_algo))? {
        log::info!("DHE FIPS CAVP passed");
    }
    if run_silenced(|| hash_st::run_self_tests(hash_algorithms))? {
        log::info!("Hash FIPS CAVP passed");
    }
    if run_silenced(|| hmac_st::run_self_tests(config.base_hash_algo))? {
        log::info!("HMAC FIPS CAVP passed");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SpdmReqAsymAlgo;

    #[test]
    fn test_empty_config_runs_no_self_tests() {
        assert!(run_self_tests(&SpdmConfigInfo::default()).is_ok());
    }

    #[test]
    fn test_configured_algorithms_include_all_consumer_uses() {
        let config = SpdmConfigInfo {
            measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_256,
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            ..Default::default()
        };

        assert_eq!(
            configured_hash_algorithms(&config),
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 | SpdmBaseHashAlgo::TPM_ALG_SHA_384
        );
        assert_eq!(
            configured_asym_algorithms(&config),
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
                | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        );
    }

    #[test]
    fn test_example_supported_profile_has_self_test_coverage() {
        let config = SpdmConfigInfo {
            measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_256
                | SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_256 | SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
                | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
                | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
            req_asym_algo: SpdmReqAsymAlgo::empty(),
            dhe_algo: SpdmDheAlgo::SECP_256_R1 | SpdmDheAlgo::SECP_384_R1,
            aead_algo: SpdmAeadAlgo::AES_256_GCM,
            ..Default::default()
        };

        assert_eq!(ensure_self_test_coverage(&config), Ok(()));
    }

    /**
    The following test ensures that each classical algorithm enabled in the configuration has a corresponding self-test implemented.
    If a new classical algorithm is added to the configuration, this test will fail until a self-test is implemented for that algorithm.
    */
    #[test]
    fn test_configured_algorithms_require_self_test_coverage() {
        let unsupported_configs = [
            SpdmConfigInfo {
                base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                ..Default::default()
            },
            SpdmConfigInfo {
                measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA3_256,
                ..Default::default()
            },
            SpdmConfigInfo {
                base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
                ..Default::default()
            },
            SpdmConfigInfo {
                req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_RSAPSS_3072,
                ..Default::default()
            },
            SpdmConfigInfo {
                aead_algo: SpdmAeadAlgo::CHACHA20_POLY1305,
                ..Default::default()
            },
        ];

        for config in unsupported_configs {
            assert_eq!(
                ensure_self_test_coverage(&config),
                Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL)
            );
        }
    }
}
