// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_std]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod aead_impl;

pub mod dhe_impl;
pub mod hash_impl;
pub mod hkdf_impl;
pub mod hmac_impl;
pub mod kem_impl;
pub mod rand_impl;

pub mod asym_verify_impl;
pub mod cert_operation_impl;
pub mod pqc_asym_verify_impl;

#[cfg(all(test, feature = "fips"))]
mod tests {
    use super::*;

    #[test]
    fn test_spdm_fips_self_tests() {
        let config = spdmlib::common::SpdmConfigInfo {
            base_hash_algo: spdmlib::protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_256
                | spdmlib::protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            base_asym_algo: spdmlib::protocol::SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
                | spdmlib::protocol::SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
                | spdmlib::protocol::SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            dhe_algo: spdmlib::protocol::SpdmDheAlgo::SECP_256_R1
                | spdmlib::protocol::SpdmDheAlgo::SECP_384_R1,
            aead_algo: spdmlib::protocol::SpdmAeadAlgo::AES_256_GCM,
            ..Default::default()
        };

        spdmlib::crypto::hash::register(hash_impl::DEFAULT.clone());
        spdmlib::crypto::hmac::register(hmac_impl::DEFAULT.clone());
        spdmlib::crypto::aead::register(aead_impl::DEFAULT.clone());
        spdmlib::crypto::asym_verify::register(asym_verify_impl::DEFAULT.clone());
        spdmlib::crypto::dhe::register(dhe_impl::DEFAULT.clone());

        assert!(spdmlib::crypto::fips::run_self_tests(&config).is_ok());
    }
}
