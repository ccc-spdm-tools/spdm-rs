// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

pub mod aead_impl;
pub mod asym_verify_impl;
pub mod cert_operation_impl;
pub mod dhe_impl;
pub mod hash_impl;
pub mod hkdf_impl;
pub mod hmac_impl;
pub mod kem_impl;
pub mod pqc_asym_verify_impl;
pub mod rand_impl;
extern crate alloc;

#[cfg(all(test, feature = "fips"))]
mod tests {
    use crate::{
        common::SpdmConfigInfo,
        protocol::{SpdmAeadAlgo, SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDheAlgo},
    };

    #[test]
    fn test_spdm_fips_self_tests() {
        let config = SpdmConfigInfo {
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_256 | SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
                | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
                | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            dhe_algo: SpdmDheAlgo::SECP_256_R1 | SpdmDheAlgo::SECP_384_R1,
            aead_algo: SpdmAeadAlgo::AES_256_GCM,
            ..Default::default()
        };

        assert!(crate::crypto::fips::run_self_tests(&config).is_ok());
    }
}
