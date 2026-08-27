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
    #[test]
    fn test_spdm_fips_self_tests() {
        assert!(crate::crypto::fips::run_self_tests().is_ok());
    }
}
