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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdm_fips_self_tests() {
        spdmlib::crypto::hash::register(hash_impl::DEFAULT.clone());
        spdmlib::crypto::hmac::register(hmac_impl::DEFAULT.clone());
        spdmlib::crypto::aead::register(aead_impl::DEFAULT.clone());
        spdmlib::crypto::asym_verify::register(asym_verify_impl::DEFAULT.clone());
        spdmlib::crypto::dhe::register(dhe_impl::DEFAULT.clone());

        assert!(spdmlib::crypto::fips::run_self_tests().is_ok());
    }
}
