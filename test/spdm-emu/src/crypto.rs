// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[cfg(feature = "spdm-mbedtls")]
pub fn crypto_mbedtls_register_handles() {
    spdmlib::crypto::aead::register(spdmlib_crypto_mbedtls::aead_impl::DEFAULT.clone());

    spdmlib::crypto::asym_verify::register(
        spdmlib_crypto_mbedtls::asym_verify_impl::DEFAULT.clone(),
    );

    spdmlib::crypto::cert_operation::register(
        spdmlib_crypto_mbedtls::cert_operation_impl::DEFAULT.clone(),
    );

    spdmlib::crypto::dhe::register(spdmlib_crypto_mbedtls::dhe_impl::DEFAULT.clone());

    spdmlib::crypto::hash::register(spdmlib_crypto_mbedtls::hash_impl::DEFAULT.clone());

    spdmlib::crypto::hkdf::register(spdmlib_crypto_mbedtls::hkdf_impl::DEFAULT.clone());

    spdmlib::crypto::hmac::register(spdmlib_crypto_mbedtls::hmac_impl::DEFAULT.clone());

    spdmlib::crypto::rand::register(spdmlib_crypto_mbedtls::rand_impl::DEFAULT.clone());
}
