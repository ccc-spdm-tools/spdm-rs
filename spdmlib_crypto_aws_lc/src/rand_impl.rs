// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! CSPRNG via aws-lc-rs, for the standalone aws-lc backend.

use aws_lc_rs::rand::SecureRandom;
use spdmlib::crypto::SpdmCryptoRandom;
use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};

pub static DEFAULT: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    rng.fill(data).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    Ok(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_random_small() {
        let data = &mut [0u8; 16];
        assert!(matches!(get_random(data), Ok(16)));
    }

    #[test]
    fn test_get_random_large() {
        let data = &mut [0u8; 80];
        assert!(matches!(get_random(data), Ok(80)));
    }
}
