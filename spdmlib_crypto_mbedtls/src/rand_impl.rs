// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::arch::x86_64::_rdrand64_step;
use spdmlib::crypto::SpdmCryptoRandom;
use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};

pub static DEFAULT: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

/// Number of RDRAND attempts before reporting failure.
const RDRAND_RETRY_COUNT: usize = 6;

fn rdrand64() -> Option<u64> {
    let mut value = 0u64;
    for _ in 0..RDRAND_RETRY_COUNT {
        // SAFETY: `value` is a live, properly aligned u64 for RDRAND to write.
        if unsafe { _rdrand64_step(&mut value) } == 1 {
            return Some(value);
        }
    }
    None
}

/// # Safety
///
/// `output` must be valid for writes of `len` bytes.
pub unsafe fn random(output: *mut u8, len: usize) -> i32 {
    // SAFETY: the caller guarantees `output` points to `len` writable bytes.
    let output = unsafe { core::slice::from_raw_parts_mut(output, len) };
    for chunk in output.chunks_mut(8) {
        match rdrand64() {
            Some(value) => chunk.copy_from_slice(&value.to_ne_bytes()[..chunk.len()]),
            None => return 1,
        }
    }
    0
}

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    if 0 == unsafe { random(data.as_mut_ptr(), data.len()) } {
        Ok(data.len())
    } else {
        Err(SPDM_STATUS_CRYPTO_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(8))]
    struct Aligned([u8; 40]);

    #[test]
    fn test_case0_get_random() {
        let data = &mut [0u8; 16];
        assert!(matches!(get_random(data), Ok(16)));
    }

    #[test]
    fn test_case1_random_unaligned_output() {
        // Start at every offset inside a word so each u64 write lands on a
        // misaligned address.
        let mut buffer = Aligned([0u8; 40]);
        for offset in 1..8 {
            let out = &mut buffer.0[offset..offset + 32];
            assert_eq!(unsafe { random(out.as_mut_ptr(), out.len()) }, 0);
            assert!(out.iter().any(|&b| b != 0));
        }
    }

    #[test]
    fn test_case2_random_partial_word() {
        let mut data = [0u8; 17];
        for len in [0usize, 1, 7, 8, 9, 16, 17] {
            assert_eq!(get_random(&mut data[..len]), Ok(len));
        }
    }
}
