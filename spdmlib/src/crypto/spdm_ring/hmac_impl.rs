// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::SpdmHmac;
use crate::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use crate::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub static DEFAULT: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(base_hash_algo: SpdmBaseHashAlgo, key: &[u8], data: &[u8]) -> Option<SpdmDigestStruct> {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => ring::hmac::HMAC_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => ring::hmac::HMAC_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => ring::hmac::HMAC_SHA512,
        _ => {
            panic!();
        }
    };

    let s_key = ring::hmac::Key::new(algorithm, key);
    let tag = ring::hmac::sign(&s_key, data);
    let tag = tag.as_ref();
    Some(SpdmDigestStruct::from(tag))
}

fn hmac_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    key: &[u8],
    data: &[u8],
    hmac: &SpdmDigestStruct,
) -> SpdmResult {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => ring::hmac::HMAC_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => ring::hmac::HMAC_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => ring::hmac::HMAC_SHA512,
        _ => {
            panic!();
        }
    };

    let v_key = ring::hmac::Key::new(algorithm, key);
    match ring::hmac::verify(&v_key, data, &hmac.data[..(hmac.data_size as usize)]) {
        Ok(()) => Ok(()),
        Err(_) => Err(SPDM_STATUS_VERIF_FAIL),
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{SpdmFinishedKeyStruct, SPDM_MAX_HASH_SIZE};

    use super::*;

    #[test]
    fn test_case0_hmac_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let key = &SpdmFinishedKeyStruct {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let data = &mut [100u8; 64];
        let spdm_digest = hmac(base_hash_algo, key.as_ref(), data).unwrap();
        let spdm_digest_struct = hmac_verify(base_hash_algo, key.as_ref(), data, &spdm_digest);

        match spdm_digest_struct {
            Ok(()) => {
                assert!(true)
            }
            _ => {
                panic!()
            }
        }
    }
    #[test]
    fn test_case1_hmac_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let key = &SpdmFinishedKeyStruct {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let data = &mut [10u8; 128];
        let spdm_digest = hmac(base_hash_algo, key.as_ref(), data).unwrap();
        let spdm_digest_struct = hmac_verify(base_hash_algo, key.as_ref(), data, &spdm_digest);

        match spdm_digest_struct {
            Ok(()) => {
                assert!(true)
            }
            _ => {
                panic!()
            }
        }
    }
    #[test]
    #[should_panic]
    fn test_case2_hmac_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let key = &SpdmFinishedKeyStruct {
            data_size: 128,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let data = &mut [10u8; 128];
        let spdm_digest = hmac(base_hash_algo, key.as_ref(), data).unwrap();
        let data = &mut [100u8; 128];
        let spdm_digest_struct = hmac_verify(base_hash_algo, key.as_ref(), data, &spdm_digest);

        match spdm_digest_struct {
            Ok(()) => {
                assert!(true)
            }
            _ => {
                panic!()
            }
        }
    }
}
