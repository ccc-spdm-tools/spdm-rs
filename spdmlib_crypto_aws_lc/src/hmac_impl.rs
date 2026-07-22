// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! HMAC-SHA-256/384/512 via aws-lc-rs, for the standalone aws-lc backend.

use spdmlib::crypto::SpdmHmac;
use spdmlib::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub static DEFAULT: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(base_hash_algo: SpdmBaseHashAlgo, key: &[u8], data: &[u8]) -> Option<SpdmDigestStruct> {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => aws_lc_rs::hmac::HMAC_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => aws_lc_rs::hmac::HMAC_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => aws_lc_rs::hmac::HMAC_SHA512,
        _ => return None,
    };
    let s_key = aws_lc_rs::hmac::Key::new(algorithm, key);
    let tag = aws_lc_rs::hmac::sign(&s_key, data);
    Some(SpdmDigestStruct::from(tag.as_ref()))
}

fn hmac_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    key: &[u8],
    data: &[u8],
    hmac: &SpdmDigestStruct,
) -> SpdmResult {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => aws_lc_rs::hmac::HMAC_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => aws_lc_rs::hmac::HMAC_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => aws_lc_rs::hmac::HMAC_SHA512,
        _ => return Err(SPDM_STATUS_VERIF_FAIL),
    };
    let v_key = aws_lc_rs::hmac::Key::new(algorithm, key);
    match aws_lc_rs::hmac::verify(&v_key, data, &hmac.data[..(hmac.data_size as usize)]) {
        Ok(()) => Ok(()),
        Err(_) => Err(SPDM_STATUS_VERIF_FAIL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sign_verify_roundtrip() {
        for algo in [
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
        ] {
            let key = [0x0bu8; 20];
            let data = b"spdm-rs aws-lc hmac test";
            let tag = hmac(algo, &key, data).unwrap();
            assert!(hmac_verify(algo, &key, data, &tag).is_ok());
            // Wrong data must fail.
            assert!(hmac_verify(algo, &key, b"other", &tag).is_err());
        }
    }
}
