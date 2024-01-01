// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::SpdmHkdf;
use crate::protocol::{
    SpdmBaseHashAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
    SpdmHkdfPseudoRandomKey, SPDM_MAX_HKDF_OKM_SIZE,
};

pub static DEFAULT: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: hkdf_extract,
    hkdf_expand_cb: hkdf_expand,
};

fn hkdf_extract(
    hash_algo: SpdmBaseHashAlgo,
    salt: &[u8],
    ikm: &SpdmHkdfInputKeyingMaterial,
) -> Option<SpdmHkdfPseudoRandomKey> {
    let algorithm = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => ring::hmac::HMAC_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => ring::hmac::HMAC_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => ring::hmac::HMAC_SHA512,
        _ => {
            panic!();
        }
    };

    let s_key = ring::hmac::Key::new(algorithm, salt);
    let tag = ring::hmac::sign(&s_key, ikm.as_ref());
    let tag = tag.as_ref();
    Some(SpdmHkdfPseudoRandomKey::from(tag))
}

fn hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    prk: &SpdmHkdfPseudoRandomKey,
    info: &[u8],
    out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    if out_size as usize > SPDM_MAX_HKDF_OKM_SIZE {
        return None;
    }

    let algo = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(ring::hkdf::HKDF_SHA256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(ring::hkdf::HKDF_SHA384),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(ring::hkdf::HKDF_SHA512),
        _ => return None,
    }?;

    if prk.data_size as usize != algo.hmac_algorithm().digest_algorithm().output_len() {
        return None;
    }

    let prk = ring::hkdf::Prk::new_less_safe(algo, prk.as_ref());

    let mut ret = SpdmHkdfOutputKeyingMaterial::default();
    let res = prk
        .expand(&[info], SpdmCryptoHkdfKeyLen::new(out_size))
        .and_then(|okm| {
            let len = out_size;
            ret.data_size = len;
            okm.fill(&mut ret.data[..len as usize])
        });
    match res {
        Ok(_) => Some(ret),
        Err(_) => None,
    }
}

struct SpdmCryptoHkdfKeyLen {
    out_size: usize,
}
impl SpdmCryptoHkdfKeyLen {
    pub fn new(len: u16) -> Self {
        SpdmCryptoHkdfKeyLen {
            out_size: len as usize,
        }
    }
}

impl ring::hkdf::KeyType for SpdmCryptoHkdfKeyLen {
    fn len(&self) -> usize {
        self.out_size
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::SPDM_MAX_HASH_SIZE;

    use super::*;

    #[test]
    fn test_case0_hkdf_expand() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        // according to https://www.rfc-editor.org/rfc/rfc5869
        // prk.len should be hashlen
        let prk = SpdmHkdfPseudoRandomKey {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let info = &mut [100u8; 64];
        let out_size = 64;
        let hkdf_expand = hkdf_expand(base_hash_algo, &prk, info, out_size);

        match hkdf_expand {
            Some(_) => {
                assert!(true)
            }
            None => {
                assert!(false)
            }
        }
    }
    #[test]
    fn test_case1_hkdf_expand() {
        // remove should panic
        // hkdf_expand is a library call. It's better to return failure/success instead of panic.
        let base_hash_algo = SpdmBaseHashAlgo::empty();
        let prk = SpdmHkdfPseudoRandomKey {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let info = &mut [100u8; 64];
        let out_size = 64;
        let hkdf_expand = hkdf_expand(base_hash_algo, &prk, info, out_size);

        match hkdf_expand {
            Some(_) => {
                // when bash_hash_algo is empty
                // hkdf_expand will failed and return None.
                assert!(false)
            }
            None => {
                assert!(true)
            }
        }
    }
}
