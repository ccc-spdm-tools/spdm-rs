// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! HKDF-SHA-256/384/512 via aws-lc-rs, for the standalone aws-lc backend.

use spdmlib::crypto::SpdmHkdf;
#[cfg(all(test, feature = "sha384"))]
use spdmlib::protocol::SpdmDigestStruct;
#[cfg(spdm_has_hash)]
use spdmlib::protocol::SPDM_MAX_HKDF_OKM_SIZE;
use spdmlib::protocol::{
    SpdmBaseHashAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
    SpdmHkdfPseudoRandomKey,
};

pub static DEFAULT: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: hkdf_extract,
    hkdf_expand_cb: hkdf_expand,
};

#[cfg(spdm_has_hash)]
fn hkdf_extract(
    hash_algo: SpdmBaseHashAlgo,
    salt: &[u8],
    ikm: &SpdmHkdfInputKeyingMaterial,
) -> Option<SpdmHkdfPseudoRandomKey> {
    // HKDF-Extract(salt, IKM) == HMAC(salt, IKM); use HMAC to produce the PRK,
    // matching the ring backend's behavior.
    let algorithm = match hash_algo {
        #[cfg(feature = "sha256")]
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => aws_lc_rs::hmac::HMAC_SHA256,
        #[cfg(feature = "sha384")]
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => aws_lc_rs::hmac::HMAC_SHA384,
        #[cfg(feature = "sha512")]
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => aws_lc_rs::hmac::HMAC_SHA512,
        _ => return None,
    };
    let s_key = aws_lc_rs::hmac::Key::new(algorithm, salt);
    let tag = aws_lc_rs::hmac::sign(&s_key, ikm.as_ref());
    Some(SpdmHkdfPseudoRandomKey::from(tag.as_ref()))
}

#[cfg(not(spdm_has_hash))]
fn hkdf_extract(
    _hash_algo: SpdmBaseHashAlgo,
    _salt: &[u8],
    _ikm: &SpdmHkdfInputKeyingMaterial,
) -> Option<SpdmHkdfPseudoRandomKey> {
    None
}

#[cfg(spdm_has_hash)]
fn hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    prk: &SpdmHkdfPseudoRandomKey,
    info: &[u8],
    out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    if out_size as usize > SPDM_MAX_HKDF_OKM_SIZE {
        return None;
    }
    let algo: aws_lc_rs::hkdf::Algorithm = match hash_algo {
        #[cfg(feature = "sha256")]
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => aws_lc_rs::hkdf::HKDF_SHA256,
        #[cfg(feature = "sha384")]
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => aws_lc_rs::hkdf::HKDF_SHA384,
        #[cfg(feature = "sha512")]
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => aws_lc_rs::hkdf::HKDF_SHA512,
        _ => return None,
    };
    if prk.data_size as usize != algo.hmac_algorithm().digest_algorithm().output_len() {
        return None;
    }
    let prk = aws_lc_rs::hkdf::Prk::new_less_safe(algo, prk.as_ref());
    let mut ret = SpdmHkdfOutputKeyingMaterial::default();
    let res = prk
        .expand(&[info], SpdmCryptoHkdfKeyLen::new(out_size))
        .and_then(|okm| {
            ret.data_size = out_size;
            okm.fill(&mut ret.data[..out_size as usize])
        });
    match res {
        Ok(_) => Some(ret),
        Err(_) => None,
    }
}

#[cfg(not(spdm_has_hash))]
fn hkdf_expand(
    _hash_algo: SpdmBaseHashAlgo,
    _prk: &SpdmHkdfPseudoRandomKey,
    _info: &[u8],
    _out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    None
}

#[cfg(spdm_has_hash)]
struct SpdmCryptoHkdfKeyLen {
    out_size: usize,
}
#[cfg(spdm_has_hash)]
impl SpdmCryptoHkdfKeyLen {
    pub fn new(len: u16) -> Self {
        SpdmCryptoHkdfKeyLen {
            out_size: len as usize,
        }
    }
}
#[cfg(spdm_has_hash)]
impl aws_lc_rs::hkdf::KeyType for SpdmCryptoHkdfKeyLen {
    fn len(&self) -> usize {
        self.out_size
    }
}

#[cfg(all(test, feature = "sha384"))]
mod tests {
    use super::*;

    #[cfg(feature = "sha384")]
    #[test]
    fn test_hkdf_extract_expand() {
        let algo = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        // Build an IKM from a SpdmDigestStruct (one of the enum's variants).
        let digest = SpdmDigestStruct::from(&[0x0bu8; 48][..]);
        let ikm = SpdmHkdfInputKeyingMaterial::SpdmDigest(&digest);
        let prk = hkdf_extract(algo, &[0u8; 48], &ikm).unwrap();
        assert_eq!(prk.data_size, 48);
        let okm = hkdf_expand(algo, &prk, b"info", 48).unwrap();
        assert_eq!(okm.data_size, 48);
    }
}
