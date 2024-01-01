// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::spdmlib::crypto::SpdmHkdf;
use spdmlib::protocol::{
    SpdmBaseHashAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
    SpdmHkdfPseudoRandomKey, SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE, SHA512_DIGEST_SIZE,
    SPDM_MAX_HASH_SIZE, SPDM_MAX_HKDF_OKM_SIZE,
};

pub static FAKE_HKDF: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: fake_hkdf_extract,
    hkdf_expand_cb: fake_hkdf_expand,
};

fn fake_hkdf_extract(
    hash_algo: SpdmBaseHashAlgo,
    _salt: &[u8],
    _ikm: &SpdmHkdfInputKeyingMaterial,
) -> Option<SpdmHkdfPseudoRandomKey> {
    match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(SpdmHkdfPseudoRandomKey {
            data_size: SHA256_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        }),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(SpdmHkdfPseudoRandomKey {
            data_size: SHA384_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        }),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(SpdmHkdfPseudoRandomKey {
            data_size: SHA512_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        }),
        _ => None,
    }
}

fn fake_hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    _pk: &SpdmHkdfPseudoRandomKey,
    _info: &[u8],
    _out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(SpdmHkdfOutputKeyingMaterial {
            data_size: SHA256_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HKDF_OKM_SIZE]),
        }),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(SpdmHkdfOutputKeyingMaterial {
            data_size: SHA384_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HKDF_OKM_SIZE]),
        }),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(SpdmHkdfOutputKeyingMaterial {
            data_size: SHA512_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HKDF_OKM_SIZE]),
        }),
        _ => None,
    }
}
