// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::SpdmHkdf;
use crate::protocol::{
    SpdmBaseHashAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
    SpdmHkdfPseudoRandomKey
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
    unimplemented!()
}

fn hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    prk: &SpdmHkdfPseudoRandomKey,
    info: &[u8],
    out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    unimplemented!()
}
