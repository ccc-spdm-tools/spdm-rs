// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::SpdmAead;
use crate::error::{SpdmResult};

use crate::protocol::{SpdmAeadAlgo, SpdmAeadIvStruct, SpdmAeadKeyStruct};

pub static DEFAULT: SpdmAead = SpdmAead {
    encrypt_cb: encrypt,
    decrypt_cb: decrypt,
};

fn encrypt(
    aead_algo: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &SpdmAeadIvStruct,
    aad: &[u8],
    plain_text: &[u8],
    tag: &mut [u8],
    cipher_text: &mut [u8],
) -> SpdmResult<(usize, usize)> {
    unimplemented!()
}

fn decrypt(
    aead_algo: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &SpdmAeadIvStruct,
    aad: &[u8],
    cipher_text: &[u8],
    tag: &[u8],
    plain_text: &mut [u8],
) -> SpdmResult<usize> {
    unimplemented!()
}
