// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::crypto::SpdmAead;
use spdmlib::error::SpdmResult;
use spdmlib::protocol::{SpdmAeadAlgo, SpdmAeadIvStruct, SpdmAeadKeyStruct};

pub static FAKE_AEAD: SpdmAead = SpdmAead {
    encrypt_cb: fake_encrypt,
    decrypt_cb: fake_decrypt,
};

fn fake_encrypt(
    _aead_algo: SpdmAeadAlgo,
    _key: &SpdmAeadKeyStruct,
    _iv: &SpdmAeadIvStruct,
    _aad: &[u8],
    plain_text: &[u8],
    tag: &mut [u8],
    cipher_text: &mut [u8],
) -> SpdmResult<(usize, usize)> {
    let plain_text_size = plain_text.len();
    let cipher_text_size = cipher_text.len();
    if cipher_text_size != plain_text_size {
        panic!("cipher_text len invalid");
    }
    cipher_text.copy_from_slice(plain_text);
    Ok((plain_text_size, tag.len()))
}

fn fake_decrypt(
    _aead_algo: SpdmAeadAlgo,
    _key: &SpdmAeadKeyStruct,
    _iv: &SpdmAeadIvStruct,
    _aad: &[u8],
    cipher_text: &[u8],
    _tag: &[u8],
    plain_text: &mut [u8],
) -> SpdmResult<usize> {
    let plain_text_size = plain_text.len();
    let cipher_text_size = cipher_text.len();
    if cipher_text_size != plain_text_size {
        panic!("plain_text len invalid");
    }
    plain_text.copy_from_slice(cipher_text);
    Ok(cipher_text_size)
}
