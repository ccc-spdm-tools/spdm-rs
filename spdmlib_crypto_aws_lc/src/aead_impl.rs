// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! AEAD (AES-128/256-GCM, ChaCha20-Poly1305) via aws-lc-rs, for the standalone
//! aws-lc backend. Mirrors the ring backend's structure.

extern crate alloc;
use alloc::vec::Vec;

use log::error;
use spdmlib::crypto::SpdmAead;
use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};
use spdmlib::protocol::{SpdmAeadAlgo, SpdmAeadIvStruct, SpdmAeadKeyStruct};

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
    if key.data_size != aead_algo.get_key_size() {
        error!("key len invalid");
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }
    if iv.data_size != aead_algo.get_iv_size() {
        error!("iv len invalid");
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }
    let tag_size = tag.len();
    if tag_size != aead_algo.get_tag_size() as usize {
        error!("tag len invalid");
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }
    let plain_text_size = plain_text.len();
    if cipher_text.len() != plain_text_size {
        error!("cipher_text len invalid");
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }

    let mut d = [0u8; aws_lc_rs::aead::NONCE_LEN];
    d.copy_from_slice(&iv.data[..aws_lc_rs::aead::NONCE_LEN]);
    let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(d);

    cipher_text.copy_from_slice(plain_text);
    let mut s_key: aws_lc_rs::aead::SealingKey<OneNonceSequence> = make_key(aead_algo, key, nonce)?;
    match s_key.seal_in_place_separate_tag(aws_lc_rs::aead::Aad::from(aad), cipher_text) {
        Ok(t) => {
            tag.copy_from_slice(t.as_ref());
            Ok((plain_text_size, tag_size))
        }
        Err(_) => Err(SPDM_STATUS_CRYPTO_ERROR),
    }
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
    if key.data_size != aead_algo.get_key_size() {
        error!("key len invalid");
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }
    if iv.data_size != aead_algo.get_iv_size() {
        error!("iv len invalid");
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }
    let tag_size = tag.len();
    if tag_size != aead_algo.get_tag_size() as usize {
        error!("tag len invalid");
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }
    let cipher_text_size = cipher_text.len();
    if plain_text.len() != cipher_text_size {
        error!("plain_text len invalid");
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }

    let mut d = [0u8; aws_lc_rs::aead::NONCE_LEN];
    d.copy_from_slice(&iv.data[..aws_lc_rs::aead::NONCE_LEN]);
    let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(d);

    let mut in_out: Vec<u8> = Vec::with_capacity(cipher_text_size + tag_size);
    in_out.extend_from_slice(cipher_text);
    in_out.extend_from_slice(tag);

    let mut o_key: aws_lc_rs::aead::OpeningKey<OneNonceSequence> = make_key(aead_algo, key, nonce)?;
    match o_key.open_in_place(aws_lc_rs::aead::Aad::from(aad), &mut in_out) {
        Ok(out) => {
            plain_text.copy_from_slice(&out[..cipher_text_size]);
            Ok(cipher_text_size)
        }
        Err(_) => Err(SPDM_STATUS_CRYPTO_ERROR),
    }
}

fn make_key<K: aws_lc_rs::aead::BoundKey<OneNonceSequence>>(
    aead_algo: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    nonce: aws_lc_rs::aead::Nonce,
) -> SpdmResult<K> {
    let algorithm = match aead_algo {
        SpdmAeadAlgo::AES_128_GCM => &aws_lc_rs::aead::AES_128_GCM,
        SpdmAeadAlgo::AES_256_GCM => &aws_lc_rs::aead::AES_256_GCM,
        SpdmAeadAlgo::CHACHA20_POLY1305 => &aws_lc_rs::aead::CHACHA20_POLY1305,
        _ => return Err(SPDM_STATUS_CRYPTO_ERROR),
    };
    let unbound = aws_lc_rs::aead::UnboundKey::new(algorithm, key.as_ref())
        .map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    Ok(K::new(unbound, OneNonceSequence::new(nonce)))
}

struct OneNonceSequence(Option<aws_lc_rs::aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: aws_lc_rs::aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aws_lc_rs::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aws_lc_rs::aead::Nonce, aws_lc_rs::error::Unspecified> {
        self.0.take().ok_or(aws_lc_rs::error::Unspecified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_roundtrip_aes256() {
        let aead = SpdmAeadAlgo::AES_256_GCM;
        let key = SpdmAeadKeyStruct::from(&[0x11u8; 32][..]);
        let iv = SpdmAeadIvStruct::from(&[0x22u8; 12][..]);
        let plain = b"spdm-rs aws-lc aead test payload";
        let mut cipher = alloc::vec![0u8; plain.len()];
        let mut tag = [0u8; 16];
        let (pl, tl) = encrypt(aead, &key, &iv, b"aad", plain, &mut tag, &mut cipher).unwrap();
        assert_eq!(pl, plain.len());
        assert_eq!(tl, 16);
        let mut dec = alloc::vec![0u8; cipher.len()];
        let dl = decrypt(aead, &key, &iv, b"aad", &cipher, &tag, &mut dec).unwrap();
        assert_eq!(dl, plain.len());
        assert_eq!(&dec[..], &plain[..]);
        // Tampered AAD must fail.
        assert!(decrypt(aead, &key, &iv, b"bad", &cipher, &tag, &mut dec).is_err());
    }
}
