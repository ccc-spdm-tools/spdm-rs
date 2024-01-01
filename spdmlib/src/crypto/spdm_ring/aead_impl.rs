// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::bytes_mut_scrubbed::BytesMutStrubbed;
use crate::crypto::SpdmAead;
use crate::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};

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

    let mut d = [0u8; ring::aead::NONCE_LEN];
    d.copy_from_slice(&iv.data[..ring::aead::NONCE_LEN]);
    let nonce = ring::aead::Nonce::assume_unique_for_key(d);

    cipher_text.copy_from_slice(plain_text);

    let mut s_key: ring::aead::SealingKey<OneNonceSequence> =
        if let Ok(k) = make_key(aead_algo, key, nonce) {
            k
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };

    match s_key.seal_in_place_separate_tag(ring::aead::Aad::from(aad), cipher_text) {
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

    let mut d = [0u8; ring::aead::NONCE_LEN];
    d.copy_from_slice(&iv.data[..ring::aead::NONCE_LEN]);
    let nonce = ring::aead::Nonce::assume_unique_for_key(d);

    let mut in_out = BytesMutStrubbed::new();
    in_out.extend_from_slice(cipher_text);
    in_out.extend_from_slice(tag);

    let mut o_key: ring::aead::OpeningKey<OneNonceSequence> =
        if let Ok(k) = make_key(aead_algo, key, nonce) {
            k
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
    match o_key.open_in_place(ring::aead::Aad::from(aad), &mut in_out) {
        Ok(in_out_result) => {
            plain_text.copy_from_slice(&in_out_result[..cipher_text_size]);
            Ok(cipher_text_size)
        }
        Err(_) => Err(SPDM_STATUS_CRYPTO_ERROR),
    }
}

struct OneNonceSequence(Option<ring::aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: ring::aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl ring::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

fn make_key<K: ring::aead::BoundKey<OneNonceSequence>>(
    aead_algo: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    nonce: ring::aead::Nonce,
) -> SpdmResult<K> {
    let algorithm = match aead_algo {
        SpdmAeadAlgo::AES_128_GCM => &ring::aead::AES_128_GCM,
        SpdmAeadAlgo::AES_256_GCM => &ring::aead::AES_256_GCM,
        SpdmAeadAlgo::CHACHA20_POLY1305 => &ring::aead::CHACHA20_POLY1305,
        _ => {
            panic!();
        }
    };

    let key = if let Ok(k) = ring::aead::UnboundKey::new(algorithm, key.as_ref()) {
        k
    } else {
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    };
    let nonce_sequence = OneNonceSequence::new(nonce);
    Ok(K::new(key, nonce_sequence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;

    #[test]
    fn test_case0_encrypt() {
        let aead_algo = SpdmAeadAlgo::AES_128_GCM;
        let key = &SpdmAeadKeyStruct {
            data_size: 16,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [0u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];

        let status = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case1_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &SpdmAeadKeyStruct {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [100u8; 16];
        let tag = &mut [0u8; 16];

        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];

        let status = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text).is_ok();
        assert!(status);
    }
    #[test]
    #[should_panic]
    fn test_case2_encrypt() {
        let aead_algo = SpdmAeadAlgo::empty();
        let key = &SpdmAeadKeyStruct {
            data_size: 1,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    fn test_case3_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &SpdmAeadKeyStruct {
            data_size: 1,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    fn test_case4_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &SpdmAeadKeyStruct {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 1,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 32];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    fn test_case5_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &SpdmAeadKeyStruct {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 1];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    fn test_case6_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &SpdmAeadKeyStruct {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 32];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 1];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    #[should_panic]
    fn test_case0_decrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &SpdmAeadKeyStruct {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let cipher_text = &mut [100u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 12];
        let plain_text = &mut [100u8; 16];

        let ret_tag_size = decrypt(aead_algo, key, iv, aad, cipher_text, tag, plain_text);

        match ret_tag_size {
            Ok(16) => {
                assert!(true)
            }
            _ => {
                panic!()
            }
        }
    }
}
