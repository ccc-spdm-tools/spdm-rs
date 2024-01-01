// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use mbedtls::cipher::{raw, Authenticated, Cipher, Decryption, Encryption, Fresh};
use spdmlib::crypto::SpdmAead;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_PARAMETER};
use spdmlib::protocol::{
    SpdmAeadAlgo, SpdmAeadIvStruct, SpdmAeadKeyStruct, AEAD_AES_256_GCM_TAG_SIZE,
};

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
    let key_len = key.as_ref().len();
    if key_len != 32 {
        return Err(SPDM_STATUS_INVALID_PARAMETER);
    }
    if tag.len() != AEAD_AES_256_GCM_TAG_SIZE {
        return Err(SPDM_STATUS_INVALID_PARAMETER);
    }
    if aead_algo != SpdmAeadAlgo::AES_256_GCM {
        return Err(SPDM_STATUS_INVALID_PARAMETER);
    }
    let mut cipher_and_tag = Vec::<u8>::new();
    cipher_and_tag.extend_from_slice(plain_text);
    cipher_and_tag.extend_from_slice(&[0u8; AEAD_AES_256_GCM_TAG_SIZE]);
    match aead_algo {
        SpdmAeadAlgo::AES_256_GCM => {
            let cipher = Cipher::<Encryption, Authenticated, Fresh>::new(
                raw::CipherId::Aes,
                raw::CipherMode::GCM,
                (key_len * 8) as u32,
            )
            .map_err(|_| SPDM_STATUS_INVALID_PARAMETER)?;
            let cipher = cipher
                .set_key_iv(key.as_ref(), iv.as_ref())
                .map_err(|_| SPDM_STATUS_INVALID_PARAMETER)?;

            let (len, _) = cipher
                .encrypt_auth(
                    aad,
                    plain_text,
                    cipher_and_tag.as_mut_slice(),
                    AEAD_AES_256_GCM_TAG_SIZE,
                )
                .map_err(|_| SPDM_STATUS_INVALID_PARAMETER)?;
            let len = len - AEAD_AES_256_GCM_TAG_SIZE;
            if cipher_text.len() < len {
                return Err(SPDM_STATUS_INVALID_PARAMETER);
            }
            cipher_text[0..len].copy_from_slice(&cipher_and_tag[0..len]);
            tag[0..AEAD_AES_256_GCM_TAG_SIZE]
                .copy_from_slice(&cipher_and_tag[len..(len + AEAD_AES_256_GCM_TAG_SIZE)]);
            Ok((len, AEAD_AES_256_GCM_TAG_SIZE))
        }
        _ => Err(SPDM_STATUS_INVALID_PARAMETER),
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
    let key_len = key.as_ref().len();
    if key_len != 32 {
        return Err(SPDM_STATUS_INVALID_PARAMETER);
    }
    if tag.len() != AEAD_AES_256_GCM_TAG_SIZE {
        return Err(SPDM_STATUS_INVALID_PARAMETER);
    }
    if aead_algo != SpdmAeadAlgo::AES_256_GCM {
        return Err(SPDM_STATUS_INVALID_PARAMETER);
    }

    let mut cipher_and_tag = Vec::<u8>::new();
    cipher_and_tag.extend_from_slice(cipher_text);
    cipher_and_tag.extend_from_slice(tag);

    match aead_algo {
        SpdmAeadAlgo::AES_256_GCM => {
            let cipher = Cipher::<Decryption, Authenticated, _>::new(
                raw::CipherId::Aes,
                raw::CipherMode::GCM,
                (key_len * 8) as u32,
            )
            .map_err(|_| SPDM_STATUS_INVALID_PARAMETER)?;
            let cipher = cipher
                .set_key_iv(key.as_ref(), iv.as_ref())
                .map_err(|_| SPDM_STATUS_INVALID_PARAMETER)?;
            let (len, _) = cipher
                .decrypt_auth(
                    aad,
                    cipher_and_tag.as_slice(),
                    plain_text,
                    AEAD_AES_256_GCM_TAG_SIZE,
                )
                .map_err(|_| SPDM_STATUS_INVALID_PARAMETER)?;
            Ok(len)
        }
        _ => Err(SPDM_STATUS_INVALID_PARAMETER),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use spdmlib::{
        protocol::SpdmAeadAlgo,
        protocol::{
            SpdmAeadIvStruct, SpdmAeadKeyStruct, SPDM_MAX_AEAD_IV_SIZE, SPDM_MAX_AEAD_KEY_SIZE,
        },
    };
    #[test]
    fn test_case_gcm256() {
        // Test vector from GCM Test Vectors (SP 800-38D)
        // [Keylen = 256]
        // [IVlen = 96]
        // [PTlen = 128]
        // [AADlen = 128]
        // [Taglen = 128]

        // Count = 0
        // Key = 92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b
        // IV = ac93a1a6145299bde902f21a
        // PT = 2d71bcfa914e4ac045b2aa60955fad24
        // AAD = 1e0889016f67601c8ebea4943bc23ad6
        // CT = 8995ae2e6df3dbf96fac7b7137bae67f
        // Tag = eca5aa77d51d4a0a14d9c51e1da474ab
        let aead_algo = SpdmAeadAlgo::AES_256_GCM;
        let key = &from_hex_to_aead_key(
            "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b",
        )
        .unwrap();
        let iv = &from_hex_to_aead_iv("ac93a1a6145299bde902f21a").unwrap();
        let plain_text = &from_hex("2d71bcfa914e4ac045b2aa60955fad24").unwrap()[..];
        let tag = &from_hex("eca5aa77d51d4a0a14d9c51e1da474ab").unwrap()[..];
        let aad = &from_hex("1e0889016f67601c8ebea4943bc23ad6").unwrap()[..];
        let cipher = &from_hex("8995ae2e6df3dbf96fac7b7137bae67f").unwrap()[..];
        let out_tag = &mut [0u8; 16][..];
        let out_cipher = &mut [0u8; 16][..];
        let out_plain_text = &mut [0u8; 16][..];
        let (out_cipher_len, out_tag_len) =
            encrypt(aead_algo, key, iv, aad, plain_text, out_tag, out_cipher).unwrap();
        assert_eq!(tag, &out_tag[0..out_tag_len]);
        assert_eq!(cipher, &out_cipher[0..out_cipher_len]);

        let out_plain_text_len =
            decrypt(aead_algo, key, iv, aad, out_cipher, out_tag, out_plain_text).unwrap();
        assert_eq!(out_plain_text, plain_text);
        assert_eq!(out_plain_text_len, plain_text.len());
    }

    fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
        if hex_str.len() % 2 != 0 {
            return Err(String::from(
                "Hex string does not have an even number of digits",
            ));
        }

        let mut result = Vec::with_capacity(hex_str.len() / 2);
        for digits in hex_str.as_bytes().chunks(2) {
            let hi = from_hex_digit(digits[0])?;
            let lo = from_hex_digit(digits[1])?;
            result.push((hi * 0x10) | lo);
        }
        Ok(result)
    }

    fn from_hex_to_aead_key(hex_str: &str) -> Result<SpdmAeadKeyStruct, String> {
        if hex_str.len() % 2 != 0 || hex_str.len() > SPDM_MAX_AEAD_KEY_SIZE * 2 {
            return Err(String::from(
                "Hex string does not have an even number of digits",
            ));
        }

        let mut result = SpdmAeadKeyStruct {
            data_size: hex_str.len() as u16 / 2,
            data: Box::new([0u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        for (i, digits) in hex_str.as_bytes().chunks(2).enumerate() {
            let hi = from_hex_digit(digits[0])?;
            let lo = from_hex_digit(digits[1])?;
            result.data[i] = (hi * 0x10) | lo;
        }
        Ok(result)
    }

    fn from_hex_to_aead_iv(hex_str: &str) -> Result<SpdmAeadIvStruct, String> {
        if hex_str.len() % 2 != 0 || hex_str.len() > SPDM_MAX_AEAD_IV_SIZE * 2 {
            return Err(String::from(
                "Hex string does not have an even number of digits",
            ));
        }

        let mut result = SpdmAeadIvStruct {
            data_size: hex_str.len() as u16 / 2,
            data: Box::new([0u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        for (i, digits) in hex_str.as_bytes().chunks(2).enumerate() {
            let hi = from_hex_digit(digits[0])?;
            let lo = from_hex_digit(digits[1])?;
            result.data[i] = (hi * 0x10) | lo;
        }
        Ok(result)
    }

    fn from_hex_digit(d: u8) -> Result<u8, String> {
        use core::ops::RangeInclusive;
        const DECIMAL: (u8, RangeInclusive<u8>) = (0, b'0'..=b'9');
        const HEX_LOWER: (u8, RangeInclusive<u8>) = (10, b'a'..=b'f');
        const HEX_UPPER: (u8, RangeInclusive<u8>) = (10, b'A'..=b'F');
        for (offset, range) in &[DECIMAL, HEX_LOWER, HEX_UPPER] {
            if range.contains(&d) {
                return Ok(d - range.start() + offset);
            }
        }
        Err(format!("Invalid hex digit '{}'", d as char))
    }
}
