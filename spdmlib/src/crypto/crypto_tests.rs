// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::aead::{decrypt, encrypt};
#[cfg(feature = "hashed-transcript-data")]
use super::hash;
#[cfg(feature = "hashed-transcript-data")]
use crate::protocol::SpdmBaseHashAlgo;
use crate::{
    protocol::SpdmAeadAlgo,
    protocol::{
        SpdmAeadIvStruct, SpdmAeadKeyStruct, SPDM_MAX_AEAD_IV_SIZE, SPDM_MAX_AEAD_KEY_SIZE,
    },
};

#[cfg(feature = "hashed-transcript-data")]
#[test]
fn test_case_hash() {
    // Len = 8
    // Msg = d3
    // MD = 28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1
    let mut ctx = hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_256).unwrap();
    let data = &from_hex("d3").unwrap();
    let md = &from_hex("28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1").unwrap();
    hash::hash_ctx_update(&mut ctx, data).unwrap();
    let res = hash::hash_ctx_finalize(ctx).unwrap();
    assert_eq!(res.as_ref(), md);

    // Len = 512
    // Msg = 5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509
    // MD = 42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa
    let mut ctx2 = hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_256).unwrap();
    let data = &from_hex("5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509").unwrap();
    let md = &from_hex("42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa").unwrap();
    hash::hash_ctx_update(&mut ctx2, &data.as_slice()[0..10]).unwrap();
    let mut ctx3 = ctx2.clone();
    hash::hash_ctx_update(&mut ctx2, &data[10..]).unwrap();
    hash::hash_ctx_update(&mut ctx3, &data[10..]).unwrap();
    let res = hash::hash_ctx_finalize(ctx2).unwrap();
    let res3 = hash::hash_ctx_finalize(ctx3).unwrap();
    assert_eq!(res.as_ref(), md);
    assert_eq!(res3.as_ref(), md);
}

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
    let key =
        &from_hex_to_aead_key("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b")
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

#[test]
fn test_case_gcm128() {
    // Test vector from GCM Test Vectors (SP 800-38D)
    // [Keylen = 128]
    // [IVlen = 96]
    // [PTlen = 128]
    // [AADlen = 128]
    // [Taglen = 128]

    // Count = 0
    // Key = c939cc13397c1d37de6ae0e1cb7c423c
    // IV = b3d8cc017cbb89b39e0f67e2
    // PT = c3b3c41f113a31b73d9a5cd432103069
    // AAD = 24825602bd12a984e0092d3e448eda5f
    // CT = 93fe7d9e9bfd10348a5606e5cafa7354
    // Tag = 0032a1dc85f1c9786925a2e71d8272dd

    let aead_algo = SpdmAeadAlgo::AES_128_GCM;
    let key = &from_hex_to_aead_key("c939cc13397c1d37de6ae0e1cb7c423c").unwrap();
    let iv = &from_hex_to_aead_iv("b3d8cc017cbb89b39e0f67e2").unwrap();
    let plain_text = &from_hex("c3b3c41f113a31b73d9a5cd432103069").unwrap()[..];
    let tag = &from_hex("0032a1dc85f1c9786925a2e71d8272dd").unwrap()[..];
    let aad = &from_hex("24825602bd12a984e0092d3e448eda5f").unwrap()[..];
    let cipher = &from_hex("93fe7d9e9bfd10348a5606e5cafa7354").unwrap()[..];
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

#[test]
fn test_case_chacha20_poly1305() {
    // Test vector from RFC8439#section-2.8.2
    // KEY: 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
    // NONCE: 070000004041424344454647
    // IN: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    // ADD: 50515253c0c1c2c3c4c5c6c7
    // CT: d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116
    // TAG: 1ae10b594f09e26a7e902ecbd0600691
    let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
    let key =
        &from_hex_to_aead_key("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap();
    let iv = &from_hex_to_aead_iv("070000004041424344454647").unwrap();
    let plain_text = &b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."[..];
    let cipher = &from_hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        .unwrap()[..];
    let tag = &from_hex("1ae10b594f09e26a7e902ecbd0600691").unwrap()[..];
    let aad = &from_hex("50515253c0c1c2c3c4c5c6c7").unwrap()[..];
    let out_cipher = &mut [0u8; 114][..];
    let out_tag = &mut [0u8; 0x10][..];
    let out_plain_text = &mut [0u8; 114][..];
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
