// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

extern crate alloc;
use alloc::{boxed::Box, vec, vec::Vec};

use super::aead::{decrypt, encrypt};
use crate::{
    protocol::SpdmAeadAlgo,
    protocol::{
        SpdmAeadIvStruct, SpdmAeadKeyStruct, SPDM_MAX_AEAD_IV_SIZE, SPDM_MAX_AEAD_KEY_SIZE,
    },
};

use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};

use crate::crypto::fips::cavs_vectors::gcmDecrypt256;
use crate::crypto::fips::cavs_vectors::gcmEncryptExtIV256;

fn encrypt_self_test() -> SpdmResult {
    let aead_algo = SpdmAeadAlgo::AES_256_GCM;
    let cavs_vectors = gcmEncryptExtIV256::get_cavs_vectors();

    for cv in cavs_vectors.iter() {
        // Sanity check, expecting CAVS vectors with specific parameters
        if cv.key.len() != aead_algo.get_key_size() as usize
            || cv.iv.len() != aead_algo.get_iv_size() as usize
            || cv.tag.len() != aead_algo.get_tag_size() as usize
        {
            return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
        }

        let mut key = &mut SpdmAeadKeyStruct {
            data_size: cv.key.len() as u16,
            data: Box::new([0u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        for i in 0..cv.key.len() {
            key.data[i] = cv.key[i];
        }

        let mut iv = &mut SpdmAeadIvStruct {
            data_size: cv.iv.len() as u16,
            data: Box::new([0u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        for i in 0..cv.iv.len() {
            iv.data[i] = cv.iv[i];
        }

        let pt = &cv.pt;
        let tag = &cv.tag;
        let aad = &cv.aad;
        let ct = &cv.ct;
        let out_tag = &mut vec![0u8; cv.tag.len()][..];
        let out_ct = &mut vec![0u8; cv.ct.len()][..];

        let (out_ct_len, out_tag_len) =
            encrypt(aead_algo, key, iv, aad, pt, out_tag, out_ct).unwrap();

        if tag != &out_tag[0..out_tag_len] {
            return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
        }
        if ct != &out_ct[0..out_ct_len] {
            return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
        }
    }

    Ok(())
}

fn decrypt_self_test() -> SpdmResult {
    let aead_algo = SpdmAeadAlgo::AES_256_GCM;
    let cavs_vectors = gcmDecrypt256::get_cavs_vectors();

    for cv in cavs_vectors.iter() {
        // Sanity check, expecting CAVS vectors with specific parameters
        if cv.key.len() != aead_algo.get_key_size() as usize
            || cv.iv.len() != aead_algo.get_iv_size() as usize
            || cv.tag.len() != aead_algo.get_tag_size() as usize
        {
            return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
        }

        let mut key = &mut SpdmAeadKeyStruct {
            data_size: cv.key.len() as u16,
            data: Box::new([0u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        for i in 0..cv.key.len() {
            key.data[i] = cv.key[i];
        }

        let mut iv = &mut SpdmAeadIvStruct {
            data_size: cv.iv.len() as u16,
            data: Box::new([0u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        for i in 0..cv.iv.len() {
            iv.data[i] = cv.iv[i];
        }

        let pt = &cv.pt;
        let tag = &cv.tag;
        let aad = &cv.aad;
        let ct = &cv.ct;
        let out_pt = &mut vec![0u8; cv.pt.len()][..];

        let out_pt_len = decrypt(aead_algo, key, iv, aad, ct, tag, out_pt).unwrap();

        if out_pt_len != pt.len() {
            return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
        }
        if out_pt != pt {
            return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
        }
    }

    Ok(())
}

pub fn run_self_tests() -> SpdmResult {
    // encrypt
    match encrypt_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // decrypt
    match decrypt_self_test() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    Ok(())
}
