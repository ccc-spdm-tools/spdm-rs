// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//
extern crate alloc;
use alloc::vec::Vec;

use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};

use crate::crypto::fips::cavs_vectors::dhe_vectors_p256;
use crate::crypto::fips::cavs_vectors::dhe_vectors_p384;

use ring::agreement::{
    agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256, ECDH_P384,
};

pub fn run_self_tests() -> SpdmResult {
    // P256
    {
        let cavs_vectors = dhe_vectors_p256::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            let mut qe_cavs = Vec::with_capacity(1 + cv.qe_cavs_x.len() + cv.qe_cavs_y.len());
            qe_cavs.push(0x04);
            qe_cavs.extend_from_slice(&cv.qe_cavs_x);
            qe_cavs.extend_from_slice(&cv.qe_cavs_y);

            let res;
            if let Ok(my_private) = EphemeralPrivateKey::from_bytes_for_test(&ECDH_P256, &cv.de_iut)
            {
                let peer_public = UnparsedPublicKey::new(&ECDH_P256, &qe_cavs);
                if let Ok(shared_secret) =
                    agree_ephemeral(my_private, &peer_public, |key_material| {
                        key_material.to_vec()
                    })
                {
                    res = &shared_secret[..] == &cv.z[..];
                } else {
                    res = false;
                }
            } else {
                res = false;
            }
            if !res {
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    // P384
    {
        let cavs_vectors = dhe_vectors_p384::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            let mut qe_cavs = Vec::with_capacity(1 + cv.qe_cavs_x.len() + cv.qe_cavs_y.len());
            qe_cavs.push(0x04);
            qe_cavs.extend_from_slice(&cv.qe_cavs_x);
            qe_cavs.extend_from_slice(&cv.qe_cavs_y);

            let res;
            if let Ok(my_private) = EphemeralPrivateKey::from_bytes_for_test(&ECDH_P384, &cv.de_iut)
            {
                let peer_public = UnparsedPublicKey::new(&ECDH_P384, &qe_cavs);
                if let Ok(shared_secret) =
                    agree_ephemeral(my_private, &peer_public, |key_material| {
                        key_material.to_vec()
                    })
                {
                    res = &shared_secret[..] == &cv.z[..];
                } else {
                    res = false;
                }
            } else {
                res = false;
            }
            if !res {
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    Ok(())
}
