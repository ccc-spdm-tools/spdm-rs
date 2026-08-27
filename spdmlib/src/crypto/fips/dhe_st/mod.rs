// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//
extern crate alloc;

use crate::crypto::dhe;
use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};
use crate::protocol::{SpdmDheAlgo, SpdmDheExchangeStruct};

use crate::crypto::fips::cavs_vectors::dhe_vectors_p256;
use crate::crypto::fips::cavs_vectors::dhe_vectors_p384;

fn verify_vector(
    algo: SpdmDheAlgo,
    private_key: &[u8],
    peer_x: &[u8],
    peer_y: &[u8],
    expected_secret: &[u8],
) -> bool {
    let Some(key_exchange) = dhe::import_private_key(algo, private_key) else {
        return false;
    };
    let mut peer_public = SpdmDheExchangeStruct {
        data_size: (peer_x.len() + peer_y.len()) as u16,
        ..Default::default()
    };
    peer_public.data[..peer_x.len()].copy_from_slice(peer_x);
    peer_public.data[peer_x.len()..peer_x.len() + peer_y.len()].copy_from_slice(peer_y);

    let Some(secret) = key_exchange.compute_final_key(&peer_public) else {
        return false;
    };
    &secret.data[..secret.data_size as usize] == expected_secret
}

pub fn run_self_tests() -> SpdmResult {
    // P256
    {
        let cavs_vectors = dhe_vectors_p256::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            if !verify_vector(
                SpdmDheAlgo::SECP_256_R1,
                cv.de_iut,
                cv.qe_cavs_x,
                cv.qe_cavs_y,
                cv.z,
            ) {
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    // P384
    {
        let cavs_vectors = dhe_vectors_p384::get_cavs_vectors();
        for cv in cavs_vectors.iter() {
            if !verify_vector(
                SpdmDheAlgo::SECP_384_R1,
                cv.de_iut,
                cv.qe_cavs_x,
                cv.qe_cavs_y,
                cv.z,
            ) {
                return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
            }
        }
    }

    Ok(())
}
