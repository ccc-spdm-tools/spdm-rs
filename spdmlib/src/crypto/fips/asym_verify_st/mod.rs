// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

use crate::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};
use ring::signature::RsaPublicKeyComponents;

use crate::crypto::fips::cavs_vectors::rsa_sig_ver;

pub fn run_self_tests() -> SpdmResult {
    let cavs_vectors = rsa_sig_ver::get_cavs_vectors();
    for cv in cavs_vectors.iter() {
        let public_key = RsaPublicKeyComponents { n: cv.n, e: cv.e };

        let params = match cv.hash {
            "SHA1" => &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            "SHA256" => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            "SHA384" => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            "SHA512" => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            _ => continue,
        };

        let ret = public_key.verify(params, &cv.msg, &cv.sig);
        match (cv.res, ret.is_ok()) {
            // Expecting positive result but got an error
            ("P", false) |
            // Expecting negative result but got a success
            ("F", true) => return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL),
            // All other cases are ok
            _ => continue,
        }
    }

    Ok(())
}
