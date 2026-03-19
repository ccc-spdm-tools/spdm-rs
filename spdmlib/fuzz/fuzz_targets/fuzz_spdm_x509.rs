// Copyright (c) 2024, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

pub use fuzzlib::*;

use spdmlib::crypto::{cert_operation, check_leaf_certificate, is_root_certificate};
use spdmlib::protocol::SpdmBaseAsymAlgo;

fuzz_target!(|cert: &[u8]| {
    // Exercise certificate chain parsing with various algorithms
    for _algo in [
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
    ] {
        let _ = cert_operation::get_cert_from_cert_chain(cert, 0);
        let _ = cert_operation::get_cert_from_cert_chain(cert, -1);
        let _ = cert_operation::verify_cert_chain(cert);
    }

    let _ = check_leaf_certificate(cert, true);
    let _ = check_leaf_certificate(cert, false);
    let _ = is_root_certificate(cert);
});
