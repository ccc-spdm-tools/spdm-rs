// Copyright (c) 2024, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

pub use fuzzlib::*;

use spdmlib::crypto::{cert_operation, check_leaf_certificate, is_root_certificate};
use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmPqcAsymAlgo};

fuzz_target!(|cert: &[u8]| {
    // Exercise certificate chain parsing with various algorithms
    for algo in [
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
        let _ = cert_operation::verify_cert_chain(
            cert,
            algo,
            SpdmPqcAsymAlgo::empty(),
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        );
        let _ = spdm_x509::x509::spdm_validator::validate_spdm_certificate_chain_algorithms(
            cert,
            algo.bits(),
            0,
        );
    }

    for pqc in [
        SpdmPqcAsymAlgo::ALG_MLDSA_44,
        SpdmPqcAsymAlgo::ALG_MLDSA_65,
        SpdmPqcAsymAlgo::ALG_MLDSA_87,
    ] {
        let _ = cert_operation::verify_cert_chain(
            cert,
            SpdmBaseAsymAlgo::empty(),
            pqc,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        );
        let _ = spdm_x509::x509::spdm_validator::validate_spdm_certificate_chain_algorithms(
            cert,
            0,
            pqc.bits(),
        );
    }

    let _ = check_leaf_certificate(cert, true, false);
    let _ = check_leaf_certificate(cert, false, false);
    let _ = check_leaf_certificate(cert, false, true);
    let _ = is_root_certificate(cert);
});
