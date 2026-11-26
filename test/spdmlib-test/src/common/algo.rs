// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! The algorithms that the tests negotiate, from three environment variables. This is the one
//! place that decides them, so a test never names an algorithm for the connection it sets up.
//!
//! * `SPDMRS_USE_PQC` is true: ML-KEM + ML-DSA, and nothing classical. It takes precedence.
//! * Else the key exchange is ECDHE, and the signature is ECDSA or RSA. `SPDMRS_USE_ECDSA` decides
//!   the one of the Responder (BaseAsymAlgo): ECDSA when it is true, RSA when it is false.
//!   `SPDMRS_REQ_USE_ECDSA` decides, the same way, the one of the Requester in mutual
//!   authentication (ReqBaseAsymAlg).
//!
//! The functions are named after the SPDM fields. A function reads only the variables of its own
//! field, so `base_asym_algo()` never looks at `SPDMRS_REQ_USE_ECDSA`, and `req_base_asym_algo()`
//! never looks at `SPDMRS_USE_ECDSA`. A test uses these functions, and decides no algorithm by
//! itself.

use super::{req_use_ecdsa, use_ecdsa, use_pqc};
use spdmlib::protocol::*;

/// BaseAsymAlgo. It is empty with PQC.
pub fn base_asym_algo() -> SpdmBaseAsymAlgo {
    if use_pqc() {
        SpdmBaseAsymAlgo::empty()
    } else if use_ecdsa() {
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
    } else {
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
    }
}

/// ReqBaseAsymAlg. It is empty with PQC.
pub fn req_base_asym_algo() -> SpdmReqAsymAlgo {
    if use_pqc() {
        SpdmReqAsymAlgo::empty()
    } else if req_use_ecdsa() {
        SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
    } else {
        SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072
    }
}

/// PqcAsymAlgo. It is empty without PQC.
pub fn pqc_asym_algo() -> SpdmPqcAsymAlgo {
    if use_pqc() {
        SpdmPqcAsymAlgo::ALG_MLDSA_87
    } else {
        SpdmPqcAsymAlgo::empty()
    }
}

/// ReqPqcAsymAlg. It is empty without PQC.
pub fn req_pqc_asym_algo() -> SpdmPqcReqAsymAlgo {
    if use_pqc() {
        SpdmPqcReqAsymAlgo::ALG_MLDSA_87
    } else {
        SpdmPqcReqAsymAlgo::empty()
    }
}

/// The DHE group. It is empty with PQC, which uses a KEM.
pub fn dhe_algo() -> SpdmDheAlgo {
    if use_pqc() {
        SpdmDheAlgo::empty()
    } else {
        SpdmDheAlgo::SECP_384_R1
    }
}

/// The KEM. It is empty without PQC.
pub fn kem_algo() -> SpdmKemAlgo {
    if use_pqc() {
        SpdmKemAlgo::ALG_MLKEM_1024
    } else {
        SpdmKemAlgo::empty()
    }
}

/// The size of a signature of the BaseAsymAlgo, or of the PqcAsymAlgo with PQC.
pub fn asym_sig_size() -> usize {
    if use_pqc() {
        MLDSA_87_SIG_SIZE
    } else if use_ecdsa() {
        ECDSA_ECC_NIST_P384_SIG_SIZE
    } else {
        RSASSA_3072_SIG_SIZE
    }
}

/// The size of a signature of the ReqBaseAsymAlg, or of the ReqPqcAsymAlg with PQC.
pub fn req_asym_sig_size() -> usize {
    if use_pqc() {
        MLDSA_87_SIG_SIZE
    } else if req_use_ecdsa() {
        ECDSA_ECC_NIST_P384_SIG_SIZE
    } else {
        RSASSA_3072_SIG_SIZE
    }
}

/// The directory, under the repository root, with the keys and the certificates of the
/// BaseAsymAlgo, or of the PqcAsymAlgo with PQC.
pub fn asym_cert_dir() -> &'static str {
    if use_pqc() {
        "test_key/mldsa87"
    } else if use_ecdsa() {
        "test_key/ecp384"
    } else {
        "test_key/rsa3072"
    }
}

/// The directory, under the repository root, with the keys and the certificates of the
/// ReqBaseAsymAlg, or of the ReqPqcAsymAlg with PQC.
pub fn req_asym_cert_dir() -> &'static str {
    if use_pqc() {
        "test_key/mldsa87"
    } else if req_use_ecdsa() {
        "test_key/ecp384"
    } else {
        "test_key/rsa3072"
    }
}

/// The SPDM version that a test runs a connection at. PQC needs SPDM 1.4, so a lower version is
/// raised to it; without PQC the version is kept.
pub fn spdm_version(version: SpdmVersion) -> SpdmVersion {
    if use_pqc() && version < SpdmVersion::SpdmVersion14 {
        SpdmVersion::SpdmVersion14
    } else {
        version
    }
}
