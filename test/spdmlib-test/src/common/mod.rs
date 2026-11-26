// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]

// TBD: need test different algorithm combinations

/// Default for base_asym_algo (BaseAsymAlgo - responder signing algorithm).
/// Override at runtime with SPDMRS_USE_ECDSA env variable.
pub const USE_ECDSA: bool = true;

/// Default for req_asym_algo (ReqBaseAsymAlg - requester signing algorithm).
/// Override at runtime with SPDMRS_REQ_USE_ECDSA env variable.
pub const REQ_USE_ECDSA: bool = true;

/// Check if ECDSA should be used for base_asym_algo (BaseAsymAlgo).
/// SPDMRS_USE_ECDSA=false or 0 -> uses RSA
/// SPDMRS_USE_ECDSA=true or unset -> uses ECDSA (default)
pub fn use_ecdsa() -> bool {
    std::env::var("SPDMRS_USE_ECDSA")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(USE_ECDSA)
}

/// Check if ECDSA should be used for req_asym_algo (ReqBaseAsymAlg).
/// SPDMRS_REQ_USE_ECDSA=false or 0 -> uses RSA
/// SPDMRS_REQ_USE_ECDSA=true or unset -> uses ECDSA (default)
pub fn req_use_ecdsa() -> bool {
    std::env::var("SPDMRS_REQ_USE_ECDSA")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(REQ_USE_ECDSA)
}

/// Check if PQC should be used: ML-KEM + ML-DSA, for both endpoints. It takes precedence over
/// SPDMRS_USE_ECDSA and SPDMRS_REQ_USE_ECDSA.
/// SPDMRS_USE_PQC=true or 1 -> uses ML-KEM and ML-DSA
/// SPDMRS_USE_PQC=false or 0 or unset -> does not (default)
pub fn use_pqc() -> bool {
    std::env::var("SPDMRS_USE_PQC")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

pub mod algo;

pub mod util;

pub mod device_io;

pub use pcidoe_transport as transport;

pub mod crypto_callback;
pub mod secret_callback;
