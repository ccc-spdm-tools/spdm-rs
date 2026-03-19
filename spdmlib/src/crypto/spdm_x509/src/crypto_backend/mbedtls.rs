// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! mbedtls backend for signature verification.
//!
//! This module provides an mbedtls-based implementation of the crypto backend.

use super::SignatureAlgorithm;
use crate::error::Result;

/// Verify a signature using mbedtls backend (stub).
pub fn verify_signature(
    _algorithm: SignatureAlgorithm,
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<()> {
    Err(crate::error::Error::unsupported_algorithm(
        "mbedtls backend not yet implemented",
    ))
}
