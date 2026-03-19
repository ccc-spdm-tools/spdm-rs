// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! X.509 v3 certificate validation, extensions, and SPDM support.
//!
//! This module provides support for parsing and validating X.509 v3 certificates
//! and extensions as defined in RFC 5280, including SPDM-specific extensions
//! per DMTF DSP0274.

pub mod chain;
pub mod extensions;
pub mod oids;
pub mod signature;
pub mod spdm_validator;
pub(crate) mod validator;

pub use chain::{
    get_cert_from_cert_chain, parse_spdm_cert_chain, validate_spdm_cert_chain,
    validate_spdm_cert_chain_with_backend, verify_cert_chain, verify_cert_chain_with_backend,
    verify_cert_chain_with_options, SpdmCertChainHeader,
};
pub use extensions::*;
pub use signature::{
    verify_ecc_curve, verify_hash_algorithm, verify_rsa_key_size, verify_signature,
    verify_signature_algorithm, verify_signature_with_backend, SpdmBaseAsymAlgo, SpdmBaseHashAlgo,
};
pub use spdm_validator::{SpdmCertificateModel, SpdmCertificateRole, SpdmValidator};
