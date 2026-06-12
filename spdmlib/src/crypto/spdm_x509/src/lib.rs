// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM X.509 Certificate Validation
//!
//! A no_std-compatible X.509 parser and SPDM-focused certificate validation library.
//! Uses `der` for ASN.1 parsing and optional crypto backends for signature checks.
//!
//! # Features
//! - Parse X.509 v3 certificates from DER/PEM
//! - Verify SPDM certificate chains and signatures
//! - Process and validate extensions (Basic Constraints, Key Usage, etc.)
//! - SPDM EKU and extension validation
//!
//! # Example
//! ```no_run
//! use spdm_x509::Certificate;
//!
//! # fn example(cert_der: &[u8]) -> spdm_x509::Result<()> {
//! let cert = Certificate::from_der(cert_der)?;
//! let _ = cert;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod certificate;
pub mod chain;
pub mod crypto_backend;
pub mod error;
pub mod time;
pub mod x509;

pub use certificate::Certificate;
pub use chain::CertificateChain;
pub use error::{Error, Result};
pub use x509::extensions::{BasicConstraints, ExtendedKeyUsage, Extension, Extensions, KeyUsage};
pub use x509::{
    parse_spdm_cert_chain, validate_spdm_cert_chain, validate_spdm_cert_chain_with_backend,
    verify_cert_chain, verify_cert_chain_with_backend, verify_cert_chain_with_options,
    verify_signature, verify_signature_with_backend, SpdmBaseAsymAlgo, SpdmBaseHashAlgo,
    SpdmCertificateModel, SpdmCertificateRole, SpdmValidator,
};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::x509::{SpdmCertificateModel, SpdmCertificateRole, SpdmValidator};
    pub use crate::{Certificate, Error, Result};
}

/// Re-exports for spdmlib compatibility
pub mod spdmlib {
    pub use crate::x509::chain::{
        get_cert_from_cert_chain, verify_cert_chain, verify_cert_chain_with_backend,
    };
    pub use crate::x509::signature::{verify_signature, verify_signature_with_backend};
    pub use crate::x509::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmValidator};
}
