// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Certificate chain types.
//!
//! This module provides the `CertificateChain` type for representing
//! an ordered sequence of X.509 certificates from leaf to root.

extern crate alloc;

use alloc::vec::Vec;

use crate::certificate::Certificate;

// ============================================================================
// Certificate Chain
// ============================================================================

/// A certificate chain, ordered from leaf (end-entity) to root (trust anchor).
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// The certificates in the chain, from leaf to root
    pub certificates: Vec<Certificate>,
}

impl CertificateChain {
    /// Create a new certificate chain
    pub fn new(certificates: Vec<Certificate>) -> Self {
        Self { certificates }
    }

    /// Create a chain with a single certificate
    pub fn single(cert: Certificate) -> Self {
        Self {
            certificates: alloc::vec![cert],
        }
    }

    /// Add a certificate to the chain
    pub fn push(&mut self, cert: Certificate) {
        self.certificates.push(cert);
    }

    /// Get the leaf (end-entity) certificate
    pub fn leaf(&self) -> Option<&Certificate> {
        self.certificates.first()
    }

    /// Get the root (trust anchor) certificate
    pub fn root(&self) -> Option<&Certificate> {
        self.certificates.last()
    }

    /// Get the chain length
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Get an iterator over the certificates
    pub fn iter(&self) -> core::slice::Iter<'_, Certificate> {
        self.certificates.iter()
    }
}
