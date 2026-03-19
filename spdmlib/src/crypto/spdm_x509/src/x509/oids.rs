// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM OID constants
//!
//! This module defines Object Identifier (OID) constants for SPDM (DSP0274)
//! certificate validation. These OIDs are used in X.509 certificate extensions
//! to identify SPDM-specific certificate types and usage.
//!
//! # SPDM Base OID
//! All SPDM-related OIDs are under the DMTF enterprise OID: 1.3.6.1.4.1.412.274
//!
//! # References
//! - DSP0274 - SPDM Specification

use const_oid::ObjectIdentifier;

// =============================================================================
// DMTF and SPDM Base OIDs
// =============================================================================

/// DMTF enterprise base OID - 1.3.6.1.4.1.412
pub const DMTF_BASE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412");

/// SPDM base OID - 1.3.6.1.4.1.412.274
/// All SPDM-specific OIDs are under this base
pub const SPDM_BASE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274");

// =============================================================================
// SPDM OIDs per libspdm include/industry_standard/spdm.h
// =============================================================================

/// Device Info OID - 1.3.6.1.4.1.412.274.1
/// id-DMTF-device-info in libspdm
///
/// This OID appears within the SPDM Extension (see below).
pub const DEVICE_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.1");

/// Hardware Identity OID - 1.3.6.1.4.1.412.274.2
/// id-DMTF-hardware-identity in libspdm
///
/// This OID appears within the SPDM Extension to indicate that the certificate
/// contains hardware identity information.
///
/// # Validation Rules
/// - MUST be present in DeviceCert certificates
/// - MUST NOT be present in AliasCert certificates
/// - Optional for GenericCert certificates
pub const HARDWARE_IDENTITY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.2");

// =============================================================================
// SPDM Extended Key Usage OIDs (DSP0274 Section 10.6.1.3)
// =============================================================================

/// SPDM Responder Authentication EKU - 1.3.6.1.4.1.412.274.3
/// id-DMTF-eku-responder-auth in libspdm
///
/// This EKU identifies a certificate that can be used for SPDM Responder authentication.
/// A Responder certificate MUST NOT contain ONLY the Requester Auth OID.
pub const SPDM_RESPONDER_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.3");

/// SPDM Requester Authentication EKU - 1.3.6.1.4.1.412.274.4
/// id-DMTF-eku-requester-auth in libspdm
///
/// This EKU identifies a certificate that can be used for SPDM Requester authentication.
/// A Requester certificate MUST NOT contain ONLY the Requester Auth OID.
pub const SPDM_REQUESTER_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.4");

/// Mutable Certificate OID - 1.3.6.1.4.1.412.274.5
/// id-DMTF-mutable-certificate in libspdm
pub const MUTABLE_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.5");

// =============================================================================
// SPDM Extension OIDs (DSP0274 Section 10.6.1.4)
// =============================================================================

/// SPDM Extension - 1.3.6.1.4.1.412.274.6
/// id-DMTF-SPDM-extension in libspdm
///
/// This X.509 extension (the extension OID itself) contains SPDM-specific
/// certificate information. The extension value is a SEQUENCE of OIDs that
/// identify certificate characteristics (e.g., HARDWARE_IDENTITY, DEVICE_INFO).
pub const SPDM_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.6");

// =============================================================================
// Hash Algorithm OIDs (for SPDM algorithm negotiation)
// =============================================================================

/// SHA-256 - 2.16.840.1.101.3.4.2.1
pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// SHA-384 - 2.16.840.1.101.3.4.2.2
pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

/// SHA-512 - 2.16.840.1.101.3.4.2.3
pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// SHA3-256 - 2.16.840.1.101.3.4.2.8
pub const SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");

/// SHA3-384 - 2.16.840.1.101.3.4.2.9
pub const SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");

/// SHA3-512 - 2.16.840.1.101.3.4.2.10
pub const SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");

// =============================================================================
// Asymmetric Algorithm OIDs (for SPDM algorithm negotiation)
// =============================================================================

/// RSA Encryption - 1.2.840.113549.1.1.1
/// Used for RSA-2048, RSA-3072, and RSA-4096
pub const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// EC Public Key - 1.2.840.10045.2.1
/// Used as algorithm OID in SubjectPublicKeyInfo for ECDSA keys
pub const ECPUBLICKEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// ECDSA P-256 (secp256r1) - 1.2.840.10045.3.1.7
pub const ECDSA_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// ECDSA P-384 (secp384r1) - 1.3.132.0.34
pub const ECDSA_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// ECDSA P-521 (secp521r1) - 1.3.132.0.35
pub const ECDSA_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// EdDSA Ed25519 - 1.3.101.112
pub const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// EdDSA Ed448 - 1.3.101.113
pub const ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if an OID is an SPDM-related OID
///
/// # Arguments
/// * `oid` - The OID to check
///
/// # Returns
/// `true` if the OID starts with the SPDM base (1.3.6.1.4.1.412.274), `false` otherwise
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::oids;
/// assert!(oids::is_spdm_oid(&oids::SPDM_REQUESTER_AUTH));
/// assert!(!oids::is_spdm_oid(&oids::SHA256));
/// ```
pub fn is_spdm_oid(oid: &ObjectIdentifier) -> bool {
    // Check if the OID starts with the SPDM base (1.3.6.1.4.1.412.274)
    oid.as_bytes().starts_with(SPDM_BASE.as_bytes())
}

/// Check if an OID is the Hardware Identity OID
///
/// # Arguments
/// * `oid` - The OID to check
///
/// # Returns
/// `true` if the OID equals the Hardware Identity OID (1.3.6.1.4.1.412.274.2)
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::oids;
/// assert!(oids::is_hardware_identity(&oids::HARDWARE_IDENTITY));
/// ```
pub fn is_hardware_identity(oid: &ObjectIdentifier) -> bool {
    oid == &HARDWARE_IDENTITY
}

/// Check if an OID is the Device Info OID
///
/// # Arguments
/// * `oid` - The OID to check
///
/// # Returns
/// `true` if the OID equals the Device Info OID (1.3.6.1.4.1.412.274.1)
pub fn is_device_info(oid: &ObjectIdentifier) -> bool {
    oid == &DEVICE_INFO
}

/// Check if an OID is an SPDM EKU OID (Requester or Responder)
///
/// # Arguments
/// * `oid` - The OID to check
///
/// # Returns
/// `true` if the OID is either SPDM_REQUESTER_AUTH or SPDM_RESPONDER_AUTH
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::oids;
/// assert!(oids::is_spdm_eku(&oids::SPDM_REQUESTER_AUTH));
/// assert!(oids::is_spdm_eku(&oids::SPDM_RESPONDER_AUTH));
/// assert!(!oids::is_spdm_eku(&oids::SPDM_EXTENSION));
/// ```
pub fn is_spdm_eku(oid: &ObjectIdentifier) -> bool {
    oid == &SPDM_REQUESTER_AUTH || oid == &SPDM_RESPONDER_AUTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_device_info_oid() {
        assert_eq!(DEVICE_INFO.to_string(), "1.3.6.1.4.1.412.274.1");
    }

    #[test]
    fn test_hardware_identity_oid() {
        assert_eq!(HARDWARE_IDENTITY.to_string(), "1.3.6.1.4.1.412.274.2");
    }

    #[test]
    fn test_responder_auth_oid() {
        assert_eq!(SPDM_RESPONDER_AUTH.to_string(), "1.3.6.1.4.1.412.274.3");
    }

    #[test]
    fn test_requester_auth_oid() {
        assert_eq!(SPDM_REQUESTER_AUTH.to_string(), "1.3.6.1.4.1.412.274.4");
    }

    #[test]
    fn test_mutable_certificate_oid() {
        assert_eq!(MUTABLE_CERTIFICATE.to_string(), "1.3.6.1.4.1.412.274.5");
    }

    #[test]
    fn test_spdm_extension_oid() {
        assert_eq!(SPDM_EXTENSION.to_string(), "1.3.6.1.4.1.412.274.6");
    }

    #[test]
    fn test_is_spdm_oid() {
        assert!(is_spdm_oid(&SPDM_REQUESTER_AUTH));
        assert!(is_spdm_oid(&SPDM_RESPONDER_AUTH));
        assert!(is_spdm_oid(&SPDM_EXTENSION));
        assert!(is_spdm_oid(&HARDWARE_IDENTITY));
        assert!(!is_spdm_oid(&SHA256));
    }

    #[test]
    fn test_is_hardware_identity() {
        assert!(is_hardware_identity(&HARDWARE_IDENTITY));
        assert!(!is_hardware_identity(&SPDM_EXTENSION));
    }

    #[test]
    fn test_is_spdm_eku() {
        assert!(is_spdm_eku(&SPDM_REQUESTER_AUTH));
        assert!(is_spdm_eku(&SPDM_RESPONDER_AUTH));
        assert!(!is_spdm_eku(&SPDM_EXTENSION));
    }
}
