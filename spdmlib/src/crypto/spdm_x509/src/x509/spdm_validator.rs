// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM Certificate Validator
//!
//! Provides validation methods for SPDM certificates according to DSP0274.

extern crate alloc;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};

use super::extensions::{
    BasicConstraints, ExtendedKeyUsage, BASIC_CONSTRAINTS, EXTENDED_KEY_USAGE,
};
use super::validator::{ValidationOptions, Validator};
use crate::certificate::{Certificate, Extension};
use crate::error::{Error, ExtensionError, Result};

use super::oids;

// =============================================================================
// Helper function to find extensions
// =============================================================================

/// Find an extension by OID in a certificate
fn find_extension<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a Extension> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        exts.extensions.iter().find(|ext| &ext.extn_id == oid)
    } else {
        None
    }
}

// =============================================================================
// SPDM Certificate Model
// =============================================================================

/// SPDM Certificate Model (DSP0274 Section 10.6.1)
///
/// Defines the type/model of an SPDM certificate, which affects
/// validation requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpdmCertificateModel {
    /// Device Certificate - contains hardware identity
    ///
    /// Requirements:
    /// - MUST contain Hardware Identity OID in SPDM extension
    /// - Basic Constraints: cA = FALSE
    /// - Represents a physical device
    DeviceCert = 0,

    /// Alias Certificate - no hardware identity
    ///
    /// Requirements:
    /// - MUST NOT contain Hardware Identity OID
    /// - Basic Constraints: cA = FALSE
    /// - Represents a software instance
    AliasCert = 1,

    /// Generic Certificate - standard X.509 certificate
    ///
    /// Requirements:
    /// - Can be used for CA or intermediate certificates
    /// - Standard X.509 validation rules apply
    /// - Basic Constraints: cA may be TRUE or FALSE
    GenericCert = 2,
}

impl SpdmCertificateModel {
    /// Create from integer value
    pub fn from_value(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::DeviceCert),
            1 => Ok(Self::AliasCert),
            2 => Ok(Self::GenericCert),
            _ => Err(Error::ValidationError(alloc::format!(
                "Invalid SPDM certificate model: {}",
                value
            ))),
        }
    }

    /// Get the integer value
    pub fn value(&self) -> u8 {
        *self as u8
    }

    /// Get a human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::DeviceCert => "DeviceCert",
            Self::AliasCert => "AliasCert",
            Self::GenericCert => "GenericCert",
        }
    }
}

// =============================================================================
// SPDM Certificate Role
// =============================================================================

/// SPDM Certificate Role
///
/// Identifies whether a certificate is for a Requester or Responder.
/// This affects Extended Key Usage validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdmCertificateRole {
    /// Requester role - initiates SPDM communication
    Requester,

    /// Responder role - responds to SPDM requests
    Responder,
}

impl SpdmCertificateRole {
    /// Get a human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Requester => "Requester",
            Self::Responder => "Responder",
        }
    }
}

// =============================================================================
// SPDM Validator
// =============================================================================

/// SPDM Certificate Validator
///
/// Provides validation methods for SPDM certificates according to DSP0274.
/// Generic over the cryptographic backend, mirroring [`Validator<B>`].
pub struct SpdmValidator<B: crate::crypto_backend::CryptoBackend> {
    /// Underlying X.509 validator
    validator: Validator<B>,
}

#[cfg(feature = "ring-backend")]
impl SpdmValidator<crate::crypto_backend::RingBackend> {
    /// Create a new SPDM validator using the default Ring backend.
    pub fn new() -> Self {
        Self {
            validator: Validator::new(),
        }
    }
}

#[cfg(feature = "ring-backend")]
impl Default for SpdmValidator<crate::crypto_backend::RingBackend> {
    fn default() -> Self {
        Self::new()
    }
}

// `new()` and `Default` are only available with the ring backend.
// Without ring, callers must use `SpdmValidator::with_backend(backend)`.

impl<B: crate::crypto_backend::CryptoBackend> SpdmValidator<B> {
    /// Create a new SPDM validator with a specific crypto backend.
    pub fn with_backend(backend: B) -> Self {
        Self {
            validator: Validator::with_backend(backend),
        }
    }

    /// Validate a certificate chain using the inner X.509 validator.
    pub fn validate_chain(
        &self,
        chain: &crate::chain::CertificateChain,
        options: &ValidationOptions,
    ) -> Result<()> {
        self.validator.validate_chain(chain, options)
    }

    /// Validate an SPDM certificate with custom validation options
    ///
    /// Performs complete SPDM validation including:
    /// - Standard X.509 validation (with custom options)
    /// - SPDM EKU validation
    /// - SPDM extension validation
    /// - Hardware Identity validation
    /// - Basic Constraints validation per model
    /// - Algorithm verification
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The expected certificate model
    /// - `role`: The certificate role (Requester or Responder)
    /// - `base_asym_algo`: Negotiated SPDM base asymmetric algorithm (bitfield)
    /// - `base_hash_algo`: Negotiated SPDM base hash algorithm (bitfield)
    /// - `options`: Validation options (e.g., skip time validation)
    ///
    /// # Returns
    /// - `Ok(())` if validation succeeds
    /// - `Err(Error)` if validation fails
    pub fn validate_spdm_certificate_with_options(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
        role: SpdmCertificateRole,
        base_asym_algo: u32,
        base_hash_algo: u32,
        options: &ValidationOptions,
    ) -> Result<()> {
        // Perform standard X.509 validation first with custom options
        self.validator.validate(cert, options)?;

        // Validate SPDM-specific requirements
        self.validate_spdm_eku(cert, role)?;
        self.validate_spdm_extension(cert, model)?;
        self.validate_hardware_identity(cert, model)?;
        self.validate_basic_constraints_spdm(cert, model)?;

        // Validate algorithms match negotiated SPDM parameters
        self.validate_algorithms(cert, base_asym_algo, base_hash_algo)?;

        Ok(())
    }

    /// Validate an SPDM certificate
    ///
    /// Performs complete SPDM validation including:
    /// - Standard X.509 validation
    /// - SPDM EKU validation
    /// - SPDM extension validation
    /// - Hardware Identity validation
    /// - Basic Constraints validation per model
    /// - Algorithm verification
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The expected certificate model
    /// - `role`: The certificate role (Requester or Responder)
    /// - `base_asym_algo`: Negotiated SPDM base asymmetric algorithm (bitfield)
    /// - `base_hash_algo`: Negotiated SPDM base hash algorithm (bitfield)
    ///
    /// # Returns
    /// - `Ok(())` if validation succeeds
    /// - `Err(Error)` if validation fails
    pub fn validate_spdm_certificate(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
        role: SpdmCertificateRole,
        base_asym_algo: u32,
        base_hash_algo: u32,
    ) -> Result<()> {
        // Use default validation options
        let options = ValidationOptions::default();
        self.validate_spdm_certificate_with_options(
            cert,
            model,
            role,
            base_asym_algo,
            base_hash_algo,
            &options,
        )
    }

    /// Validate SPDM Extended Key Usage (EKU)
    ///
    /// # Validation Rules (DSP0274 Section 10.6.1.3)
    /// - If EKU extension is not present -> PASS
    /// - If Requester certificate contains ONLY Responder Auth OID -> FAIL
    /// - If Responder certificate contains ONLY Requester Auth OID -> FAIL
    /// - Otherwise -> PASS
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `role`: The certificate role
    ///
    /// # Returns
    /// - `Ok(())` if EKU validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_spdm_eku(&self, cert: &Certificate, role: SpdmCertificateRole) -> Result<()> {
        // Try to get the EKU extension
        let eku_ext = match find_extension(cert, &EXTENDED_KEY_USAGE) {
            Some(ext) => ext,
            None => return Ok(()), // No EKU extension is allowed
        };

        // Parse the EKU extension value
        let eku = ExtendedKeyUsage::from_extension(eku_ext).map_err(|e| {
            Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                "Failed to parse EKU: {:?}",
                e
            )))
        })?;

        // Check for SPDM EKU OIDs
        let has_requester = eku
            .key_purposes
            .iter()
            .any(|oid| oid == &oids::SPDM_REQUESTER_AUTH);
        let has_responder = eku
            .key_purposes
            .iter()
            .any(|oid| oid == &oids::SPDM_RESPONDER_AUTH);

        // Apply SPDM validation rules
        match role {
            SpdmCertificateRole::Requester => {
                // Requester cert MUST NOT contain ONLY Responder Auth OID
                if has_responder && !has_requester {
                    return Err(Error::ExtensionError(ExtensionError::ExtendedKeyUsage(
                        alloc::string::String::from(
                            "Requester certificate contains only Responder Auth EKU",
                        ),
                    )));
                }
            }
            SpdmCertificateRole::Responder => {
                // Responder cert MUST NOT contain ONLY Requester Auth OID
                if has_requester && !has_responder {
                    return Err(Error::ExtensionError(ExtensionError::ExtendedKeyUsage(
                        alloc::string::String::from(
                            "Responder certificate contains only Requester Auth EKU",
                        ),
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate SPDM Extension (OID 1.3.6.1.4.1.412.274.2)
    ///
    /// This extension contains SPDM-specific certificate information.
    /// The presence and content of this extension may be validated
    /// depending on the certificate model.
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The expected certificate model
    ///
    /// # Returns
    /// - `Ok(())` if extension validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_spdm_extension(
        &self,
        cert: &Certificate,
        _model: SpdmCertificateModel,
    ) -> Result<()> {
        // Try to get the SPDM extension
        let spdm_ext = match find_extension(cert, &oids::SPDM_EXTENSION) {
            Some(ext) => ext,
            None => return Ok(()), // SPDM extension is optional
        };

        // Parse the extension value: it MUST be a SEQUENCE OF ObjectIdentifier.
        // Verify that it is well-formed and every OID inside is a known SPDM
        // OID (under 1.3.6.1.4.1.412.274).  Unknown OIDs are logged but not
        // rejected so that future spec revisions remain forward-compatible.
        use der::{Decode, Header, Reader, SliceReader, Tag};

        let bytes = spdm_ext.extn_value.as_bytes();
        let mut reader = SliceReader::new(bytes).map_err(|e| {
            Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                "Invalid SPDM extension encoding: {:?}",
                e
            )))
        })?;

        let header = Header::decode(&mut reader).map_err(|e| {
            Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                "Invalid SPDM extension header: {:?}",
                e
            )))
        })?;

        if header.tag != Tag::Sequence {
            return Err(Error::ExtensionError(ExtensionError::InvalidEncoding(
                alloc::format!("Expected SEQUENCE in SPDM extension, got {:?}", header.tag),
            )));
        }

        reader
            .read_nested(header.length, |seq_reader| {
                while !seq_reader.is_finished() {
                    // Each element may be either a bare OID or a SEQUENCE { OID, ... }
                    // (DSP0274 Section 10.6.1 defines SpdmExtension ::= SEQUENCE { id OID, ... }).
                    let tag = seq_reader.peek_tag()?;
                    let oid = if tag == Tag::Sequence {
                        // Nested SEQUENCE — read header, then extract the leading OID.
                        let hdr = Header::decode(seq_reader)?;
                        seq_reader.read_nested(hdr.length, |inner| {
                            let id = ObjectIdentifier::decode(inner)?;
                            // Skip any remaining fields in this SpdmExtension entry.
                            while !inner.is_finished() {
                                let _: der::Any = Decode::decode(inner)?;
                            }
                            Ok(id)
                        })?
                    } else {
                        ObjectIdentifier::decode(seq_reader)?
                    };
                    if !oids::is_spdm_oid(&oid) {
                        log::warn!(
                            "Unknown OID in SPDM extension: {} (not under SPDM base)",
                            oid
                        );
                    }
                }
                Ok(())
            })
            .map_err(|e| {
                Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                    "Failed to parse SPDM extension OIDs: {:?}",
                    e
                )))
            })?;

        Ok(())
    }

    /// Validate Hardware Identity OID (1.3.6.1.4.1.412.274.4)
    ///
    /// # Validation Rules (DSP0274 Section 10.6.1.4)
    /// - **DeviceCert**: Hardware Identity OID MUST be present in SPDM extension
    /// - **AliasCert**: Hardware Identity OID MUST NOT be present
    /// - **GenericCert**: No specific requirement
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The certificate model
    ///
    /// # Returns
    /// - `Ok(())` if hardware identity validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_hardware_identity(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
    ) -> Result<()> {
        // Check if the certificate has the SPDM extension
        let spdm_ext = match find_extension(cert, &oids::SPDM_EXTENSION) {
            Some(ext) => ext,
            None => {
                // If DeviceCert, SPDM extension should be present
                if model == SpdmCertificateModel::DeviceCert {
                    return Err(Error::ExtensionError(
                        ExtensionError::MissingRequiredExtension(alloc::string::String::from(
                            "DeviceCert requires SPDM extension with Hardware Identity",
                        )),
                    ));
                }
                return Ok(());
            }
        };

        // Parse the SPDM extension to look for Hardware Identity OID
        // The extension value is a SEQUENCE of OIDs
        let has_hw_identity = self.check_hardware_identity_in_extension(&spdm_ext.extn_value)?;

        // Apply validation rules based on certificate model
        match model {
            SpdmCertificateModel::DeviceCert => {
                if !has_hw_identity {
                    return Err(Error::ExtensionError(
                        ExtensionError::MissingRequiredExtension(alloc::string::String::from(
                            "DeviceCert MUST contain Hardware Identity OID",
                        )),
                    ));
                }
            }
            SpdmCertificateModel::AliasCert => {
                if has_hw_identity {
                    return Err(Error::ExtensionError(ExtensionError::InvalidValue(
                        alloc::string::String::from(
                            "AliasCert MUST NOT contain Hardware Identity OID",
                        ),
                    )));
                }
            }
            SpdmCertificateModel::GenericCert => {
                // No specific requirement for GenericCert
            }
        }

        Ok(())
    }

    /// Check if Hardware Identity OID is present in SPDM extension.
    ///
    /// The SPDM extension value is an OCTET STRING containing a DER-encoded
    /// SEQUENCE OF ObjectIdentifier.  We parse this properly with the `der`
    /// crate instead of doing a raw byte-pattern search (which could
    /// false-positive on arbitrary DER content).
    fn check_hardware_identity_in_extension(
        &self,
        extn_value: &der::asn1::OctetString,
    ) -> Result<bool> {
        use const_oid::ObjectIdentifier;
        use der::{Decode, Header, Reader, SliceReader, Tag};

        let bytes = extn_value.as_bytes();

        let mut reader = SliceReader::new(bytes).map_err(|e| {
            Error::ExtensionError(crate::error::ExtensionError::InvalidEncoding(
                alloc::format!("Invalid SPDM extension encoding: {:?}", e),
            ))
        })?;

        // Read the outer SEQUENCE header
        let header = Header::decode(&mut reader).map_err(|e| {
            Error::ExtensionError(crate::error::ExtensionError::InvalidEncoding(
                alloc::format!("Invalid SPDM extension SEQUENCE header: {:?}", e),
            ))
        })?;

        if header.tag != Tag::Sequence {
            return Err(Error::ExtensionError(
                crate::error::ExtensionError::InvalidEncoding(alloc::format!(
                    "Expected SEQUENCE in SPDM extension, got {:?}",
                    header.tag
                )),
            ));
        }

        // Iterate over elements within the SEQUENCE.
        // Each element may be a bare OID or a SEQUENCE { OID, ... }.
        let mut found = false;
        reader
            .read_nested(header.length, |seq_reader| {
                while !seq_reader.is_finished() {
                    let tag = seq_reader.peek_tag()?;
                    let oid = if tag == Tag::Sequence {
                        let hdr = Header::decode(seq_reader)?;
                        seq_reader.read_nested(hdr.length, |inner| {
                            let id = ObjectIdentifier::decode(inner)?;
                            while !inner.is_finished() {
                                let _: der::Any = Decode::decode(inner)?;
                            }
                            Ok(id)
                        })?
                    } else {
                        ObjectIdentifier::decode(seq_reader)?
                    };
                    if oid == oids::HARDWARE_IDENTITY {
                        found = true;
                    }
                }
                Ok(())
            })
            .map_err(|e| {
                Error::ExtensionError(crate::error::ExtensionError::InvalidEncoding(
                    alloc::format!("Failed to parse SPDM extension OIDs: {:?}", e),
                ))
            })?;

        Ok(found)
    }

    /// Validate Basic Constraints per SPDM certificate model
    ///
    /// # Validation Rules
    /// - **DeviceCert**: cA MUST be FALSE
    /// - **AliasCert**: cA MUST be FALSE
    /// - **GenericCert**: cA may be TRUE or FALSE (for CA or end-entity)
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The certificate model
    ///
    /// # Returns
    /// - `Ok(())` if Basic Constraints validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_basic_constraints_spdm(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
    ) -> Result<()> {
        // Get the Basic Constraints extension
        let bc_ext = match find_extension(cert, &BASIC_CONSTRAINTS) {
            Some(ext) => ext,
            None => {
                // No Basic Constraints extension
                // For DeviceCert and AliasCert, cA defaults to FALSE, which is correct
                // For GenericCert, it depends on usage
                return Ok(());
            }
        };

        // Parse the Basic Constraints
        let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes()).map_err(|e| {
            Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                "Failed to parse Basic Constraints: {:?}",
                e
            )))
        })?;

        // Apply validation rules based on certificate model
        match model {
            SpdmCertificateModel::DeviceCert | SpdmCertificateModel::AliasCert => {
                if bc.ca {
                    return Err(Error::ExtensionError(ExtensionError::BasicConstraints(
                        alloc::format!("{} MUST have cA=FALSE in Basic Constraints", model.name()),
                    )));
                }
            }
            SpdmCertificateModel::GenericCert => {
                // GenericCert can have either cA=TRUE or cA=FALSE
                // No specific validation required
            }
        }

        Ok(())
    }

    /// Validate certificate algorithms against negotiated SPDM algorithms
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `base_asym_algo`: Negotiated SPDM base asymmetric algorithm (bitfield)
    /// - `base_hash_algo`: Negotiated SPDM base hash algorithm (bitfield)
    ///
    /// # Returns
    /// - `Ok(())` if algorithm validation passes
    /// - `Err(AlgorithmError)` if validation fails
    fn validate_algorithms(
        &self,
        cert: &Certificate,
        base_asym_algo: u32,
        base_hash_algo: u32,
    ) -> Result<()> {
        use super::signature::{verify_ecc_curve, verify_rsa_key_size, verify_signature_algorithm};

        // Verify signature algorithm
        verify_signature_algorithm(
            &cert.signature_algorithm.oid,
            base_asym_algo,
            base_hash_algo,
        )?;

        // Verify public key algorithm
        let pk_algo_oid = &cert.tbs_certificate.subject_public_key_info.algorithm.oid;

        // Check if it's RSA or ECC
        if pk_algo_oid == &oids::RSA {
            // Verify RSA key size
            // For RSA, we need the full SubjectPublicKeyInfo DER encoding
            let pk_der = cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|e| {
                    Error::ValidationError(alloc::format!("Failed to encode public key: {:?}", e))
                })?;
            verify_rsa_key_size(&pk_der, base_asym_algo)?;
        } else {
            // Try to get the curve OID for ECC
            if let Some(params) = &cert
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .parameters
            {
                // Parameters for ECC contain the curve OID
                // The parameters are already a der::Any, which we can try to decode as an OID
                if let Ok(curve_oid) = ObjectIdentifier::from_der(params.value()) {
                    verify_ecc_curve(&curve_oid, base_asym_algo)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "ring-backend"))]
mod tests {
    extern crate std;
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    #[test]
    fn test_certificate_model() {
        assert_eq!(SpdmCertificateModel::DeviceCert.value(), 0);
        assert_eq!(SpdmCertificateModel::AliasCert.value(), 1);
        assert_eq!(SpdmCertificateModel::GenericCert.value(), 2);

        assert_eq!(
            SpdmCertificateModel::from_value(0).unwrap(),
            SpdmCertificateModel::DeviceCert
        );
        assert_eq!(
            SpdmCertificateModel::from_value(1).unwrap(),
            SpdmCertificateModel::AliasCert
        );
        assert_eq!(
            SpdmCertificateModel::from_value(2).unwrap(),
            SpdmCertificateModel::GenericCert
        );

        assert!(SpdmCertificateModel::from_value(3).is_err());
    }

    #[test]
    fn test_certificate_model_names() {
        assert_eq!(SpdmCertificateModel::DeviceCert.name(), "DeviceCert");
        assert_eq!(SpdmCertificateModel::AliasCert.name(), "AliasCert");
        assert_eq!(SpdmCertificateModel::GenericCert.name(), "GenericCert");
    }

    #[test]
    fn test_certificate_role_names() {
        assert_eq!(SpdmCertificateRole::Requester.name(), "Requester");
        assert_eq!(SpdmCertificateRole::Responder.name(), "Responder");
    }

    // ── Helpers ──

    fn load_cert(path: &str) -> Certificate {
        let der = std::fs::read(path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
        Certificate::from_der(&der).unwrap_or_else(|e| panic!("Failed to parse {}: {:?}", path, e))
    }

    fn test_key_path(relative: &str) -> String {
        format!(
            "{}/../../../../test_key/{}",
            env!("CARGO_MANIFEST_DIR"),
            relative
        )
    }

    // ── validate_spdm_eku ──

    #[test]
    fn test_spdm_eku_responder_cert_with_rsp_eku_passes() {
        let cert = load_cert(&test_key_path(
            "ecp256/end_responder_with_spdm_rsp_eku.cert.der",
        ));
        let validator = SpdmValidator::new();
        let result = validator.validate_spdm_eku(&cert, SpdmCertificateRole::Responder);
        assert!(
            result.is_ok(),
            "rsp EKU on responder role should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_spdm_eku_responder_cert_with_req_only_eku_rejected() {
        let cert = load_cert(&test_key_path(
            "ecp256/end_responder_with_spdm_req_eku.cert.der",
        ));
        let validator = SpdmValidator::new();
        let result = validator.validate_spdm_eku(&cert, SpdmCertificateRole::Responder);
        assert!(
            result.is_err(),
            "req-only EKU on responder role should be rejected"
        );
    }

    #[test]
    fn test_spdm_eku_responder_cert_with_both_eku_passes() {
        let cert = load_cert(&test_key_path(
            "ecp256/end_responder_with_spdm_req_rsp_eku.cert.der",
        ));
        let validator = SpdmValidator::new();
        let result = validator.validate_spdm_eku(&cert, SpdmCertificateRole::Responder);
        assert!(
            result.is_ok(),
            "both EKUs on responder role should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_spdm_eku_requester_cert_with_req_eku_passes() {
        let cert = load_cert(&test_key_path(
            "ecp256/end_requester_with_spdm_req_eku.cert.der",
        ));
        let validator = SpdmValidator::new();
        let result = validator.validate_spdm_eku(&cert, SpdmCertificateRole::Requester);
        assert!(
            result.is_ok(),
            "req EKU on requester role should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_spdm_eku_requester_cert_with_rsp_only_eku_rejected() {
        let cert = load_cert(&test_key_path(
            "ecp256/end_responder_with_spdm_rsp_eku.cert.der",
        ));
        let validator = SpdmValidator::new();
        let result = validator.validate_spdm_eku(&cert, SpdmCertificateRole::Requester);
        assert!(
            result.is_err(),
            "rsp-only EKU on requester role should be rejected"
        );
    }

    #[test]
    fn test_spdm_eku_no_eku_extension_passes() {
        // CA cert typically has no EKU
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        assert!(validator
            .validate_spdm_eku(&cert, SpdmCertificateRole::Responder)
            .is_ok());
        assert!(validator
            .validate_spdm_eku(&cert, SpdmCertificateRole::Requester)
            .is_ok());
    }

    // ── validate_spdm_extension ──

    #[test]
    fn test_spdm_extension_absent_passes() {
        // CA cert has no SPDM extension
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        let result = validator.validate_spdm_extension(&cert, SpdmCertificateModel::GenericCert);
        assert!(result.is_ok());
    }

    // ── validate_hardware_identity ──

    #[test]
    fn test_hw_identity_generic_cert_no_spdm_ext_passes() {
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        let result = validator.validate_hardware_identity(&cert, SpdmCertificateModel::GenericCert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hw_identity_device_cert_without_spdm_ext_rejected() {
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        let result = validator.validate_hardware_identity(&cert, SpdmCertificateModel::DeviceCert);
        assert!(result.is_err(), "DeviceCert without SPDM ext should fail");
    }

    // ── validate_basic_constraints_spdm ──

    #[test]
    fn test_bc_spdm_device_cert_with_ca_true_rejected() {
        // CA cert has cA=TRUE
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        let result =
            validator.validate_basic_constraints_spdm(&cert, SpdmCertificateModel::DeviceCert);
        assert!(result.is_err(), "DeviceCert with cA=TRUE should fail");
    }

    #[test]
    fn test_bc_spdm_alias_cert_with_ca_true_rejected() {
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        let result =
            validator.validate_basic_constraints_spdm(&cert, SpdmCertificateModel::AliasCert);
        assert!(result.is_err(), "AliasCert with cA=TRUE should fail");
    }

    #[test]
    fn test_bc_spdm_generic_cert_ca_true_passes() {
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        let result =
            validator.validate_basic_constraints_spdm(&cert, SpdmCertificateModel::GenericCert);
        assert!(
            result.is_ok(),
            "GenericCert allows cA=TRUE: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_bc_spdm_device_cert_ca_false_passes() {
        // end_responder.cert.der has CA:FALSE — should pass for DeviceCert
        let cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = SpdmValidator::new();
        let result =
            validator.validate_basic_constraints_spdm(&cert, SpdmCertificateModel::DeviceCert);
        assert!(
            result.is_ok(),
            "DeviceCert with cA=FALSE should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_bc_spdm_no_bc_extension_passes() {
        // Cert without BC — defaults to cA=FALSE which is fine
        let cert = load_cert(&test_key_path(
            "ecp256/end_requester_without_basic_constraint.cert.der",
        ));
        let validator = SpdmValidator::new();
        assert!(validator
            .validate_basic_constraints_spdm(&cert, SpdmCertificateModel::DeviceCert)
            .is_ok());
        assert!(validator
            .validate_basic_constraints_spdm(&cert, SpdmCertificateModel::AliasCert)
            .is_ok());
    }

    // ── validate_spdm_certificate (full validation) ──

    #[test]
    fn test_validate_spdm_certificate_ecp256_generic() {
        let cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = SpdmValidator::new();
        let opts = ValidationOptions::default().skip_time_validation();
        let asym = 1u32 << 4; // EcdsaP256
        let hash = 1u32 << 0; // SHA-256
        let result = validator.validate_spdm_certificate_with_options(
            &cert,
            SpdmCertificateModel::GenericCert,
            SpdmCertificateRole::Responder,
            asym,
            hash,
            &opts,
        );
        assert!(
            result.is_ok(),
            "full SPDM validation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_spdm_certificate_wrong_asym_rejected() {
        let cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = SpdmValidator::new();
        let opts = ValidationOptions::default().skip_time_validation();
        let asym = 1u32 << 0; // RsaSsa2048 — wrong for ECC cert
        let hash = 1u32 << 0; // SHA-256
        let result = validator.validate_spdm_certificate_with_options(
            &cert,
            SpdmCertificateModel::GenericCert,
            SpdmCertificateRole::Responder,
            asym,
            hash,
            &opts,
        );
        assert!(result.is_err(), "wrong asym algo should be rejected");
    }

    // ── validate_chain via SpdmValidator ──

    #[test]
    fn test_spdm_validator_validate_chain() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        let chain = crate::chain::CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = SpdmValidator::new();
        let result = validator.validate_chain(&chain, &opts);
        assert!(
            result.is_ok(),
            "SpdmValidator chain failed: {:?}",
            result.err()
        );
    }
}
