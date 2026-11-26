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

#[cfg(test)]
impl SpdmValidator<crate::crypto_backend::RingBackend> {
    /// Create a new SPDM validator using the bundled test-only ring backend.
    pub fn new() -> Self {
        Self {
            validator: Validator::with_backend(crate::crypto_backend::RingBackend),
        }
    }
}

#[cfg(test)]
impl Default for SpdmValidator<crate::crypto_backend::RingBackend> {
    fn default() -> Self {
        Self::new()
    }
}

// `new()` and `Default` are only available with a default crypto backend.
// Without one, callers must use `SpdmValidator::with_backend(backend)`.

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
    /// # Validation Rules (DSP0274 Section 10.8.2)
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
        // EKU validation is a pure extension-byte inspection with no
        // cryptographic operation, so delegate to the backend-free free function.
        validate_spdm_eku(cert, role)
    }

    /// Validate SPDM Extension (OID 1.3.6.1.4.1.412.274.6) per DSP0274 §10.9.2.2.
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `_model`: The expected certificate model
    ///
    /// # Returns
    /// - `Ok(())` if extension validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_spdm_extension(
        &self,
        cert: &Certificate,
        _model: SpdmCertificateModel,
    ) -> Result<()> {
        validate_spdm_extension(cert)
    }

    /// Validate Hardware Identity OID (1.3.6.1.4.1.412.274.2)
    ///
    /// # Validation Rules (DSP0274 §7.2.1.1 and §10.9.2.2.1)
    /// - **DeviceCert**: Hardware Identity OID is RECOMMENDED (not mandatory)
    /// - **AliasCert**: Hardware Identity OID MUST NOT be present
    /// - **GenericCert**: No specific requirement
    /// - If present, the SPDM extension MUST satisfy DSP0274 §10.9.2.2 and the
    ///   Hardware Identity entry MUST NOT include a definition value.
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
        // Hardware-identity validation is a pure extension-byte inspection with no
        // cryptographic operation, so delegate to the backend-free free function.
        validate_hardware_identity(cert, model)
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
        use super::signature::{
            verify_ecc_key_params, verify_rsa_key_size, verify_signature_algorithm,
        };

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
        } else if pk_algo_oid == &oids::ECPUBLICKEY {
            // Parameters for ECC contain the curve OID
            verify_ecc_key_params(
                cert.tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .parameters
                    .as_ref(),
                base_asym_algo,
            )?;
        }

        Ok(())
    }
}

// =============================================================================
// Backend-free helpers
//
// SPDM hardware-identity and EKU validation inspect only X.509 extension bytes
// and perform no cryptographic operation, so they do not need a `CryptoBackend`.
// Exposing them as free functions lets callers (e.g. spdmlib's
// check_leaf_certificate) validate the HW-identity and EKU role rules
// without instantiating `SpdmValidator<B>` for a specific backend — which is
// what allows a build with no classical backend (standalone aws-lc) to compile
// without referencing `RingBackend`.
// =============================================================================

/// Parse and strictly validate an `id-DMTF-spdm-extension` (`1.3.6.1.4.1.412.274.6`)
/// extension per DSP0274 §10.9.2.2 and §10.9.2.2.1.
///
/// ASN.1 grammar:
/// ```text
/// SpdmExtension ::= SEQUENCE SIZE (1..MAX) OF SpdmExtensionEntry
/// SpdmExtensionEntry ::= SEQUENCE {
///     oid        OBJECT IDENTIFIER,
///     definition ANY DEFINED BY oid OPTIONAL
/// }
/// ```
///
/// Enforces:
/// - The X.509 extension MUST be non-critical.
/// - Outer DER SEQUENCE is non-empty with no trailing bytes.
/// - Every entry is a nested SEQUENCE (bare OIDs are rejected) containing an
///   OID and at most one optional definition value (no trailing fields).
/// - `id-DMTF-hardware-identity` (`1.3.6.1.4.1.412.274.2`) MUST NOT carry a
///   definition value.
fn parse_spdm_extension(ext: &Extension) -> Result<alloc::vec::Vec<ObjectIdentifier>> {
    use der::{Decode, Header, Reader, SliceReader, Tag};

    if ext.critical {
        return Err(Error::ExtensionError(ExtensionError::InvalidValue(
            alloc::string::String::from("SPDM extension MUST be non-critical"),
        )));
    }

    let bytes = ext.extn_value.as_bytes();
    let mut reader = SliceReader::new(bytes).map_err(|e| {
        Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
            "Invalid SPDM extension encoding: {:?}",
            e
        )))
    })?;

    let header = Header::decode(&mut reader).map_err(|e| {
        Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
            "Invalid SPDM extension SEQUENCE header: {:?}",
            e
        )))
    })?;

    if header.tag != Tag::Sequence {
        return Err(Error::ExtensionError(ExtensionError::InvalidEncoding(
            alloc::format!("Expected SEQUENCE in SPDM extension, got {:?}", header.tag),
        )));
    }

    let mut entries: alloc::vec::Vec<(ObjectIdentifier, bool)> = alloc::vec::Vec::new();
    reader
        .read_nested(header.length, |seq_reader| {
            while !seq_reader.is_finished() {
                let entry_hdr = Header::decode(seq_reader)?;
                if entry_hdr.tag != Tag::Sequence {
                    return Err(der::Error::new(
                        der::ErrorKind::TagUnexpected {
                            expected: Some(Tag::Sequence),
                            actual: entry_hdr.tag,
                        },
                        seq_reader.position(),
                    ));
                }
                let entry = seq_reader.read_nested(entry_hdr.length, |inner| {
                    let oid = ObjectIdentifier::decode(inner)?;
                    let has_definition = if !inner.is_finished() {
                        let _: der::Any = Decode::decode(inner)?;
                        true
                    } else {
                        false
                    };
                    if !inner.is_finished() {
                        return Err(der::Error::new(
                            der::ErrorKind::TrailingData {
                                decoded: inner.position(),
                                remaining: inner.remaining_len(),
                            },
                            inner.position(),
                        ));
                    }
                    Ok((oid, has_definition))
                })?;
                entries.push(entry);
            }
            Ok(())
        })
        .map_err(|e| {
            Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                "Failed to parse SPDM extension entries: {:?}",
                e
            )))
        })?;

    if !reader.is_finished() {
        return Err(Error::ExtensionError(ExtensionError::InvalidEncoding(
            alloc::string::String::from("Trailing bytes after SPDM extension SEQUENCE"),
        )));
    }

    if entries.is_empty() {
        return Err(Error::ExtensionError(ExtensionError::InvalidEncoding(
            alloc::string::String::from("SPDM extension must contain at least one entry"),
        )));
    }

    let mut oids_out = alloc::vec::Vec::with_capacity(entries.len());
    for (oid, has_definition) in entries {
        if oid == oids::HARDWARE_IDENTITY && has_definition {
            return Err(Error::ExtensionError(ExtensionError::InvalidValue(
                alloc::string::String::from(
                    "Hardware Identity OID must not include a definition value",
                ),
            )));
        }
        if !oids::is_spdm_oid(&oid) {
            log::warn!(
                "Unknown OID in SPDM extension: {} (not under SPDM base)",
                oid
            );
        }
        oids_out.push(oid);
    }

    Ok(oids_out)
}

/// Validate the optional SPDM extension (`1.3.6.1.4.1.412.274.6`) per
/// DSP0274 §10.9.2.2, without requiring a crypto backend.
pub fn validate_spdm_extension(cert: &Certificate) -> Result<()> {
    let Some(spdm_ext) = find_extension(cert, &oids::SPDM_EXTENSION) else {
        return Ok(());
    };
    parse_spdm_extension(spdm_ext).map(|_| ())
}

/// Validate the SPDM Hardware Identity OID rules for a certificate model
/// (DSP0274 §7.2.1.1 and §10.9.2.2.1), without requiring a crypto backend.
///
/// - Any present SPDM extension MUST be non-critical and canonically encoded
///   per DSP0274 §10.9.2.2, and Hardware Identity MUST have no definition value.
/// - **DeviceCert**: Hardware Identity is RECOMMENDED (not mandatory); absence
///   is accepted.
/// - **AliasCert**: Hardware Identity OID MUST NOT be present.
/// - **GenericCert**: no Hardware Identity presence requirement.
pub fn validate_hardware_identity(cert: &Certificate, model: SpdmCertificateModel) -> Result<()> {
    let spdm_ext = match find_extension(cert, &oids::SPDM_EXTENSION) {
        Some(ext) => ext,
        None => return Ok(()),
    };

    let oids = parse_spdm_extension(spdm_ext)?;
    let has_hw_identity = oids.iter().any(|oid| oid == &oids::HARDWARE_IDENTITY);

    if model == SpdmCertificateModel::AliasCert && has_hw_identity {
        return Err(Error::ExtensionError(ExtensionError::InvalidValue(
            alloc::string::String::from("AliasCert MUST NOT contain Hardware Identity OID"),
        )));
    }

    Ok(())
}

/// Validate SPDM extension syntax across every certificate in a root-to-leaf
/// DER chain and enforce Hardware Identity placement for `AliasCert` chains
/// (DSP0274 §7.2.1.1 and §10.9.2.2.1).
///
/// - Every certificate carrying `id-DMTF-spdm-extension` must satisfy
///   [`validate_spdm_extension`].
/// - For `AliasCert`:
///   - The leaf certificate MUST NOT contain the Hardware Identity OID.
///   - Once a DeviceCert CA in the chain asserts Hardware Identity, no
///     subordinate certificate below it (alias intermediate CA or alias leaf)
///     may assert Hardware Identity.
pub fn validate_chain_hardware_identity(
    cert_chain: &[u8],
    model: SpdmCertificateModel,
) -> Result<()> {
    let certificates = super::chain::parse_concatenated_certificates(cert_chain)?;
    if certificates.is_empty() {
        return Err(Error::ChainError(crate::error::ChainError::EmptyChain));
    }

    let mut seen_device_ca_hw_id = false;
    let last_idx = certificates.len() - 1;

    for (idx, cert) in certificates.iter().enumerate() {
        let Some(spdm_ext) = find_extension(cert, &oids::SPDM_EXTENSION) else {
            continue;
        };
        let oids = parse_spdm_extension(spdm_ext)?;
        let has_hw_identity = oids.iter().any(|oid| oid == &oids::HARDWARE_IDENTITY);

        if model == SpdmCertificateModel::AliasCert && has_hw_identity {
            if idx == last_idx {
                return Err(Error::ExtensionError(ExtensionError::InvalidValue(
                    alloc::string::String::from(
                        "AliasCert leaf MUST NOT contain Hardware Identity OID",
                    ),
                )));
            }
            if seen_device_ca_hw_id {
                return Err(Error::ExtensionError(ExtensionError::InvalidValue(
                    alloc::string::String::from(
                        "AliasCert subordinate certificate MUST NOT contain Hardware Identity OID",
                    ),
                )));
            }
            seen_device_ca_hw_id = true;
        }
    }

    Ok(())
}

/// Validate the SPDM Extended Key Usage rules for a certificate role
/// (DSP0274 Section 10.8.2), without requiring a crypto backend.
///
/// - No EKU extension: no requirement.
/// - **Requester**: MUST NOT contain only the Responder Auth OID.
/// - **Responder**: MUST NOT contain only the Requester Auth OID.
pub fn validate_spdm_eku(cert: &Certificate, role: SpdmCertificateRole) -> Result<()> {
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

#[cfg(test)]
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

    fn set_spdm_extension(cert: &mut Certificate, critical: bool, value: &[u8]) {
        let exts =
            cert.tbs_certificate
                .extensions
                .get_or_insert_with(|| crate::certificate::Extensions {
                    extensions: alloc::vec::Vec::new(),
                });
        exts.extensions
            .retain(|e| e.extn_id != oids::SPDM_EXTENSION);
        exts.extensions.push(Extension {
            extn_id: oids::SPDM_EXTENSION,
            critical,
            extn_value: der::asn1::OctetString::new(value).unwrap(),
        });
    }

    #[test]
    fn test_spdm_extension_absent_passes() {
        // CA cert has no SPDM extension
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        let result = validator.validate_spdm_extension(&cert, SpdmCertificateModel::GenericCert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_spdm_extension_canonical_nested_entries_pass() {
        // Real DeviceCert fixture carries canonical SEQUENCE { SEQUENCE { HARDWARE_IDENTITY } }
        let cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        assert!(validate_spdm_extension(&cert).is_ok());

        // Non-HW-ID SPDM OID with a single optional definition value (UTF8String "ok") is valid.
        let mut with_def = cert;
        // Outer SEQUENCE (0x30 0x12):
        //   Inner SEQUENCE (0x30 0x10):
        //     OID 1.3.6.1.4.1.412.274.1 (0x06 0x0a 2b 06 01 04 01 83 1c 82 12 01)
        //     UTF8String "ok" (0x0c 0x02 0x6f 0x6b)
        let canonical_with_def = [
            0x30, 0x12, 0x30, 0x10, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c, 0x82,
            0x12, 0x01, 0x0c, 0x02, 0x6f, 0x6b,
        ];
        set_spdm_extension(&mut with_def, false, &canonical_with_def);
        assert!(validate_spdm_extension(&with_def).is_ok());
    }

    #[test]
    fn test_spdm_extension_critical_is_rejected_by_validator() {
        let mut cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let canonical_hw_id = [
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c, 0x82,
            0x12, 0x02,
        ];
        set_spdm_extension(&mut cert, true, &canonical_hw_id);

        assert!(matches!(
            validate_spdm_extension(&cert),
            Err(Error::ExtensionError(ExtensionError::InvalidValue(_)))
        ));
        assert!(matches!(
            Validator::new().validate(
                &cert,
                &ValidationOptions::default().skip_signature_validation()
            ),
            Err(Error::ExtensionError(ExtensionError::InvalidValue(_)))
        ));
    }

    #[test]
    fn test_spdm_extension_malformed_encodings_rejected() {
        let base = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let cases: &[(&str, &[u8])] = &[
            // Empty outer SEQUENCE (violates SIZE (1..MAX))
            ("empty container", &[0x30, 0x00]),
            // Bare OID instead of nested SEQUENCE { OID }
            (
                "bare OID",
                &[
                    0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c, 0x82, 0x12,
                    0x02,
                ],
            ),
            // Trailing byte after outer SEQUENCE
            (
                "trailing outer byte",
                &[
                    0x30, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c,
                    0x82, 0x12, 0x02, 0x00,
                ],
            ),
            // Invalid / truncated OID inside entry
            ("invalid OID", &[0x30, 0x05, 0x30, 0x03, 0x06, 0x01, 0x80]),
            // Trailing third field inside SpdmExtensionEntry (OID + 2 values)
            (
                "trailing entry field",
                &[
                    0x30, 0x12, 0x30, 0x10, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c,
                    0x82, 0x12, 0x01, 0x05, 0x00, 0x05, 0x00,
                ],
            ),
            // Non-SEQUENCE outer tag
            ("non-sequence outer", &[0x05, 0x00]),
        ];

        for (name, bytes) in cases {
            let mut cert = base.clone();
            set_spdm_extension(&mut cert, false, bytes);
            assert!(
                matches!(
                    validate_spdm_extension(&cert),
                    Err(Error::ExtensionError(ExtensionError::InvalidEncoding(_)))
                ),
                "case '{}' should fail with InvalidEncoding",
                name
            );
            assert!(
                Validator::new()
                    .validate(
                        &cert,
                        &ValidationOptions::default().skip_signature_validation()
                    )
                    .is_err(),
                "Validator must reject malformed SPDM extension '{}'",
                name
            );
        }
    }

    #[test]
    fn test_hw_identity_forbids_definition_bytes() {
        let mut cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        // SEQUENCE { SEQUENCE { HARDWARE_IDENTITY, NULL } }
        let hw_id_with_null = [
            0x30, 0x10, 0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c, 0x82,
            0x12, 0x02, 0x05, 0x00,
        ];
        set_spdm_extension(&mut cert, false, &hw_id_with_null);

        assert!(matches!(
            validate_spdm_extension(&cert),
            Err(Error::ExtensionError(ExtensionError::InvalidValue(_)))
        ));
        assert!(matches!(
            validate_hardware_identity(&cert, SpdmCertificateModel::DeviceCert),
            Err(Error::ExtensionError(ExtensionError::InvalidValue(_)))
        ));
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
    fn test_hw_identity_device_cert_without_spdm_ext_passes_per_dsp0274() {
        // DSP0274 §7.2.1.1 / §10.9.2.2.1 recommends (does not mandate) HW Identity on DeviceCert.
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = SpdmValidator::new();
        let result = validator.validate_hardware_identity(&cert, SpdmCertificateModel::DeviceCert);
        assert!(
            result.is_ok(),
            "DeviceCert without SPDM extension must be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_chain_hw_identity_alias_placement_rules() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let device_ca = load_cert(&test_key_path(
            "ecp256/end_responder_alias_cert_partial_set.cert.der",
        ));
        let alias_leaf = load_cert(&test_key_path("ecp256/end_responder_alias.cert.der"));
        let device_leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        let encode_chain = |certs: &[&Certificate]| -> alloc::vec::Vec<u8> {
            let mut out = alloc::vec::Vec::new();
            for c in certs {
                out.extend_from_slice(&c.to_der().unwrap());
            }
            out
        };

        // Valid alias chain: DeviceCert CA carries HW_ID, alias leaf does not.
        let valid_alias = encode_chain(&[&ca, &inter, &device_ca, &alias_leaf]);
        assert!(
            validate_chain_hardware_identity(&valid_alias, SpdmCertificateModel::AliasCert).is_ok()
        );

        // Alias leaf carrying HW_ID must be rejected.
        let bad_alias_leaf = encode_chain(&[&ca, &inter, &device_ca, &device_leaf]);
        assert!(matches!(
            validate_chain_hardware_identity(&bad_alias_leaf, SpdmCertificateModel::AliasCert),
            Err(Error::ExtensionError(ExtensionError::InvalidValue(_)))
        ));

        // Alias intermediate CA carrying HW_ID below a DeviceCert CA must be rejected.
        let bad_alias_sub_ca = encode_chain(&[&ca, &inter, &device_ca, &device_ca, &alias_leaf]);
        assert!(matches!(
            validate_chain_hardware_identity(&bad_alias_sub_ca, SpdmCertificateModel::AliasCert),
            Err(Error::ExtensionError(ExtensionError::InvalidValue(_)))
        ));
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
        let opts = ValidationOptions::default();
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
        let opts = ValidationOptions::default();
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

    #[test]
    fn test_validate_spdm_certificate_wrong_curve_rejected() {
        let cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = SpdmValidator::new();
        let opts = ValidationOptions::default();
        let asym = 1u32 << 7; // EcdsaP384 — wrong curve for a P-256 key
        let hash = 1u32 << 0; // SHA-256
        let result = validator.validate_spdm_certificate_with_options(
            &cert,
            SpdmCertificateModel::GenericCert,
            SpdmCertificateRole::Responder,
            asym,
            hash,
            &opts,
        );
        assert!(result.is_err(), "wrong ECC curve should be rejected");
    }

    // ── validate_chain via SpdmValidator ──

    #[test]
    fn test_spdm_validator_validate_chain() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        let chain = crate::chain::CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default();
        let validator = SpdmValidator::new();
        let result = validator.validate_chain(&chain, &opts);
        assert!(
            result.is_ok(),
            "SpdmValidator chain failed: {:?}",
            result.err()
        );
    }
}
