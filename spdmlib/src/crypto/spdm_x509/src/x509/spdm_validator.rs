// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM Certificate Validator
//!
//! Provides validation methods for SPDM certificates according to DSP0274.

extern crate alloc;

use const_oid::ObjectIdentifier;
use der::Decode;

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
    /// - `base_hash_algo`: Retained for compatibility; does not constrain issuer signatures
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
    /// - `base_hash_algo`: Retained for compatibility; does not constrain issuer signatures
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
        _base_hash_algo: u32,
    ) -> Result<()> {
        super::signature::verify_public_key_algorithm(
            &cert.tbs_certificate.subject_public_key_info,
            base_asym_algo,
            0,
        )
    }
}

/// Check the leaf key of a root-to-leaf chain against the selected classical or
/// ML-DSA authentication algorithm. Does not verify signatures or trust.
pub fn validate_spdm_certificate_chain_algorithms(
    cert_chain: &[u8],
    base_asym_algo: u32,
    pqc_asym_algo: u32,
) -> Result<()> {
    let certificates = super::chain::parse_concatenated_certificates(cert_chain)?;
    let leaf = certificates
        .last()
        .ok_or(Error::ChainError(crate::error::ChainError::EmptyChain))?;
    super::signature::verify_public_key_algorithm(
        &leaf.tbs_certificate.subject_public_key_info,
        base_asym_algo,
        pqc_asym_algo,
    )
}

// =============================================================================
// Backend-free helpers
//
// SPDM hardware-identity validation inspects only X.509 extension bytes and
// performs no cryptographic operation, so it does not need a `CryptoBackend`.
// Exposing it as a free function lets callers (e.g. spdmlib's
// check_leaf_certificate) validate the DeviceCert/AliasCert HW-identity rules
// without instantiating `SpdmValidator<B>` for a specific backend — which is
// what allows a build with no classical backend (standalone aws-lc) to compile
// without referencing `RingBackend`.
// =============================================================================

/// Check DSP0274 1.4.0 Table 48 certificate fields in a root-to-leaf DER chain.
///
/// Every certificate must be v3 with a positive serial number. Issuers must
/// contain Basic Constraints with cA=TRUE; the leaf must contain cA=FALSE.
/// DeviceCert/AliasCert leaves require digitalSignature Key Usage, while
/// GenericCert leaves may omit Key Usage. Leaves must not assert keyCertSign.
/// Present Extended Key Usage must be well-formed and nonempty.
///
/// This checks fields only, not signatures, trust, time, EKU purpose, model negotiation,
/// or the remaining SPDM extension and algorithm requirements.
pub fn validate_spdm14_certificate_chain_fields(
    cert_chain: &[u8],
    model: SpdmCertificateModel,
) -> Result<()> {
    use super::chain::parse_concatenated_certificates;
    use super::extensions::{KeyUsage, KEY_USAGE};
    use crate::certificate::Version;
    use crate::error::{ChainError, ParseError};

    let certificates = parse_concatenated_certificates(cert_chain)?;
    if certificates.is_empty() {
        return Err(Error::ChainError(ChainError::EmptyChain));
    }
    if certificates.len() > ValidationOptions::default().max_chain_depth {
        return Err(Error::ChainError(ChainError::ChainTooLong));
    }

    for (index, cert) in certificates.iter().enumerate() {
        let is_leaf = index + 1 == certificates.len();

        if cert.tbs_certificate.version != Version::V3 {
            return Err(Error::InvalidVersion(cert.tbs_certificate.version.value()));
        }
        // DER decoding rejects negative INTEGERs; zero needs an explicit check.
        if cert.serial_number().iter().all(|byte| *byte == 0) {
            return Err(Error::ParseError(ParseError::InvalidInteger(
                "SPDM certificate serial number must be positive".into(),
            )));
        }

        if let Some(ext) = find_extension(cert, &EXTENDED_KEY_USAGE) {
            let eku = ExtendedKeyUsage::from_extension(ext).map_err(|e| {
                Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                    "Invalid Extended Key Usage: {:?}",
                    e
                )))
            })?;
            if eku.key_purposes.is_empty() {
                return Err(Error::ExtensionError(ExtensionError::InvalidEncoding(
                    "Extended Key Usage must contain at least one purpose".into(),
                )));
            }
        }

        let bc_ext = find_extension(cert, &BASIC_CONSTRAINTS).ok_or_else(|| {
            Error::ExtensionError(ExtensionError::MissingRequiredExtension(
                "Basic Constraints".into(),
            ))
        })?;
        let bc = BasicConstraints::from_extension(bc_ext).map_err(|e| {
            Error::ExtensionError(ExtensionError::BasicConstraints(alloc::format!(
                "Invalid Basic Constraints: {:?}",
                e
            )))
        })?;
        if is_leaf {
            if bc.ca || bc.path_len_constraint.is_some() {
                return Err(Error::ExtensionError(ExtensionError::BasicConstraints(
                    "SPDM leaf must have cA=FALSE and no pathLenConstraint".into(),
                )));
            }
            match find_extension(cert, &KEY_USAGE) {
                Some(ext) => {
                    let ku = KeyUsage::from_extension(ext).map_err(|e| {
                        Error::ExtensionError(ExtensionError::KeyUsage(alloc::format!(
                            "Invalid leaf Key Usage: {:?}",
                            e
                        )))
                    })?;
                    if !ku.has(KeyUsage::DIGITAL_SIGNATURE) || ku.has(KeyUsage::KEY_CERT_SIGN) {
                        return Err(Error::ExtensionError(ExtensionError::KeyUsage(
                            "SPDM leaf Key Usage must include digitalSignature without keyCertSign"
                                .into(),
                        )));
                    }
                }
                None if model != SpdmCertificateModel::GenericCert => {
                    return Err(Error::ExtensionError(
                        ExtensionError::MissingRequiredExtension("Key Usage".into()),
                    ));
                }
                None => {}
            }
        } else if !bc.ca {
            return Err(Error::ChainError(ChainError::IssuerNotCA));
        }
    }
    Ok(())
}

/// Validate the SPDM Hardware Identity OID rules for a certificate model
/// (DSP0274 Section 10.6.1.4), without requiring a crypto backend.
///
/// - **DeviceCert**: the SPDM extension with the Hardware Identity OID MUST be present.
/// - **AliasCert**: the Hardware Identity OID MUST NOT be present.
/// - **GenericCert**: no requirement.
pub fn validate_hardware_identity(cert: &Certificate, model: SpdmCertificateModel) -> Result<()> {
    let spdm_ext = match find_extension(cert, &oids::SPDM_EXTENSION) {
        Some(ext) => ext,
        None => {
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

    let has_hw_identity = check_hardware_identity_in_extension(&spdm_ext.extn_value)?;

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
                    alloc::string::String::from("AliasCert MUST NOT contain Hardware Identity OID"),
                )));
            }
        }
        SpdmCertificateModel::GenericCert => {}
    }

    Ok(())
}

/// Returns `true` if the SPDM extension OCTET STRING (a DER SEQUENCE OF OID)
/// contains the Hardware Identity OID.
fn check_hardware_identity_in_extension(extn_value: &der::asn1::OctetString) -> Result<bool> {
    use const_oid::ObjectIdentifier;
    use der::{Decode, Header, Reader, SliceReader, Tag};

    let bytes = extn_value.as_bytes();

    let mut reader = SliceReader::new(bytes).map_err(|e| {
        Error::ExtensionError(crate::error::ExtensionError::InvalidEncoding(
            alloc::format!("Invalid SPDM extension encoding: {:?}", e),
        ))
    })?;

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

    #[test]
    fn test_selected_key_algorithms_do_not_constrain_issuer_signatures() {
        let cert = load_cert(&test_key_path("ecp256/end_responder_rsa_issuer.cert.der"));
        let validator = SpdmValidator::new();
        for hash in [1, 2, 4] {
            validator.validate_algorithms(&cert, 1 << 4, hash).unwrap();
        }
        assert!(matches!(
            validator.validate_algorithms(&cert, 1 << 7, 1),
            Err(Error::AlgorithmError(
                crate::error::AlgorithmError::Unsupported(_)
            ))
        ));
        let mut chain = std::fs::read(test_key_path("rsa2048/ca.cert.der")).unwrap();
        chain.extend(std::fs::read(test_key_path("rsa2048/inter.cert.der")).unwrap());
        chain.extend(cert.to_der().unwrap());
        for hash in [None, Some(1), Some(2), Some(4)] {
            super::super::chain::verify_cert_chain_with_backend_and_role(
                &chain,
                crate::crypto_backend::RingBackend,
                Some(1 << 4),
                hash,
                SpdmCertificateRole::Responder,
            )
            .unwrap();
            assert!(matches!(
                super::super::chain::verify_cert_chain_with_backend_and_role(
                    &chain,
                    crate::crypto_backend::RingBackend,
                    Some(1 << 7),
                    hash,
                    SpdmCertificateRole::Responder,
                ),
                Err(Error::AlgorithmError(
                    crate::error::AlgorithmError::Unsupported(_)
                ))
            ));
        }
        *chain.last_mut().unwrap() ^= 1;
        assert!(matches!(
            super::super::chain::verify_cert_chain_with_backend_and_role(
                &chain,
                crate::crypto_backend::RingBackend,
                Some(1 << 4),
                Some(1),
                SpdmCertificateRole::Responder,
            ),
            Err(Error::SignatureError(_))
        ));
        assert!(matches!(
            validate_spdm_certificate_chain_algorithms(&[], 1 << 4, 0),
            Err(Error::ChainError(crate::error::ChainError::EmptyChain))
        ));
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

    fn field_chain(certs: &[Certificate]) -> alloc::vec::Vec<u8> {
        certs
            .iter()
            .flat_map(|cert| cert.to_der().unwrap())
            .collect()
    }

    fn replace_field_extension(
        cert: &mut Certificate,
        oid: ObjectIdentifier,
        value: Option<&[u8]>,
    ) {
        let extensions = cert
            .tbs_certificate
            .extensions
            .get_or_insert_with(crate::certificate::Extensions::new);
        extensions.extensions.retain(|ext| ext.extn_id != oid);
        if let Some(value) = value {
            extensions.push(Extension::new(oid, false, value.to_vec()).unwrap());
        }
    }

    fn with_serial(cert: &Certificate, serial: &[u8]) -> Certificate {
        let mut result = cert.clone();
        let tbs = &cert.tbs_certificate;
        result.tbs_certificate = crate::certificate::TBSCertificate::new(
            serial.to_vec(),
            tbs.signature.clone(),
            tbs.issuer.clone(),
            tbs.validity.clone(),
            tbs.subject.clone(),
            tbs.subject_public_key_info.clone(),
        );
        result.tbs_certificate.extensions = tbs.extensions.clone();
        result
    }

    #[test]
    fn test_spdm14_leaf_field_matrix() {
        use super::super::extensions::KEY_USAGE;
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        for model in [
            SpdmCertificateModel::DeviceCert,
            SpdmCertificateModel::AliasCert,
            SpdmCertificateModel::GenericCert,
        ] {
            for (case, bc, ku, expected) in [
                (
                    "valid",
                    Some(&[0x30, 0][..]),
                    Some(&[3, 2, 7, 0x80][..]),
                    "ok",
                ),
                ("missing-bc", None, Some(&[3, 2, 7, 0x80][..]), "missing-bc"),
                (
                    "ca-leaf",
                    Some(&[0x30, 3, 1, 1, 0xff][..]),
                    Some(&[3, 2, 7, 0x80][..]),
                    "bc",
                ),
                (
                    "malformed-bc",
                    Some(&[0x30, 1, 0xff][..]),
                    Some(&[3, 2, 7, 0x80][..]),
                    "bc",
                ),
                (
                    "leaf-pathlen",
                    Some(&[0x30, 3, 2, 1, 0][..]),
                    Some(&[3, 2, 7, 0x80][..]),
                    "bc",
                ),
                ("missing-ku", Some(&[0x30, 0][..]), None, "missing-ku"),
                (
                    "wrong-ku",
                    Some(&[0x30, 0][..]),
                    Some(&[3, 2, 2, 4][..]),
                    "ku",
                ),
                (
                    "leaf-keycertsign",
                    Some(&[0x30, 0][..]),
                    Some(&[3, 2, 2, 0x84][..]),
                    "ku",
                ),
                (
                    "malformed-ku",
                    Some(&[0x30, 0][..]),
                    Some(&[3, 2, 8, 0x80][..]),
                    "ku",
                ),
            ] {
                let mut cert = leaf.clone();
                replace_field_extension(&mut cert, BASIC_CONSTRAINTS, bc);
                replace_field_extension(&mut cert, KEY_USAGE, ku);
                let result = validate_spdm14_certificate_chain_fields(&field_chain(&[cert]), model);
                let matches = match (expected, model, &result) {
                    ("ok", _, Ok(())) => true,
                    ("missing-ku", SpdmCertificateModel::GenericCert, Ok(())) => true,
                    (
                        "missing-ku",
                        _,
                        Err(Error::ExtensionError(ExtensionError::MissingRequiredExtension(name))),
                    ) => name == "Key Usage",
                    (
                        "missing-bc",
                        _,
                        Err(Error::ExtensionError(ExtensionError::MissingRequiredExtension(name))),
                    ) => name == "Basic Constraints",
                    ("bc", _, Err(Error::ExtensionError(ExtensionError::BasicConstraints(_)))) => {
                        true
                    }
                    ("ku", _, Err(Error::ExtensionError(ExtensionError::KeyUsage(_)))) => true,
                    _ => false,
                };
                assert!(matches, "{:?}/{}: {:?}", model, case, result);
            }
        }
    }

    #[test]
    fn test_spdm14_issuer_field_matrix() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        for position in 0..2 {
            for (value, expected) in [
                (Some(&[0x30, 3, 1, 1, 0xff][..]), "ok"),
                (None, "missing"),
                (Some(&[0x30, 0][..]), "not-ca"),
                (Some(&[0x30, 1, 0xff][..]), "malformed"),
            ] {
                let mut certs = [ca.clone(), inter.clone(), leaf.clone()];
                replace_field_extension(&mut certs[position], BASIC_CONSTRAINTS, value);
                let result = validate_spdm14_certificate_chain_fields(
                    &field_chain(&certs),
                    SpdmCertificateModel::DeviceCert,
                );
                let matches = matches!(
                    (expected, &result),
                    ("ok", Ok(()))
                        | (
                            "missing",
                            Err(Error::ExtensionError(
                                ExtensionError::MissingRequiredExtension(_)
                            ))
                        )
                        | (
                            "not-ca",
                            Err(Error::ChainError(crate::error::ChainError::IssuerNotCA))
                        )
                        | (
                            "malformed",
                            Err(Error::ExtensionError(ExtensionError::BasicConstraints(_)))
                        )
                );
                assert!(matches, "position {}/{}: {:?}", position, expected, result);
            }
        }
    }

    #[test]
    fn test_spdm14_version_and_serial_at_every_position() {
        use crate::certificate::Version;
        let certs = [
            load_cert(&test_key_path("ecp256/ca.cert.der")),
            load_cert(&test_key_path("ecp256/inter.cert.der")),
            load_cert(&test_key_path("ecp256/end_responder.cert.der")),
        ];
        for position in 0..certs.len() {
            for version in [Version::V1, Version::V2] {
                let mut mutated = certs.clone();
                mutated[position].tbs_certificate.version = version;
                let result = validate_spdm14_certificate_chain_fields(
                    &field_chain(&mutated),
                    SpdmCertificateModel::DeviceCert,
                );
                assert!(matches!(result, Err(Error::InvalidVersion(v)) if v == version.value()));
            }
            let mut mutated = certs.clone();
            mutated[position] = with_serial(&mutated[position], &[0]);
            assert!(matches!(
                validate_spdm14_certificate_chain_fields(
                    &field_chain(&mutated),
                    SpdmCertificateModel::DeviceCert
                ),
                Err(Error::ParseError(crate::error::ParseError::InvalidInteger(
                    _
                )))
            ));
            mutated[position] = with_serial(&certs[position], &[0x80]);
            assert!(
                validate_spdm14_certificate_chain_fields(
                    &field_chain(&mutated),
                    SpdmCertificateModel::DeviceCert,
                )
                .is_ok(),
                "positive serial requiring a sign octet must be accepted"
            );
        }
    }

    #[test]
    fn test_spdm14_der_boundaries_and_negative_serial() {
        let leaf = with_serial(
            &load_cert(&test_key_path("ecp256/end_responder.cert.der")),
            &[0x7f],
        );
        let der = field_chain(&[leaf]);
        let mut negative = der.clone();
        let serial = negative
            .windows(3)
            .position(|bytes| bytes == [2, 1, 0x7f])
            .unwrap();
        negative[serial + 2] = 0xff;
        let mut trailing = der.clone();
        trailing.push(0);
        let mut malformed = der.clone();
        malformed[0] = 0x31;
        for invalid in [
            &negative[..],
            &trailing[..],
            &malformed[..],
            &der[..der.len() - 1],
        ] {
            assert!(matches!(
                validate_spdm14_certificate_chain_fields(invalid, SpdmCertificateModel::DeviceCert),
                Err(Error::ParseError(_))
            ));
        }
        assert!(matches!(
            validate_spdm14_certificate_chain_fields(&[], SpdmCertificateModel::DeviceCert),
            Err(Error::ChainError(crate::error::ChainError::EmptyChain))
        ));
    }

    #[test]
    fn test_spdm14_profile_depth_bound() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let limit = ValidationOptions::default().max_chain_depth;
        let mut certs = vec![ca.clone(); limit - 1];
        certs.push(leaf);
        assert!(validate_spdm14_certificate_chain_fields(
            &field_chain(&certs),
            SpdmCertificateModel::DeviceCert,
        )
        .is_ok());
        certs.insert(0, ca);
        assert!(matches!(
            validate_spdm14_certificate_chain_fields(
                &field_chain(&certs),
                SpdmCertificateModel::DeviceCert,
            ),
            Err(Error::ChainError(crate::error::ChainError::ChainTooLong))
        ));
    }

    #[test]
    fn test_spdm14_malformed_eku_at_every_position() {
        let certs = [
            load_cert(&test_key_path("ecp256/ca.cert.der")),
            load_cert(&test_key_path("ecp256/inter.cert.der")),
            load_cert(&test_key_path("ecp256/end_responder.cert.der")),
        ];
        for position in 0..certs.len() {
            for value in [
                &[0x30, 0][..],
                &[0x30, 1, 0xff][..],
                &[0x30, 3, 6, 1, 0x80][..],
                &[0x30, 3, 6, 1][..],
            ] {
                let mut mutated = certs.clone();
                replace_field_extension(&mut mutated[position], EXTENDED_KEY_USAGE, Some(value));
                assert!(
                    matches!(
                        validate_spdm14_certificate_chain_fields(
                            &field_chain(&mutated),
                            SpdmCertificateModel::DeviceCert,
                        ),
                        Err(Error::ExtensionError(ExtensionError::InvalidEncoding(_)))
                    ),
                    "position {}/value {:?}",
                    position,
                    value
                );
            }
        }
    }
}
