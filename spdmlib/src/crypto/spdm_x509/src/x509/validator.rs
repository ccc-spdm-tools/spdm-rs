// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Certificate validation and chain verification.
//!
//! This module provides certificate validation functionality including:
//! - Signature verification
//! - Validity period checking
//! - Certificate chain validation
//! - Extension validation

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::certificate::Certificate;
use crate::chain::CertificateChain;
#[cfg(feature = "ring-backend")]
use crate::crypto_backend::RingBackend;
use crate::crypto_backend::{CryptoBackend, SignatureAlgorithm};
use crate::error::{Error, Result};
use crate::time::Time;
use crate::x509::extensions::{
    BasicConstraints, KeyUsage, AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS, EXTENDED_KEY_USAGE,
    KEY_USAGE, SUBJECT_ALT_NAME, SUBJECT_KEY_IDENTIFIER, TCG_PLATFORM_CERTIFICATE,
};
use crate::x509::extensions::{HARDWARE_IDENTITY, SPDM_EXTENSION};
use const_oid::ObjectIdentifier;

// ============================================================================
// Validation Options
// ============================================================================

/// Options for certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Whether to check the certificate validity period
    pub check_time: bool,

    /// Whether to verify the certificate signature
    pub check_signature: bool,

    /// Whether to validate extensions
    pub check_extensions: bool,

    /// Maximum allowed certificate chain depth
    pub max_chain_depth: usize,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            check_time: !cfg!(feature = "no-time-check"),
            check_signature: true,
            check_extensions: true,
            max_chain_depth: 10,
        }
    }
}

impl ValidationOptions {
    /// Create a new ValidationOptions with all checks enabled
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable time validation (useful for testing)
    pub fn skip_time_validation(mut self) -> Self {
        self.check_time = false;
        self
    }

    /// Disable signature validation (useful for parsing-only scenarios)
    pub fn skip_signature_validation(mut self) -> Self {
        self.check_signature = false;
        self
    }

    /// Set the maximum chain depth
    pub fn with_max_chain_depth(mut self, depth: usize) -> Self {
        self.max_chain_depth = depth;
        self
    }
}

// ============================================================================
// Validator
// ============================================================================

/// Certificate validator.
pub struct Validator<B: CryptoBackend> {
    /// Crypto backend for signature verification
    backend: B,
    /// Cache of known extension OIDs for fast lookup
    known_extensions: Vec<ObjectIdentifier>,
}

#[cfg(feature = "ring-backend")]
impl Validator<RingBackend> {
    /// Create a new Validator with the Ring backend
    pub fn new() -> Self {
        Self::with_backend(RingBackend)
    }
}

impl<B: CryptoBackend> Validator<B> {
    /// Create a new Validator with a specific backend
    pub fn with_backend(backend: B) -> Self {
        let mut known_extensions = vec![
            BASIC_CONSTRAINTS,
            KEY_USAGE,
            EXTENDED_KEY_USAGE,
            SUBJECT_ALT_NAME,
            AUTHORITY_KEY_IDENTIFIER,
            SUBJECT_KEY_IDENTIFIER,
            // TCG extensions
            TCG_PLATFORM_CERTIFICATE,
        ];

        known_extensions.push(HARDWARE_IDENTITY);
        known_extensions.push(SPDM_EXTENSION);

        Self {
            backend,
            known_extensions,
        }
    }

    /// Validate a single certificate.
    pub fn validate(&self, cert: &Certificate, options: &ValidationOptions) -> Result<()> {
        // RFC 5280 §4.1.1.2: signatureAlgorithm MUST be identical to the
        // signature field in the TBSCertificate sequence.  Compare both OID
        // and parameters (the latter matters for RSA-PSS where the same OID
        // can carry different hash/MGF parameters).
        if cert.signature_algorithm.oid != cert.tbs_certificate.signature.oid {
            return Err(Error::SignatureError(
                crate::error::SignatureError::AlgorithmMismatch {
                    cert_algo: cert.signature_algorithm.oid.to_string(),
                    tbs_algo: cert.tbs_certificate.signature.oid.to_string(),
                },
            ));
        }
        {
            use der::Encode;
            let outer_params = cert
                .signature_algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.to_der().ok());
            let inner_params = cert
                .tbs_certificate
                .signature
                .parameters
                .as_ref()
                .and_then(|p| p.to_der().ok());
            if outer_params != inner_params {
                return Err(Error::SignatureError(
                    crate::error::SignatureError::AlgorithmMismatch {
                        cert_algo: alloc::format!("{} (with params)", cert.signature_algorithm.oid),
                        tbs_algo: alloc::format!(
                            "{} (with params)",
                            cert.tbs_certificate.signature.oid
                        ),
                    },
                ));
            }
        }

        if options.check_time {
            self.validate_time(cert)?;
        }

        if options.check_extensions {
            self.validate_extensions(cert)?;
        }

        Ok(())
    }

    /// Verify certificate signature against issuer's public key.
    pub fn verify_signature(&self, cert: &Certificate, issuer: &Certificate) -> Result<()> {
        log::trace!("verify_signature: starting signature verification");
        log::trace!("cert subject: {:?}", cert.tbs_certificate.subject);
        log::trace!("issuer subject: {:?}", issuer.tbs_certificate.subject);

        // Only attempt to decode curve OID for ECC keys; RSA parameters are
        // ASN.1 NULL and would produce a spurious decode failure.
        let pk_algo = &issuer.tbs_certificate.subject_public_key_info.algorithm.oid;
        let curve_oid = if *pk_algo == super::oids::ECPUBLICKEY {
            issuer
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
        } else {
            None
        };

        let sig_algo = match SignatureAlgorithm::from_oid_with_params(
            &cert.signature_algorithm.oid,
            curve_oid.as_ref(),
            cert.signature_algorithm.parameters.as_ref(),
        ) {
            Ok(algo) => {
                log::trace!("verify_signature: signature algorithm = {:?}", algo);
                algo
            }
            Err(e) => {
                log::error!(
                    "verify_signature: unsupported signature algorithm OID: {:?}",
                    cert.signature_algorithm.oid
                );
                return Err(e);
            }
        };

        let tbs_bytes = match cert.tbs_certificate.to_der() {
            Ok(bytes) => {
                log::trace!("verify_signature: TBS bytes length = {}", bytes.len());
                bytes
            }
            Err(e) => {
                log::error!(
                    "verify_signature: failed to encode TBS certificate: {:?}",
                    e
                );
                return Err(e);
            }
        };

        let signature = cert.signature_value.raw_bytes();
        log::trace!("verify_signature: signature length = {}", signature.len());

        let public_key_bytes = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        log::trace!(
            "verify_signature: public key length = {}",
            public_key_bytes.len()
        );

        match self
            .backend
            .verify_signature(sig_algo, &tbs_bytes, signature, public_key_bytes)
        {
            Ok(_) => {
                log::trace!("verify_signature: SUCCESS");
                Ok(())
            }
            Err(e) => {
                log::error!("verify_signature: FAILED: {:?}", e);
                Err(e)
            }
        }
    }

    /// Validate certificate time validity.
    fn validate_time(&self, cert: &Certificate) -> Result<()> {
        let validity = &cert.tbs_certificate.validity;

        // RFC 5280 §4.1.2.5: notBefore MUST be before notAfter.
        if !validity.is_well_formed() {
            return Err(Error::TimeError(
                crate::error::TimeError::InvalidValidityPeriod {
                    not_before: alloc::format!("{:?}", validity.not_before),
                    not_after: alloc::format!("{:?}", validity.not_after),
                },
            ));
        }

        let now = Self::get_current_time()?;

        if now.is_before(&validity.not_before) {
            return Err(Error::TimeError(crate::error::TimeError::NotYetValid));
        }

        if now.is_after(&validity.not_after) {
            return Err(Error::TimeError(crate::error::TimeError::Expired));
        }

        Ok(())
    }

    /// Get current time as a Time value.
    fn get_current_time() -> Result<Time> {
        crate::time::current_time()
            .map_err(|_| Error::TimeError(crate::error::TimeError::InvalidTime))
    }

    /// Validate certificate extensions.
    fn validate_extensions(&self, cert: &Certificate) -> Result<()> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(()),
        };

        log::trace!(
            "validate_extensions: checking {} extensions",
            extensions.extensions.len()
        );

        // RFC 5280 §4.2: "A certificate MUST NOT include more than one
        // instance of a particular extension."
        {
            let mut seen_oids = Vec::new();
            for ext in &extensions.extensions {
                if seen_oids.contains(&ext.extn_id) {
                    return Err(Error::ExtensionError(
                        crate::error::ExtensionError::DuplicateExtension(ext.extn_id.to_string()),
                    ));
                }
                seen_oids.push(ext.extn_id);
            }
        }

        for ext in &extensions.extensions {
            log::trace!(
                "validate_extensions: extension OID={}, critical={}",
                ext.extn_id,
                ext.critical
            );

            if ext.critical {
                if !self.known_extensions.contains(&ext.extn_id) {
                    log::error!(
                        "validate_extensions: UNKNOWN critical extension: {}",
                        ext.extn_id
                    );
                    return Err(Error::ExtensionError(
                        crate::error::ExtensionError::UnknownCriticalExtension(
                            ext.extn_id.to_string(),
                        ),
                    ));
                }

                if ext.extn_id == BASIC_CONSTRAINTS {
                    self.validate_basic_constraints(cert)?;
                }
            }
        }

        Ok(())
    }

    /// Validate Basic Constraints extension.
    ///
    /// If the extension is not present, validation passes (defaults apply).
    /// If present, the extension value MUST be a well-formed
    /// BasicConstraints SEQUENCE.  When `cA` is TRUE, `keyCertSign` Key
    /// Usage MUST be asserted (RFC 5280 §4.2.1.9).  When `pathLenConstraint`
    /// is present, `cA` MUST be TRUE.
    fn validate_basic_constraints(&self, cert: &Certificate) -> Result<()> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(()),
        };

        for ext in &extensions.extensions {
            if ext.extn_id == BASIC_CONSTRAINTS {
                use der::Decode;
                let bc =
                    BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;

                // RFC 5280 §4.2.1.9: pathLenConstraint is meaningful only when
                // cA is TRUE.  If someone sets pathLen without cA, reject.
                if bc.path_len_constraint.is_some() && !bc.ca {
                    return Err(Error::ExtensionError(
                        crate::error::ExtensionError::BasicConstraints(
                            alloc::string::String::from(
                                "pathLenConstraint present but cA is FALSE",
                            ),
                        ),
                    ));
                }

                // RFC 5280 §4.2.1.9: If cA is TRUE the Key Usage extension
                // (if present) MUST assert keyCertSign.
                if bc.ca {
                    if let Some(ku_ext) = extensions
                        .extensions
                        .iter()
                        .find(|e| e.extn_id == KEY_USAGE)
                    {
                        use crate::x509::extensions::KeyUsage;
                        let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
                            .map_err(Error::Asn1)?;
                        if !ku.has(KeyUsage::KEY_CERT_SIGN) {
                            return Err(Error::ConstraintError(
                                crate::error::ConstraintError::KeyUsageViolation(
                                    alloc::string::String::from(
                                        "CA certificate missing keyCertSign in Key Usage",
                                    ),
                                ),
                            ));
                        }
                    }
                }

                return Ok(());
            }
        }

        Ok(())
    }

    /// Validate a certificate chain.
    pub fn validate_chain(
        &self,
        chain: &CertificateChain,
        options: &ValidationOptions,
    ) -> Result<()> {
        log::trace!(
            "validate_chain: starting validation, chain_len={}",
            chain.len()
        );

        if chain.is_empty() {
            return Err(Error::ChainError(crate::error::ChainError::EmptyChain));
        }

        if chain.len() > options.max_chain_depth {
            return Err(Error::ChainError(crate::error::ChainError::ChainTooLong));
        }

        for (idx, cert) in chain.certificates.iter().enumerate() {
            log::trace!(
                "validate_chain: validating cert {} (subject={:?})",
                idx,
                cert.tbs_certificate.subject
            );

            self.validate(cert, options)?;

            if idx + 1 < chain.len() {
                let issuer = &chain.certificates[idx + 1];

                if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
                    log::error!("validate_chain: ISSUER MISMATCH at cert {}", idx);
                    return Err(Error::ChainError(crate::error::ChainError::IssuerMismatch));
                }

                if options.check_signature {
                    self.verify_signature(cert, issuer)?;
                }

                self.verify_issuer_is_ca(issuer, idx)?;

                // RFC 5280 §4.2.1.3: If Key Usage is present on the issuer,
                // keyCertSign MUST be asserted for it to be a valid CA that
                // can sign certificates.
                if let Some(exts) = &issuer.tbs_certificate.extensions {
                    if let Some(ku_ext) = exts.extensions.iter().find(|e| e.extn_id == KEY_USAGE) {
                        let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
                            .map_err(Error::Asn1)?;
                        if !ku.has(KeyUsage::KEY_CERT_SIGN) {
                            log::error!(
                                "validate_chain: issuer at depth {} missing keyCertSign",
                                idx + 1
                            );
                            return Err(Error::ConstraintError(
                                crate::error::ConstraintError::KeyUsageViolation(
                                    alloc::string::String::from(
                                        "Issuer certificate missing keyCertSign in Key Usage",
                                    ),
                                ),
                            ));
                        }
                    }
                }
            } else {
                // Root certificate - verify self-signed
                if options.check_signature {
                    self.verify_signature(cert, cert)?;
                }
            }
        }

        self.validate_path_length_constraints(chain)?;

        log::trace!("validate_chain: SUCCESS all validations passed");
        Ok(())
    }

    /// Verify that an issuer certificate is a CA.
    fn verify_issuer_is_ca(&self, issuer: &Certificate, depth: usize) -> Result<()> {
        let extensions = match &issuer.tbs_certificate.extensions {
            Some(exts) => exts,
            None => {
                return Err(Error::ChainError(crate::error::ChainError::IssuerNotCA));
            }
        };

        for ext in &extensions.extensions {
            if ext.extn_id == BASIC_CONSTRAINTS {
                use der::Decode;
                let bc =
                    BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;

                if !bc.ca {
                    return Err(Error::ChainError(crate::error::ChainError::IssuerNotCA));
                }

                if let Some(path_len) = bc.path_len_constraint {
                    if depth > path_len as usize {
                        return Err(Error::ChainError(
                            crate::error::ChainError::PathLengthExceeded,
                        ));
                    }
                }

                return Ok(());
            }
        }

        Err(Error::ChainError(crate::error::ChainError::IssuerNotCA))
    }

    /// Validate path length constraints in the chain.
    fn validate_path_length_constraints(&self, chain: &CertificateChain) -> Result<()> {
        for (idx, cert) in chain.certificates.iter().enumerate().skip(1) {
            let extensions = match &cert.tbs_certificate.extensions {
                Some(exts) => exts,
                None => continue,
            };

            for ext in &extensions.extensions {
                if ext.extn_id == BASIC_CONSTRAINTS {
                    use der::Decode;
                    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                        .map_err(Error::Asn1)?;

                    if let Some(path_len) = bc.path_len_constraint {
                        let remaining_certs = chain.len() - idx - 1;
                        if remaining_certs > path_len as usize {
                            return Err(Error::ChainError(
                                crate::error::ChainError::PathLengthExceeded,
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "ring-backend")]
impl Default for Validator<RingBackend> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "ring-backend"))]
mod tests {
    extern crate std;
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    #[test]
    fn test_validation_options() {
        let opts = ValidationOptions::default();
        assert_eq!(opts.check_time, !cfg!(feature = "no-time-check"));
        assert!(opts.check_signature);
        assert!(opts.check_extensions);
        assert_eq!(opts.max_chain_depth, 10);

        let opts = ValidationOptions::new()
            .skip_time_validation()
            .skip_signature_validation()
            .with_max_chain_depth(5);
        assert!(!opts.check_time);
        assert!(!opts.check_signature);
        assert_eq!(opts.max_chain_depth, 5);
    }

    #[test]
    fn test_validator_creation() {
        let _validator = Validator::new();
        let _validator2 = Validator::default();
    }

    // ── Helper to load a cert from DER file ──

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

    // ── validate: signature algorithm OID match ──

    #[test]
    fn test_validate_single_cert_structural() {
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = Validator::new();
        // CA cert should pass structural validation
        let result = validator.validate(&cert, &opts);
        assert!(
            result.is_ok(),
            "CA cert validate failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_leaf_cert() {
        let cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = Validator::new();
        let result = validator.validate(&cert, &opts);
        assert!(
            result.is_ok(),
            "leaf cert validate failed: {:?}",
            result.err()
        );
    }

    // ── validate_extensions: duplicate extension detection ──

    // (hard to test without constructing a malformed cert; tested implicitly via real certs)

    // ── validate_basic_constraints ──

    #[test]
    fn test_validate_basic_constraints_ca_cert() {
        let cert = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = Validator::new();
        // CA cert should have cA=TRUE and keyCertSign
        let result = validator.validate_basic_constraints(&cert);
        assert!(result.is_ok(), "CA BC failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_basic_constraints_leaf_cert() {
        let cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = Validator::new();
        let result = validator.validate_basic_constraints(&cert);
        assert!(result.is_ok(), "leaf BC failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_basic_constraints_ca_false_cert() {
        // end_responder.cert.der has CA:FALSE — should pass
        let cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = Validator::new();
        let result = validator.validate_basic_constraints(&cert);
        assert!(
            result.is_ok(),
            "end_responder BC (CA:FALSE) failed: {:?}",
            result.err()
        );
    }

    // ── verify_signature: cert→issuer ──

    #[test]
    fn test_verify_signature_ca_self_signed() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = Validator::new();
        let result = validator.verify_signature(&ca, &ca);
        assert!(result.is_ok(), "CA self-sig failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_signature_inter_signed_by_ca() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let validator = Validator::new();
        let result = validator.verify_signature(&inter, &ca);
        assert!(result.is_ok(), "inter→ca sig failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_signature_leaf_signed_by_inter() {
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = Validator::new();
        let result = validator.verify_signature(&leaf, &inter);
        assert!(result.is_ok(), "leaf→inter sig failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_signature_wrong_issuer_fails() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = Validator::new();
        // leaf was NOT signed by CA directly (it was signed by inter)
        let result = validator.verify_signature(&leaf, &ca);
        assert!(result.is_err(), "leaf→ca should fail (wrong issuer)");
    }

    // ── validate_chain ──

    #[test]
    fn test_validate_chain_ecp256() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        // Chain order: leaf → intermediate → root
        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = Validator::new();
        let result = validator.validate_chain(&chain, &opts);
        assert!(result.is_ok(), "ecp256 chain failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_chain_rsa3072() {
        let ca = load_cert(&test_key_path("rsa3072/ca.cert.der"));
        let inter = load_cert(&test_key_path("rsa3072/inter.cert.der"));
        let leaf = load_cert(&test_key_path("rsa3072/end_responder.cert.der"));

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = Validator::new();
        let result = validator.validate_chain(&chain, &opts);
        assert!(result.is_ok(), "rsa3072 chain failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_chain_empty_rejected() {
        let chain = CertificateChain::new(vec![]);
        let opts = ValidationOptions::default();
        let validator = Validator::new();
        assert!(validator.validate_chain(&chain, &opts).is_err());
    }

    #[test]
    fn test_validate_chain_exceeds_max_depth() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default()
            .skip_time_validation()
            .with_max_chain_depth(2); // chain has 3 certs
        let validator = Validator::new();
        assert!(validator.validate_chain(&chain, &opts).is_err());
    }

    #[test]
    fn test_validate_chain_wrong_order_rejected() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        // Wrong order: root → inter → leaf (should be leaf → inter → root)
        let chain = CertificateChain::new(vec![ca, inter, leaf]);
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = Validator::new();
        assert!(validator.validate_chain(&chain, &opts).is_err());
    }

    #[test]
    fn test_validate_chain_issuer_mismatch_rejected() {
        let ca_256 = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let leaf_384 = load_cert(&test_key_path("ecp384/end_responder.cert.der"));

        // Mixed: ecp384 leaf with ecp256 CA — issuer DN won't match
        let chain = CertificateChain::new(vec![leaf_384, ca_256]);
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = Validator::new();
        assert!(validator.validate_chain(&chain, &opts).is_err());
    }

    #[test]
    fn test_validate_chain_skip_signature() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default()
            .skip_time_validation()
            .skip_signature_validation();
        let validator = Validator::new();
        assert!(validator.validate_chain(&chain, &opts).is_ok());
    }

    // ── verify_issuer_is_ca ──

    #[test]
    fn test_verify_issuer_is_ca_with_ca_cert() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let validator = Validator::new();
        assert!(validator.verify_issuer_is_ca(&ca, 0).is_ok());
    }

    #[test]
    fn test_verify_issuer_is_ca_with_leaf_fails() {
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let validator = Validator::new();
        assert!(validator.verify_issuer_is_ca(&leaf, 0).is_err());
    }

    // ── Cross-algorithm chain tests ──

    #[test]
    fn test_validate_chain_rsa2048() {
        let ca = load_cert(&test_key_path("rsa2048/ca.cert.der"));
        let inter = load_cert(&test_key_path("rsa2048/inter.cert.der"));
        let leaf = load_cert(&test_key_path("rsa2048/end_responder.cert.der"));

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = Validator::new();
        let result = validator.validate_chain(&chain, &opts);
        assert!(result.is_ok(), "rsa2048 chain failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_chain_ecp384() {
        let ca = load_cert(&test_key_path("ecp384/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp384/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp384/end_responder.cert.der"));

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default().skip_time_validation();
        let validator = Validator::new();
        let result = validator.validate_chain(&chain, &opts);
        assert!(result.is_ok(), "ecp384 chain failed: {:?}", result.err());
    }
}
