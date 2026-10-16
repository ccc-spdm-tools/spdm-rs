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

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::certificate::name::{
    AttributeTypeAndValue, GeneralName, Name, RelativeDistinguishedName, SubjectAltName, CN,
    COUNTRY_NAME, DOMAIN_COMPONENT, EMAIL_ADDRESS, GIVEN_NAME, LOCALITY_NAME,
    ORGANIZATIONAL_UNIT_NAME, ORGANIZATION_NAME, SERIAL_NUMBER, STATE_OR_PROVINCE_NAME,
    STREET_ADDRESS, SURNAME, TITLE,
};
use crate::certificate::Certificate;
use crate::chain::CertificateChain;
#[cfg(test)]
use crate::crypto_backend::RingBackend;
use crate::crypto_backend::{CryptoBackend, SignatureAlgorithm};
use crate::error::{Error, Result};
use crate::x509::extensions::{
    BasicConstraints, KeyUsage, NameConstraints, AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS,
    EXTENDED_KEY_USAGE, KEY_USAGE, NAME_CONSTRAINTS, SUBJECT_ALT_NAME, SUBJECT_KEY_IDENTIFIER,
    TCG_PLATFORM_CERTIFICATE,
};
use crate::x509::extensions::{HARDWARE_IDENTITY, SPDM_EXTENSION};
use crate::x509::idna;
use crate::x509::rfc4518::{is_combining_mark, is_unassigned};
use const_oid::ObjectIdentifier;
use focaccia::CaseFold;
use unicode_normalization::UnicodeNormalization;

// Bound pre-Nameprep input independently of the much smaller DNS wire limits:
// mapped-to-nothing characters must not permit unbounded work or allocation.
const MAX_IDNA_HOST_INPUT_BYTES: usize = 4096;
const MAX_IDNA_LABEL_INPUT_BYTES: usize = 1024;
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DIRECTORY_STRING_CHARS: usize = 32768;
const X520_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.41");
const INITIALS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.43");
const GENERATION_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.44");
const DN_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.46");
const PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.65");

struct Rfc3454CaseFoldScratch {
    first_fold: String,
    first_normalized: String,
    second_fold: String,
    candidate: String,
}

impl Rfc3454CaseFoldScratch {
    fn new() -> Option<Self> {
        let mut scratch = Self {
            first_fold: String::new(),
            first_normalized: String::new(),
            second_fold: String::new(),
            candidate: String::new(),
        };
        for value in [
            &mut scratch.first_fold,
            &mut scratch.first_normalized,
            &mut scratch.second_fold,
            &mut scratch.candidate,
        ] {
            value.try_reserve(12).ok()?;
        }
        Some(scratch)
    }
}

// ============================================================================
// Validation Options
// ============================================================================

/// Options for certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Whether to verify the certificate signature
    pub check_signature: bool,

    /// Whether to validate extensions
    pub check_extensions: bool,

    /// Whether to validate certificate validity periods (notBefore/notAfter).
    /// Defaults to true. On no_std targets, the check is a no-op (always passes).
    pub check_time: bool,

    /// Maximum allowed certificate chain depth
    pub max_chain_depth: usize,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            check_signature: true,
            check_extensions: true,
            check_time: true,
            max_chain_depth: 10,
        }
    }
}

impl ValidationOptions {
    /// Create a new ValidationOptions with all checks enabled
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable signature validation (useful for parsing-only scenarios)
    pub fn skip_signature_validation(mut self) -> Self {
        self.check_signature = false;
        self
    }

    /// Enable certificate validity period (time) checks.
    /// Enabled by default; on no_std targets the check is a no-op.
    pub fn with_time_check(mut self) -> Self {
        self.check_time = true;
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

#[cfg(test)]
impl Validator<RingBackend> {
    /// Create a new Validator with the bundled test-only ring backend.
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
            NAME_CONSTRAINTS,
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
        self.validate_with_context(cert, options, false)
    }

    fn validate_with_context(
        &self,
        cert: &Certificate,
        options: &ValidationOptions,
        is_issuer: bool,
    ) -> Result<()> {
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

        Self::validate_required_names(cert)?;

        if options.check_extensions {
            self.validate_extensions(cert, is_issuer)?;
        }

        if options.check_time {
            self.validate_time(cert)?;
        }

        Ok(())
    }

    fn validate_required_names(cert: &Certificate) -> Result<()> {
        if cert.tbs_certificate.issuer.rdns.is_empty() {
            return Err(Error::ValidationError(String::from(
                "Certificate issuer distinguished name is empty",
            )));
        }
        Ok(())
    }

    /// Validate certificate validity period (notBefore / notAfter).
    ///
    /// On `std` targets this checks against the system clock.
    /// On `no_std` targets this is a no-op (always passes) since there is no
    /// reliable clock source.
    #[cfg(feature = "std")]
    fn validate_time(&self, cert: &Certificate) -> Result<()> {
        let validity = &cert.tbs_certificate.validity;
        let now = crate::time::Time::now()
            .map_err(|e| Error::ValidationError(alloc::format!("Time check failed: {}", e)))?;
        if !validity.is_valid_at(&now) {
            return Err(Error::ValidationError(
                "Certificate not valid at current time".into(),
            ));
        }
        Ok(())
    }

    #[cfg(not(feature = "std"))]
    fn validate_time(&self, _cert: &Certificate) -> Result<()> {
        Ok(())
    }

    /// Verify certificate signature against issuer's public key.
    pub fn verify_signature(&self, cert: &Certificate, issuer: &Certificate) -> Result<()> {
        log::trace!("verify_signature: starting signature verification");
        log::trace!("cert subject: {:?}", cert.tbs_certificate.subject);
        log::trace!("issuer subject: {:?}", issuer.tbs_certificate.subject);

        // The curve OID comes from the issuer's SubjectPublicKeyInfo because
        // we verify the signature using the issuer's public key. The curve is a
        // property of that key, not of the cert's signatureAlgorithm field.
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

        // Post-quantum (e.g. ML-DSA / FIPS 204) signatures cannot be verified by
        // the classical crypto backends (ring / mbedtls). When such a backend is
        // paired with a separately-registered PQC verifier hook, dispatch ML-DSA
        // to the hook. When the active backend can verify ML-DSA itself (e.g. the
        // aws-lc backend), no hook is registered and the signature — PQC or
        // classical — goes straight to the backend.
        let verify_result = if crate::crypto_backend::is_pqc(sig_algo)
            && crate::crypto_backend::pqc_verifier_registered()
        {
            crate::crypto_backend::verify_pqc_signature(
                sig_algo,
                &tbs_bytes,
                signature,
                public_key_bytes,
            )
        } else {
            self.backend
                .verify_signature(sig_algo, &tbs_bytes, signature, public_key_bytes)
        };

        match verify_result {
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

    /// Validate certificate extensions.
    fn validate_extensions(&self, cert: &Certificate, is_issuer: bool) -> Result<()> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Self::subject_alt_name(cert).map(|_| ()),
        };

        log::trace!(
            "validate_extensions: checking {} extensions",
            extensions.extensions.len()
        );

        Self::validate_unique_extensions(cert)?;

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

            if ext.extn_id == NAME_CONSTRAINTS {
                Self::validate_name_constraints_extension(cert, is_issuer)?;
            }
        }

        Self::subject_alt_name(cert)?;
        Ok(())
    }

    fn validate_unique_extensions(cert: &Certificate) -> Result<()> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(()),
        };

        let mut oids = Vec::new();
        oids.try_reserve_exact(extensions.extensions.len())
            .map_err(|_| Error::Asn1(der::ErrorKind::Overlength.into()))?;
        oids.extend(extensions.extensions.iter().map(|ext| ext.extn_id));
        oids.sort_unstable();

        if let Some(duplicate) = oids.windows(2).find_map(|pair| {
            if pair[0] == pair[1] {
                Some(pair[0])
            } else {
                None
            }
        }) {
            return Err(Error::ExtensionError(
                crate::error::ExtensionError::DuplicateExtension(duplicate.to_string()),
            ));
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

            self.validate_with_context(cert, options, idx != 0)?;

            if idx + 1 < chain.len() {
                let issuer = &chain.certificates[idx + 1];

                if !Self::distinguished_names_match(
                    &cert.tbs_certificate.issuer,
                    &issuer.tbs_certificate.subject,
                ) {
                    log::error!("validate_chain: ISSUER MISMATCH at cert {}", idx);
                    return Err(Error::ChainError(crate::error::ChainError::IssuerMismatch));
                }

                // RFC 5280 §4.2.1.3: If Key Usage is present on the issuer,
                // keyCertSign MUST be asserted for it to be a valid CA that
                // can sign certificates. Check this BEFORE pathLenConstraint
                // per RFC 5280 §4.2.1.9 which conditions pathLenConstraint
                // on keyCertSign being set.
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

                self.verify_issuer_is_ca(issuer, idx)?;

                // Verify signature last — CA and keyCertSign checks above are
                // cheap and may reject the issuer without incurring the cost of
                // a cryptographic signature verification.
                if options.check_signature {
                    self.verify_signature(cert, issuer)?;
                }
            } else {
                // Root certificate - verify self-signed
                if options.check_signature {
                    self.verify_signature(cert, cert)?;
                }
            }
        }

        // NOTE: pathLenConstraint is enforced inline by verify_issuer_is_ca()
        // for each CA during the chain walk above; no separate pass is needed.

        // RFC 5280 §4.2.1.10: enforce Name Constraints declared by any CA
        // certificate against the subject DN and subjectAltName of every
        // subsequent (leaf-ward) certificate in the path.
        self.validate_name_constraints(chain)?;

        log::trace!("validate_chain: SUCCESS all validations passed");
        Ok(())
    }

    /// Verify that an issuer certificate is a CA.
    ///
    /// Per SPDM 1.2 (DSP0274), the BasicConstraints extension is not required
    /// to be present.  If it *is* present the cA flag must be TRUE; if it is
    /// absent the certificate is still accepted as a valid issuer.
    fn verify_issuer_is_ca(&self, issuer: &Certificate, depth: usize) -> Result<()> {
        let extensions = match &issuer.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(()),
        };

        for ext in &extensions.extensions {
            if ext.extn_id == BASIC_CONSTRAINTS {
                use der::Decode;
                let bc =
                    BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;

                if !bc.ca {
                    return Err(Error::ChainError(crate::error::ChainError::IssuerNotCA));
                }

                // RFC 5280 §4.2.1.9: `pathLenConstraint` bounds the number of
                // non-self-issued intermediate CAs that may follow this issuer
                // toward the end-entity. The chain is walked leaf->root, so
                // `depth` (the child's index in leaf->root order) equals the
                // count of certificates already traversed below this issuer,
                // which is exactly that follow-on intermediate count. This is
                // the single, authoritative pathLen enforcement for the chain.
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

        // BasicConstraints extension not present — acceptable per SPDM 1.2.
        Ok(())
    }
    /// Enforce RFC 5280 §4.2.1.10 Name Constraints across the chain.
    ///
    /// `chain.certificates` is in leaf→root order.  A `NameConstraints`
    /// extension in a CA certificate applies to every certificate that appears
    /// *after* it toward the leaf (i.e. every certificate at a lower index).
    /// For each subordinate certificate we verify that its subject DN and each
    /// supported subjectAltName entry are permitted (when a matching
    /// `permittedSubtrees` restriction exists) and are not excluded.
    ///
    /// Name constraints are not applied to self-issued certificates unless the
    /// certificate is the leaf (final certificate in the path), per RFC 5280.
    ///
    /// Supported name forms are directoryName, dNSName, rfc822Name,
    /// uniformResourceIdentifier, and iPAddress. Constraint bases using other
    /// name forms cause rejection only when the same name form appears below.
    /// This includes SPDM's DMTF device-info `otherName`: RFC 5280 does not
    /// define matching semantics for it, so a path that constrains `otherName`
    /// is rejected rather than accepted without enforcing the constraint.
    ///
    /// RFC 5280 §6.2 permits implementations to process constraints carried in
    /// a self-signed trust anchor certificate. This validator does so, treating
    /// them as the initial constraint state for the path.
    fn validate_name_constraints(&self, chain: &CertificateChain) -> Result<()> {
        let len = chain.len();

        for (index, cert) in chain.certificates.iter().enumerate() {
            Self::validate_unique_extensions(cert)?;
            Self::validate_name_constraints_extension(cert, index != 0)?;
        }

        for i in 0..len {
            let subject_cert = &chain.certificates[i];

            // Self-issued certificates are exempt unless they are the leaf.
            let self_issued = Self::distinguished_names_match(
                &subject_cert.tbs_certificate.subject,
                &subject_cert.tbs_certificate.issuer,
            );
            if self_issued && i != 0 {
                continue;
            }

            let subject = &subject_cert.tbs_certificate.subject;
            let san = Self::subject_alt_name(subject_cert)?;

            // Check this certificate's names against every CA certificate that
            // sits above it in the path (higher index == closer to the root).
            for ca_cert in chain.certificates.iter().skip(i + 1) {
                let nc = match Self::name_constraints(ca_cert)? {
                    Some(nc) => nc,
                    None => continue,
                };
                Self::check_names_against_constraints(subject, san.as_ref(), &nc)?;
            }
        }
        Ok(())
    }

    /// Validate the RFC 5280 profile requirements that apply to the extension
    /// itself, independently of the names in subordinate certificates.
    fn validate_name_constraints_extension(cert: &Certificate, is_issuer: bool) -> Result<()> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(()),
        };
        let mut matching = extensions
            .extensions
            .iter()
            .filter(|ext| ext.extn_id == NAME_CONSTRAINTS);
        let ext = match matching.next() {
            Some(ext) => ext,
            None => return Ok(()),
        };
        if matching.next().is_some() {
            return Err(Error::ExtensionError(
                crate::error::ExtensionError::DuplicateExtension(NAME_CONSTRAINTS.to_string()),
            ));
        }

        if !ext.critical {
            return Err(Self::name_constraints_extension_error(
                "Name Constraints extension must be critical",
            ));
        }

        let is_ca = match extensions
            .extensions
            .iter()
            .find(|ext| ext.extn_id == BASIC_CONSTRAINTS)
        {
            Some(bc_ext) => {
                use der::Decode;
                BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
                    .map_err(Error::Asn1)?
                    .ca
            }
            // DSP0274 1.2 permits an issuer to omit Basic Constraints. Preserve
            // that profile relaxation consistently when the certificate's
            // position in a validated chain establishes its CA role.
            None => is_issuer,
        };
        if !is_ca {
            return Err(Self::name_constraints_extension_error(
                "Name Constraints extension is only valid in a CA certificate",
            ));
        }

        use der::Decode;
        let nc = NameConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;
        Self::validate_constraint_bases(&nc)
    }

    fn name_constraints_extension_error(message: &str) -> Error {
        Error::ExtensionError(crate::error::ExtensionError::NameConstraints(
            message.into(),
        ))
    }

    fn subject_alt_name_extension_error(message: &str) -> Error {
        Error::ExtensionError(crate::error::ExtensionError::SubjectAltName(message.into()))
    }

    fn validate_subject_alt_names(san: &SubjectAltName) -> Result<()> {
        for name in &san.names {
            name.validate_structure().map_err(|_| {
                Self::subject_alt_name_extension_error(
                    "Subject Alternative Name contains a malformed GeneralName",
                )
            })?;
            let valid = match name {
                GeneralName::DnsName(dns) => Self::is_valid_dns_san(dns),
                GeneralName::Rfc822Name(email) => Self::email_parts(email).is_some(),
                GeneralName::DirectoryName(name) => {
                    !name.rdns.is_empty() && Self::dn_is_comparable(name)
                }
                GeneralName::Uri(uri) => Self::parse_uri_dns_host(uri).is_ok(),
                GeneralName::IpAddress(bytes) => matches!(bytes.len(), 4 | 16),
                GeneralName::OtherName(_)
                | GeneralName::X400Address(_)
                | GeneralName::EdiPartyName(_) => true,
                GeneralName::RegisteredId(_) => true,
            };
            if !valid {
                return Err(Self::subject_alt_name_extension_error(
                    "Subject Alternative Name contains a malformed GeneralName",
                ));
            }
        }
        Ok(())
    }

    fn validate_constraint_bases(nc: &NameConstraints) -> Result<()> {
        let subtrees = nc
            .permitted_subtrees
            .iter()
            .chain(nc.excluded_subtrees.iter())
            .flat_map(|subtrees| subtrees.iter());

        for subtree in subtrees {
            subtree.base.validate_structure().map_err(|_| {
                Self::name_constraints_extension_error(
                    "Name Constraints contains a malformed GeneralName",
                )
            })?;
            match &subtree.base {
                GeneralName::DirectoryName(name) if Self::dn_is_comparable(name) => {}
                GeneralName::DirectoryName(_) => {
                    return Err(Self::name_constraints_extension_error(
                        "directoryName constraint contains an invalid attribute value",
                    ));
                }
                GeneralName::DnsName(constraint) if Self::is_valid_dns_constraint(constraint) => {}
                GeneralName::DnsName(_) => {
                    return Err(Self::name_constraints_extension_error(
                        "dNSName constraint is not a valid DNS subtree",
                    ));
                }
                GeneralName::Rfc822Name(constraint)
                    if Self::is_valid_email_constraint(constraint) => {}
                GeneralName::Rfc822Name(_) => {
                    return Err(Self::name_constraints_extension_error(
                        "rfc822Name constraint is not a mailbox, host, or domain",
                    ));
                }
                GeneralName::Uri(constraint) => {
                    if !Self::is_valid_domain_constraint(constraint) {
                        return Err(Self::name_constraints_extension_error(
                            "URI constraint must contain only a valid DNS host or domain",
                        ));
                    }
                }
                GeneralName::IpAddress(bytes) if Self::is_valid_ip_constraint(bytes) => {}
                GeneralName::IpAddress(_) => {
                    return Err(Self::name_constraints_extension_error(
                        "IP address constraint must contain a canonical CIDR address and mask",
                    ));
                }
                // RFC 5280 §4.2.1.10 only requires rejection for an
                // unsupported constrained form when that form appears in a
                // subsequent certificate. Defer that decision until names are
                // processed.
                _ => {}
            }
        }
        Ok(())
    }

    /// Parse the NameConstraints extension of a certificate, if present.
    fn name_constraints(cert: &Certificate) -> Result<Option<NameConstraints>> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(None),
        };
        for ext in &extensions.extensions {
            if ext.extn_id == NAME_CONSTRAINTS {
                use der::Decode;
                let nc =
                    NameConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;
                return Ok(Some(nc));
            }
        }
        Ok(None)
    }

    /// Parse the subjectAltName extension of a certificate, if present.
    fn subject_alt_name(cert: &Certificate) -> Result<Option<SubjectAltName>> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(None),
        };
        for ext in &extensions.extensions {
            if ext.extn_id == SUBJECT_ALT_NAME {
                return Self::validate_subject_alt_name_extension(cert, ext).map(Some);
            }
        }
        if cert.tbs_certificate.subject.rdns.is_empty() {
            return Err(Self::subject_alt_name_extension_error(
                "subjectAltName is required when the subject is empty",
            ));
        }
        Ok(None)
    }

    fn validate_subject_alt_name_extension(
        cert: &Certificate,
        ext: &crate::certificate::Extension,
    ) -> Result<SubjectAltName> {
        let san = Self::decode_subject_alt_name(ext)?;
        if cert.tbs_certificate.subject.rdns.is_empty() && !ext.critical {
            return Err(Self::subject_alt_name_extension_error(
                "subjectAltName must be critical when the subject is empty",
            ));
        }
        Ok(san)
    }

    fn decode_subject_alt_name(ext: &crate::certificate::Extension) -> Result<SubjectAltName> {
        use der::Decode;
        let san = SubjectAltName::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;
        Self::validate_subject_alt_names(&san)?;
        Ok(san)
    }

    /// Verify a certificate's subject DN and subjectAltName entries against a
    /// single CA certificate's Name Constraints.
    fn check_names_against_constraints(
        subject: &Name,
        san: Option<&SubjectAltName>,
        nc: &NameConstraints,
    ) -> Result<()> {
        // The subject field, when non-empty, is treated as a directoryName.
        if !subject.rdns.is_empty() {
            Self::check_directory_name(subject, nc)?;
        }

        if let Some(san) = san {
            for name in &san.names {
                match name {
                    GeneralName::DirectoryName(dn) => Self::check_directory_name(dn, nc)?,
                    GeneralName::DnsName(dns) => Self::check_dns_name(dns, nc)?,
                    GeneralName::Rfc822Name(email) => Self::check_email_name(email, nc)?,
                    GeneralName::Uri(uri) => Self::check_uri_name(uri, nc)?,
                    GeneralName::IpAddress(ip) => Self::check_ip_address(ip, nc)?,
                    _ if Self::has_constraint_for_name_form(name, nc) => {
                        return Err(Error::ChainError(
                            crate::error::ChainError::NameConstraintViolation(alloc::format!(
                                "cannot process constrained GeneralName form {}",
                                name
                            )),
                        ));
                    }
                    _ => {}
                }
            }
        } else {
            // RFC 5280 §4.2.1.10: when SAN is absent, rfc822Name constraints
            // also apply to legacy emailAddress attributes in the subject DN.
            for rdn in &subject.rdns {
                for attr in rdn
                    .attributes
                    .iter()
                    .filter(|attr| attr.oid == EMAIL_ADDRESS)
                {
                    let email = attr.value_as_str().map_err(Error::Asn1)?;
                    Self::check_email_name(&email, nc)?;
                }
            }
        }
        Ok(())
    }

    fn has_constraint_for_name_form(name: &GeneralName, nc: &NameConstraints) -> bool {
        nc.permitted_subtrees
            .iter()
            .chain(nc.excluded_subtrees.iter())
            .flat_map(|subtrees| subtrees.iter())
            .any(|subtree| {
                matches!(
                    (name, &subtree.base),
                    (GeneralName::OtherName(_), GeneralName::OtherName(_))
                        | (GeneralName::X400Address(_), GeneralName::X400Address(_))
                        | (GeneralName::EdiPartyName(_), GeneralName::EdiPartyName(_))
                        | (GeneralName::RegisteredId(_), GeneralName::RegisteredId(_))
                )
            })
    }

    /// Evaluate one name value against the excluded and permitted subtrees.
    ///
    /// `is_within` returns `None` when the subtree base is a different name
    /// form (and therefore irrelevant), `Some(true)` when the value falls
    /// within the base, and `Some(false)` when the value is of the same form
    /// but outside the base.  Excluded matches take precedence, and a value is
    /// rejected if any permitted subtree of the same form exists but none of
    /// them contain the value.
    fn evaluate_constraint<F>(
        nc: &NameConstraints,
        form: &str,
        value_display: &str,
        mut is_within: F,
    ) -> Result<()>
    where
        F: FnMut(&GeneralName) -> Option<bool>,
    {
        if let Some(excluded) = &nc.excluded_subtrees {
            for subtree in excluded {
                if is_within(&subtree.base) == Some(true) {
                    return Err(Error::ChainError(
                        crate::error::ChainError::NameConstraintViolation(alloc::format!(
                            "{} {} is within an excluded subtree",
                            form,
                            value_display
                        )),
                    ));
                }
            }
        }

        if let Some(permitted) = &nc.permitted_subtrees {
            let mut constrained = false;
            let mut matched = false;
            for subtree in permitted {
                match is_within(&subtree.base) {
                    Some(true) => {
                        matched = true;
                        break;
                    }
                    Some(false) => constrained = true,
                    None => {}
                }
            }
            if constrained && !matched {
                return Err(Error::ChainError(
                    crate::error::ChainError::NameConstraintViolation(alloc::format!(
                        "{} {} is not within any permitted subtree",
                        form,
                        value_display
                    )),
                ));
            }
        }

        Ok(())
    }

    fn check_directory_name(name: &Name, nc: &NameConstraints) -> Result<()> {
        if !Self::has_directory_name_constraints(nc) {
            return Ok(());
        }
        if !Self::dn_is_comparable(name) {
            return Err(Error::ChainError(
                crate::error::ChainError::NameConstraintViolation(String::from(
                    "directoryName contains an invalid attribute value",
                )),
            ));
        }
        let display = alloc::format!("{}", name);
        Self::evaluate_constraint(nc, "directoryName", &display, |base| match base {
            GeneralName::DirectoryName(b) => Some(Self::dn_within_subtree(name, b)),
            _ => None,
        })
    }

    fn check_dns_name(dns: &str, nc: &NameConstraints) -> Result<()> {
        if !Self::is_valid_dns_san(dns) {
            return Err(Error::ChainError(
                crate::error::ChainError::NameConstraintViolation(alloc::format!(
                    "dNSName {} is malformed",
                    dns
                )),
            ));
        }
        if Self::is_dns_wildcard(dns) && Self::has_dns_constraints(nc) {
            return Err(Error::ChainError(
                crate::error::ChainError::NameConstraintViolation(alloc::format!(
                    "wildcard dNSName {} cannot be safely evaluated against Name Constraints",
                    dns
                )),
            ));
        }
        Self::evaluate_constraint(nc, "dNSName", dns, |base| match base {
            GeneralName::DnsName(b) => Some(Self::dns_within_constraint(dns, b)),
            _ => None,
        })
    }

    fn check_email_name(email: &str, nc: &NameConstraints) -> Result<()> {
        if Self::email_parts(email).is_none() {
            return Err(Error::ChainError(
                crate::error::ChainError::NameConstraintViolation(alloc::format!(
                    "rfc822Name {} is malformed",
                    email
                )),
            ));
        }
        Self::evaluate_constraint(nc, "rfc822Name", email, |base| match base {
            GeneralName::Rfc822Name(b) => Some(Self::email_within_constraint(email, b)),
            _ => None,
        })
    }

    fn check_uri_name(uri: &str, nc: &NameConstraints) -> Result<()> {
        let dns_host = Self::parse_uri_dns_host(uri).map_err(|_| {
            Error::ChainError(crate::error::ChainError::NameConstraintViolation(
                String::from("uniformResourceIdentifier is malformed"),
            ))
        })?;
        if Self::has_uri_constraints(nc) && dns_host.is_none() {
            return Err(Error::ChainError(
                crate::error::ChainError::NameConstraintViolation(String::from(
                    "uniformResourceIdentifier does not contain a DNS host",
                )),
            ));
        }
        Self::evaluate_constraint(
            nc,
            "uniformResourceIdentifier",
            "<URI>",
            |base| match base {
                GeneralName::Uri(constraint) => Some(Self::uri_within_constraint(uri, constraint)),
                _ => None,
            },
        )
    }

    fn check_ip_address(ip: &[u8], nc: &NameConstraints) -> Result<()> {
        if !matches!(ip.len(), 4 | 16) {
            return Err(Error::ChainError(
                crate::error::ChainError::NameConstraintViolation(alloc::format!(
                    "iPAddress {:?} has an invalid length",
                    ip
                )),
            ));
        }
        let display = alloc::format!("{:?}", ip);
        Self::evaluate_constraint(nc, "iPAddress", &display, |base| match base {
            GeneralName::IpAddress(constraint) => Some(Self::ip_within_constraint(ip, constraint)),
            _ => None,
        })
    }

    /// RFC 5280 §4.2.1.10 directoryName containment: `name` is within `base`
    /// when `base` is a prefix (root-side) of `name`'s RDN sequence.
    fn dn_within_subtree(name: &Name, base: &Name) -> bool {
        if name.rdns.len() < base.rdns.len() {
            return false;
        }
        base.rdns
            .iter()
            .zip(name.rdns.iter())
            .all(|(base_rdn, name_rdn)| {
                Self::relative_distinguished_names_match(base_rdn, name_rdn)
            })
    }

    fn distinguished_names_match(left: &Name, right: &Name) -> bool {
        if left == right {
            return true;
        }
        Self::dn_is_comparable(left)
            && Self::dn_is_comparable(right)
            && left.rdns.len() == right.rdns.len()
            && Self::dn_within_subtree(left, right)
    }

    fn relative_distinguished_names_match(
        left: &RelativeDistinguishedName,
        right: &RelativeDistinguishedName,
    ) -> bool {
        if left.attributes.len() != right.attributes.len() {
            return false;
        }

        let mut matched = Vec::new();
        if matched.try_reserve_exact(right.attributes.len()).is_err() {
            return false;
        }
        matched.resize(right.attributes.len(), false);
        for left_attr in left.attributes.iter() {
            let Some(index) = right
                .attributes
                .iter()
                .enumerate()
                .find(|(index, right_attr)| {
                    !matched[*index] && Self::dn_attributes_match(left_attr, right_attr)
                })
                .map(|(index, _)| index)
            else {
                return false;
            };
            matched[index] = true;
        }
        true
    }

    fn normalize_percent_encoded_host(host: &str) -> core::result::Result<Option<String>, ()> {
        if host.len() > MAX_IDNA_HOST_INPUT_BYTES {
            return Err(());
        }
        let bytes = host.as_bytes();
        let mut normalized = Vec::new();
        normalized.try_reserve_exact(bytes.len()).map_err(|_| ())?;
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'%' {
                normalized.push(bytes[index]);
                index += 1;
                continue;
            }

            let high = Self::hex_value(*bytes.get(index + 1).ok_or(())?).ok_or(())?;
            let low = Self::hex_value(*bytes.get(index + 2).ok_or(())?).ok_or(())?;
            let decoded = (high << 4) | low;
            normalized.push(decoded);
            index += 3;
        }

        let normalized = core::str::from_utf8(&normalized).map_err(|_| ())?;
        Self::idna_host_to_ascii(normalized).map(Some)
    }

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    fn idna_host_to_ascii(host: &str) -> core::result::Result<String, ()> {
        if host.is_empty() || host.len() > MAX_IDNA_HOST_INPUT_BYTES {
            return Err(());
        }
        let mut separated = String::new();
        separated.try_reserve_exact(host.len()).map_err(|_| ())?;
        for character in host.chars() {
            separated.push(
                if matches!(character, '.' | '\u{3002}' | '\u{FF0E}' | '\u{FF61}') {
                    '.'
                } else {
                    character
                },
            );
        }

        let trailing_dot = separated.ends_with('.');
        let labels = separated.strip_suffix('.').unwrap_or(&separated);
        if labels.is_empty() || labels.split('.').any(str::is_empty) {
            return Err(());
        }

        let mut ascii = String::new();
        ascii
            .try_reserve_exact(MAX_DNS_NAME_LEN + 1)
            .map_err(|_| ())?;
        for (index, label) in labels.split('.').enumerate() {
            let label = Self::idna_label_to_ascii(label)?;
            let additional = label
                .len()
                .checked_add(if index == 0 { 0 } else { 1 })
                .ok_or(())?;
            if ascii.len().checked_add(additional).ok_or(())? > MAX_DNS_NAME_LEN {
                return Err(());
            }
            if index != 0 {
                ascii.push('.');
            }
            ascii.push_str(&label);
        }
        if trailing_dot {
            ascii.push('.');
        }
        Ok(ascii)
    }

    fn idna_label_to_ascii(label: &str) -> core::result::Result<String, ()> {
        if label.is_empty()
            || label.len() > MAX_IDNA_LABEL_INPUT_BYTES
            || (label.is_ascii() && label.len() > 63)
        {
            return Err(());
        }
        let prepared = if label.is_ascii() {
            Self::owned_string(label).ok_or(())?
        } else {
            Self::nameprep_label(label)?
        };
        if prepared.is_empty()
            || prepared.chars().take(64).count() > 63
            || prepared.chars().any(|character| {
                matches!(character, '.' | '\u{3002}' | '\u{FF0E}' | '\u{FF61}')
                    || (character.is_ascii()
                        && !character.is_ascii_alphanumeric()
                        && character != '-')
            })
            || prepared.starts_with('-')
            || prepared.ends_with('-')
        {
            return Err(());
        }

        let mut ascii = if prepared.is_ascii() {
            if prepared
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("xn--"))
            {
                Self::validate_ace_label(&prepared)?;
            }
            prepared
        } else {
            if prepared
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("xn--"))
            {
                return Err(());
            }
            let payload = idna::punycode_encode(&prepared).ok_or(())?;
            if payload.len() > 59 {
                return Err(());
            }
            let mut encoded = String::new();
            encoded
                .try_reserve_exact(4 + payload.len())
                .map_err(|_| ())?;
            encoded.push_str("xn--");
            encoded.push_str(&payload);
            encoded
        };
        if ascii.len() > 63 {
            return Err(());
        }
        ascii.make_ascii_lowercase();
        Ok(ascii)
    }

    fn validate_ace_label(label: &str) -> core::result::Result<(), ()> {
        let payload = label.get(4..).ok_or(())?;
        let decoded = idna::punycode_decode(payload).ok_or(())?;
        if decoded.is_ascii() {
            return Err(());
        }
        let prepared = Self::nameprep_label(&decoded)?;
        if prepared.is_ascii()
            || prepared.chars().any(|character| {
                matches!(character, '.' | '\u{3002}' | '\u{FF0E}' | '\u{FF61}')
                    || (character.is_ascii()
                        && !character.is_ascii_alphanumeric()
                        && character != '-')
            })
            || prepared.starts_with('-')
            || prepared.ends_with('-')
        {
            return Err(());
        }
        let canonical = idna::punycode_encode(&prepared).ok_or(())?;
        if !canonical.eq_ignore_ascii_case(payload) {
            return Err(());
        }
        Ok(())
    }

    fn nameprep_label(label: &str) -> core::result::Result<String, ()> {
        if label.is_empty() || label.len() > MAX_IDNA_LABEL_INPUT_BYTES {
            return Err(());
        }
        let mut mapped = String::new();
        mapped.try_reserve(label.len()).map_err(|_| ())?;
        let mut scratch = Rfc3454CaseFoldScratch::new().ok_or(())?;
        for character in label.chars() {
            if is_unassigned(character) {
                return Err(());
            }
            if idna::commonly_mapped_to_nothing(character) {
                continue;
            }
            Self::append_rfc3454_case_fold(character, &mut mapped, &mut scratch).ok_or(())?;
        }

        let mut normalized = String::new();
        normalized.try_reserve(mapped.len()).map_err(|_| ())?;
        Self::append_nfkc(&mapped, &mut normalized).ok_or(())?;
        if normalized.is_empty()
            || normalized.chars().any(|character| {
                is_unassigned(character) || idna::is_nameprep_prohibited(character)
            })
        {
            return Err(());
        }

        if normalized.chars().any(idna::is_bidi_r_or_al)
            && (normalized.chars().any(idna::is_bidi_l)
                || !normalized.chars().next().is_some_and(idna::is_bidi_r_or_al)
                || !normalized
                    .chars()
                    .next_back()
                    .is_some_and(idna::is_bidi_r_or_al))
        {
            return Err(());
        }
        Ok(normalized)
    }

    fn dn_attributes_match(left: &AttributeTypeAndValue, right: &AttributeTypeAndValue) -> bool {
        if left.oid != right.oid {
            return false;
        }

        if left.oid == DOMAIN_COMPONENT {
            if left.value_tag_byte() != 0x16 || right.value_tag_byte() != 0x16 {
                return false;
            }
            return match (left.value_as_str(), right.value_as_str()) {
                (Ok(left), Ok(right))
                    if Self::is_valid_dns_label(&left) && Self::is_valid_dns_label(&right) =>
                {
                    left.eq_ignore_ascii_case(&right)
                }
                _ => false,
            };
        }

        if left.oid == EMAIL_ADDRESS {
            if left.value_tag_byte() != 0x16 || right.value_tag_byte() != 0x16 {
                return false;
            }
            return match (left.value_as_str(), right.value_as_str()) {
                (Ok(left), Ok(right))
                    if Self::email_parts(&left).is_some()
                        && Self::email_parts(&right).is_some() =>
                {
                    left.eq_ignore_ascii_case(&right)
                }
                _ => false,
            };
        }

        if Self::is_known_directory_string_oid(left.oid)
            || Self::is_directory_string_tag(left.value_tag_byte())
            || Self::is_directory_string_tag(right.value_tag_byte())
        {
            return match (
                Self::prepare_directory_attribute(left),
                Self::prepare_directory_attribute(right),
            ) {
                (Some(left), Some(right)) => left == right,
                _ => false,
            };
        }

        left == right
    }

    fn is_directory_string_tag(tag: u8) -> bool {
        matches!(tag, 0x0C | 0x13 | 0x14 | 0x1C | 0x1E)
    }

    fn is_known_directory_string_oid(oid: ObjectIdentifier) -> bool {
        matches!(
            oid,
            CN | SURNAME
                | LOCALITY_NAME
                | STATE_OR_PROVINCE_NAME
                | STREET_ADDRESS
                | ORGANIZATION_NAME
                | ORGANIZATIONAL_UNIT_NAME
                | TITLE
                | GIVEN_NAME
                | X520_NAME
                | INITIALS
                | GENERATION_QUALIFIER
                | DN_QUALIFIER
                | PSEUDONYM
                | COUNTRY_NAME
                | SERIAL_NUMBER
        )
    }

    fn prepare_directory_attribute(attribute: &AttributeTypeAndValue) -> Option<String> {
        let tag = attribute.value_tag_byte();
        if !Self::is_directory_string_tag(tag)
            || (attribute.oid == COUNTRY_NAME
                && (tag != 0x13 || attribute.value_content().len() != 2))
            || (attribute.oid == DN_QUALIFIER && tag != 0x13)
            || (attribute.oid == SERIAL_NUMBER
                && (tag != 0x13
                    || attribute.value_content().is_empty()
                    || attribute.value_content().len() > 64))
        {
            return None;
        }
        let value = attribute.value_as_str().ok()?;
        let maximum = match attribute.oid {
            CN | ORGANIZATION_NAME | ORGANIZATIONAL_UNIT_NAME | TITLE | SERIAL_NUMBER => 64,
            LOCALITY_NAME | STATE_OR_PROVINCE_NAME | PSEUDONYM => 128,
            COUNTRY_NAME => 2,
            _ => MAX_DIRECTORY_STRING_CHARS,
        };
        if value.chars().take(maximum + 1).count() > maximum {
            return None;
        }
        Self::prepare_directory_string(&value)
    }

    fn dn_is_comparable(name: &Name) -> bool {
        name.rdns.iter().all(|rdn| {
            !rdn.attributes.is_empty()
                && rdn.attributes.iter().all(|attribute| {
                    if attribute.oid == DOMAIN_COMPONENT {
                        return attribute.value_tag_byte() == 0x16
                            && attribute
                                .value_as_str()
                                .ok()
                                .filter(|value| Self::is_valid_dns_label(value))
                                .is_some();
                    }
                    if attribute.oid == EMAIL_ADDRESS {
                        return attribute.value_tag_byte() == 0x16
                            && attribute
                                .value_as_str()
                                .ok()
                                .filter(|value| Self::email_parts(value).is_some())
                                .is_some();
                    }
                    if Self::is_known_directory_string_oid(attribute.oid)
                        || Self::is_directory_string_tag(attribute.value_tag_byte())
                    {
                        return Self::prepare_directory_attribute(attribute).is_some();
                    }
                    true
                })
        })
    }

    fn prepare_directory_string(value: &str) -> Option<String> {
        let mut mapped = String::new();
        mapped.try_reserve(value.len()).ok()?;
        let mut scratch = Rfc3454CaseFoldScratch::new()?;
        for character in value.chars() {
            if is_unassigned(character) {
                return None;
            }
            if Self::directory_character_maps_to_nothing(character) {
                continue;
            }
            let character = if Self::directory_character_maps_to_space(character) {
                ' '
            } else {
                character
            };
            Self::append_rfc3454_case_fold(character, &mut mapped, &mut scratch)?;
        }

        let mut normalized = String::new();
        normalized.try_reserve(mapped.len()).ok()?;
        Self::append_nfkc(&mapped, &mut normalized)?;
        for character in normalized.chars() {
            let code = character as u32;
            if is_unassigned(character)
                || (0xE000..=0xF8FF).contains(&code)
                || (0xF0000..=0xFFFFD).contains(&code)
                || (0x100000..=0x10FFFD).contains(&code)
                || (0xFDD0..=0xFDEF).contains(&code)
                || code == 0xFFFD
                || matches!(code, 0x0340 | 0x0341 | 0x200E | 0x200F | 0x202A..=0x202E)
                || (0x206A..=0x206F).contains(&code)
                || code & 0xFFFF >= 0xFFFE
            {
                return None;
            }
        }

        Self::handle_insignificant_directory_spaces(&normalized)
    }

    fn owned_string(value: &str) -> Option<String> {
        let mut owned = String::new();
        owned.try_reserve_exact(value.len()).ok()?;
        owned.push_str(value);
        Some(owned)
    }

    fn push_char(output: &mut String, character: char) -> Option<()> {
        output.try_reserve(character.len_utf8()).ok()?;
        output.push(character);
        Some(())
    }

    fn append_nfkc(value: &str, output: &mut String) -> Option<()> {
        for character in value
            .chars()
            .map(Self::rfc3454_normalization_correction)
            .nfkc()
        {
            Self::push_char(output, character)?;
        }
        Some(())
    }

    fn rfc3454_normalization_correction(character: char) -> char {
        match character {
            '\u{2F868}' => '\u{2136A}',
            '\u{2F874}' => '\u{5F33}',
            '\u{2F91F}' => '\u{43AB}',
            '\u{2F95F}' => '\u{7AAE}',
            '\u{2F9BF}' => '\u{4D57}',
            _ => character,
        }
    }

    fn append_rfc3454_case_fold(
        character: char,
        output: &mut String,
        scratch: &mut Rfc3454CaseFoldScratch,
    ) -> Option<()> {
        // RFC 3454 B.2 is the stable result of full folding with NFKC.
        scratch.first_fold.clear();
        Self::append_case_fold_candidate(
            character,
            &mut scratch.first_fold,
            &mut scratch.candidate,
        )?;
        scratch.first_normalized.clear();
        scratch
            .first_normalized
            .try_reserve(scratch.first_fold.len())
            .ok()?;
        Self::append_nfkc(&scratch.first_fold, &mut scratch.first_normalized)?;

        scratch.second_fold.clear();
        scratch
            .second_fold
            .try_reserve(scratch.first_normalized.len())
            .ok()?;
        for character in scratch.first_normalized.chars() {
            Self::append_case_fold_candidate(
                character,
                &mut scratch.second_fold,
                &mut scratch.candidate,
            )?;
        }
        Self::append_nfkc(&scratch.second_fold, output)
    }

    fn append_case_fold_candidate(
        character: char,
        output: &mut String,
        candidate: &mut String,
    ) -> Option<()> {
        candidate.clear();
        for uppercase in character.to_uppercase() {
            for lowercase in uppercase.to_lowercase() {
                Self::push_char(candidate, lowercase)?;
            }
        }

        let mut encoded = [0u8; 4];
        let original = character.encode_utf8(&mut encoded);
        // Modern casing can map a Unicode 3.2 character to a code point that
        // was unassigned then; RFC 3454 B.2 preserves the original instead.
        if candidate.chars().all(|candidate| !is_unassigned(candidate))
            && CaseFold::Full.case_eq(original, candidate)
        {
            output.try_reserve(candidate.len()).ok()?;
            output.push_str(candidate);
        } else {
            Self::push_char(output, character)?;
        }
        Some(())
    }

    fn directory_character_maps_to_nothing(character: char) -> bool {
        matches!(
            character as u32,
            0x0000..=0x0008
                | 0x000E..=0x001F
                | 0x007F..=0x0084
                | 0x0086..=0x009F
                | 0x00AD
                | 0x034F
                | 0x06DD
                | 0x070F
                | 0x1806
                | 0x180B..=0x180E
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x2063
                | 0x206A..=0x206F
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFFC
                | 0xFFF9..=0xFFFB
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
        )
    }

    fn directory_character_maps_to_space(character: char) -> bool {
        matches!(
            character as u32,
            0x0009..=0x000D
                | 0x0020
                | 0x0085
                | 0x00A0
                | 0x1680
                | 0x2000..=0x200A
                | 0x2028..=0x2029
                | 0x202F
                | 0x205F
                | 0x3000
        )
    }

    fn handle_insignificant_directory_spaces(value: &str) -> Option<String> {
        let mut prepared = String::new();
        prepared
            .try_reserve(value.len().checked_mul(2)?.checked_add(2)?)
            .ok()?;
        prepared.push(' ');
        let mut pending_space = false;
        let mut seen_non_space = false;
        let mut characters = value.chars().peekable();
        while let Some(character) = characters.next() {
            let is_space = character == ' '
                && !matches!(
                    characters.peek(),
                    Some(character) if is_combining_mark(*character)
                );
            if is_space {
                pending_space = true;
                continue;
            }
            if seen_non_space && pending_space {
                prepared.push_str("  ");
            }
            prepared.push(character);
            pending_space = false;
            seen_non_space = true;
        }
        if !seen_non_space {
            prepared.push(' ');
            return Some(prepared);
        }
        prepared.push(' ');
        Some(prepared)
    }

    fn is_valid_dns_label(label: &str) -> bool {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return false;
        }
        let bytes = label.as_bytes();
        let std3 = bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
        std3 && (!label
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("xn--"))
            || Self::validate_ace_label(label).is_ok())
    }

    fn is_valid_dns_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 253
            && name.is_ascii()
            && name.split('.').all(Self::is_valid_dns_label)
            && !Self::is_ipv4_address(name)
    }

    fn is_dns_wildcard(name: &str) -> bool {
        name.contains('*')
            && !name.is_empty()
            && name.len() <= 253
            && name.is_ascii()
            && name.split('.').all(|label| {
                if label.is_empty() || label.len() > 63 {
                    return false;
                }
                if label
                    .get(..4)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("xn--"))
                {
                    return false;
                }
                let bytes = label.as_bytes();
                (matches!(bytes[0], b'*') || bytes[0].is_ascii_alphanumeric())
                    && (matches!(bytes[bytes.len() - 1], b'*')
                        || bytes[bytes.len() - 1].is_ascii_alphanumeric())
                    && bytes
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'*'))
            })
    }

    fn is_valid_dns_san(name: &str) -> bool {
        Self::is_valid_dns_name(name) || Self::is_dns_wildcard(name)
    }

    fn is_valid_dns_constraint(constraint: &str) -> bool {
        Self::is_valid_dns_name(constraint)
    }

    fn is_valid_domain_constraint(constraint: &str) -> bool {
        let domain = constraint.strip_prefix('.').unwrap_or(constraint);
        Self::is_valid_dns_name(domain)
    }

    fn is_proper_dns_subdomain(name: &str, domain: &str) -> bool {
        name.len() > domain.len()
            && name[name.len() - domain.len()..].eq_ignore_ascii_case(domain)
            && name.as_bytes()[name.len() - domain.len() - 1] == b'.'
    }

    /// RFC 5280 §4.2.1.10 dNSName containment, compared label by label.
    fn dns_within_constraint(name: &str, constraint: &str) -> bool {
        if !Self::is_valid_dns_name(name) || !Self::is_valid_dns_constraint(constraint) {
            return false;
        }
        name.eq_ignore_ascii_case(constraint) || Self::is_proper_dns_subdomain(name, constraint)
    }

    /// RFC 5280 §4.2.1.10 rfc822Name containment.  A constraint containing `@`
    /// matches a specific mailbox; a leading `.` constrains all sub-domains;
    /// otherwise the constraint is a host name that must match exactly.
    fn email_within_constraint(email: &str, constraint: &str) -> bool {
        let (local_part, host) = match Self::email_parts(email) {
            Some(parts) => parts,
            None => return false,
        };
        if constraint.contains('@') {
            return match Self::email_parts(constraint) {
                Some((constraint_local, constraint_host)) => {
                    Self::email_local_parts_equal(local_part, constraint_local)
                        && Self::email_hosts_equal(host, constraint_host)
                }
                None => false,
            };
        }
        if let Some(domain) = constraint.strip_prefix('.') {
            return Self::is_valid_dns_name(domain) && Self::is_proper_dns_subdomain(host, domain);
        }
        Self::is_valid_dns_name(constraint) && host.eq_ignore_ascii_case(constraint)
    }

    fn email_hosts_equal(left: &str, right: &str) -> bool {
        if left.eq_ignore_ascii_case(right) {
            return true;
        }
        if let (Some(left), Some(right)) = (
            Self::smtp_ipv4_domain_value(left),
            Self::smtp_ipv4_domain_value(right),
        ) {
            return left == right;
        }
        matches!(
            (
                Self::smtp_ipv6_domain_value(left),
                Self::smtp_ipv6_domain_value(right),
            ),
            (Some(left), Some(right)) if left == right
        )
    }

    fn smtp_ipv4_domain_value(domain: &str) -> Option<[u8; 4]> {
        let literal = domain.strip_prefix('[')?.strip_suffix(']')?;
        if literal.contains(':') {
            return None;
        }
        Self::parse_smtp_ipv4_address(literal)
    }

    fn smtp_ipv6_domain_value(domain: &str) -> Option<[u16; 8]> {
        let literal = domain.strip_prefix('[')?.strip_suffix(']')?;
        let prefix = literal.get(..5)?;
        if !prefix.eq_ignore_ascii_case("IPv6:") {
            return None;
        }
        Self::parse_smtp_ipv6_address(&literal[5..])
    }

    fn is_valid_email_constraint(constraint: &str) -> bool {
        if constraint.contains('@') {
            Self::email_parts(constraint).is_some()
        } else {
            Self::is_valid_domain_constraint(constraint)
        }
    }

    fn email_local_parts_equal(left: &str, right: &str) -> bool {
        match (
            Self::canonical_email_local_part(left),
            Self::canonical_email_local_part(right),
        ) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
    }

    fn canonical_email_local_part(local_part: &str) -> Option<String> {
        let Some(quoted) = local_part
            .strip_prefix('"')
            .and_then(|local_part| local_part.strip_suffix('"'))
        else {
            return Self::owned_string(local_part);
        };

        let mut canonical = String::new();
        canonical.try_reserve_exact(quoted.len()).ok()?;
        let mut escaped = false;
        for character in quoted.chars() {
            if escaped {
                canonical.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else {
                canonical.push(character);
            }
        }
        (!escaped).then_some(canonical)
    }

    fn email_parts(mailbox: &str) -> Option<(&str, &str)> {
        if mailbox.is_empty() || mailbox.len() > 254 || !mailbox.is_ascii() {
            return None;
        }

        let bytes = mailbox.as_bytes();
        let separator = if bytes[0] == b'"' {
            let mut escaped = false;
            let mut closing_quote = None;
            for (index, byte) in bytes.iter().copied().enumerate().skip(1) {
                if escaped {
                    if !(0x20..=0x7E).contains(&byte) {
                        return None;
                    }
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    closing_quote = Some(index);
                    break;
                } else if !(0x20..=0x7E).contains(&byte) {
                    return None;
                }
            }
            let closing_quote = closing_quote?;
            if escaped || bytes.get(closing_quote + 1) != Some(&b'@') {
                return None;
            }
            closing_quote + 1
        } else {
            let separator = mailbox.find('@')?;
            let local = &mailbox[..separator];
            if local.is_empty()
                || local.len() > 64
                || local.split('.').any(|atom| {
                    atom.is_empty()
                        || !atom.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(
                                    byte,
                                    b'!' | b'#'
                                        | b'$'
                                        | b'%'
                                        | b'&'
                                        | b'\''
                                        | b'*'
                                        | b'+'
                                        | b'-'
                                        | b'/'
                                        | b'='
                                        | b'?'
                                        | b'^'
                                        | b'_'
                                        | b'`'
                                        | b'{'
                                        | b'|'
                                        | b'}'
                                        | b'~'
                                )
                        })
                })
            {
                return None;
            }
            separator
        };

        let local = &mailbox[..separator];
        let host = &mailbox[separator + 1..];
        if local.len() > 64 || !Self::is_valid_email_domain(host) {
            return None;
        }
        Some((local, host))
    }

    fn is_valid_email_domain(domain: &str) -> bool {
        if Self::is_valid_email_dns_domain(domain) {
            return true;
        }
        let Some(literal) = domain
            .strip_prefix('[')
            .and_then(|domain| domain.strip_suffix(']'))
        else {
            return false;
        };
        if literal.len() > 5 && literal[..5].eq_ignore_ascii_case("IPv6:") {
            Self::is_valid_smtp_ipv6_address(&literal[5..])
        } else if literal.contains(':') {
            Self::is_valid_general_address_literal(literal)
        } else {
            Self::is_valid_smtp_ipv4_address(literal)
        }
    }

    fn is_valid_email_dns_domain(domain: &str) -> bool {
        domain.contains('.') && Self::is_valid_dns_name(domain)
    }

    fn is_valid_general_address_literal(literal: &str) -> bool {
        let Some((tag, content)) = literal.split_once(':') else {
            return false;
        };
        !tag.is_empty()
            && tag.as_bytes()[tag.len() - 1].is_ascii_alphanumeric()
            && tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !content.is_empty()
            && content
                .bytes()
                .all(|byte| (33..=90).contains(&byte) || (94..=126).contains(&byte))
    }

    /// URI constraints apply only to the DNS host component. A leading period
    /// requires at least one additional label; otherwise the host must match
    /// exactly.
    fn uri_within_constraint(uri: &str, constraint: &str) -> bool {
        if !Self::is_valid_domain_constraint(constraint) {
            return false;
        }
        let host = match Self::parse_uri_dns_host(uri) {
            Ok(Some(host)) => host,
            Ok(None) => return false,
            Err(_) => return false,
        };
        if let Some(domain) = constraint.strip_prefix('.') {
            return Self::is_proper_dns_subdomain(&host, domain);
        }
        host.eq_ignore_ascii_case(constraint)
    }

    fn has_dns_constraints(nc: &NameConstraints) -> bool {
        nc.permitted_subtrees
            .iter()
            .chain(nc.excluded_subtrees.iter())
            .flat_map(|subtrees| subtrees.iter())
            .any(|subtree| matches!(subtree.base, GeneralName::DnsName(_)))
    }

    fn has_directory_name_constraints(nc: &NameConstraints) -> bool {
        nc.permitted_subtrees
            .iter()
            .chain(nc.excluded_subtrees.iter())
            .flat_map(|subtrees| subtrees.iter())
            .any(|subtree| matches!(subtree.base, GeneralName::DirectoryName(_)))
    }

    fn has_uri_constraints(nc: &NameConstraints) -> bool {
        nc.permitted_subtrees
            .iter()
            .chain(nc.excluded_subtrees.iter())
            .flat_map(|subtrees| subtrees.iter())
            .any(|subtree| matches!(subtree.base, GeneralName::Uri(_)))
    }

    fn parse_uri_dns_host(uri: &str) -> core::result::Result<Option<String>, ()> {
        if uri.is_empty()
            || !uri.is_ascii()
            || uri.bytes().filter(|byte| *byte == b'#').count() > 1
            || !Self::has_valid_uri_characters(uri)
        {
            return Err(());
        }

        let (scheme, scheme_specific) = uri.split_once(':').ok_or(())?;
        if scheme.is_empty()
            || !scheme.as_bytes()[0].is_ascii_alphabetic()
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
            || scheme_specific.is_empty()
        {
            return Err(());
        }

        let Some(remainder) = scheme_specific.strip_prefix("//") else {
            if scheme_specific.contains(['[', ']']) {
                return Err(());
            }
            return Ok(None);
        };
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if authority.is_empty() || remainder[authority_end..].contains(['[', ']']) {
            return Err(());
        }

        let host_and_port = match authority.rsplit_once('@') {
            Some((userinfo, host)) if !userinfo.contains(['@', '[', ']']) && !host.is_empty() => {
                host
            }
            Some(_) => return Err(()),
            None => authority,
        };

        if let Some(bracketed) = host_and_port.strip_prefix('[') {
            let closing = bracketed.find(']').ok_or(())?;
            let address = &bracketed[..closing];
            let suffix = &bracketed[closing + 1..];
            if !(Self::is_valid_ipv6_address(address) || Self::is_valid_ipvfuture_address(address))
                || (!suffix.is_empty()
                    && (!suffix.starts_with(':')
                        || !suffix[1..].bytes().all(|byte| byte.is_ascii_digit())))
            {
                return Err(());
            }
            return Ok(None);
        }

        let host = match host_and_port.rsplit_once(':') {
            Some((host, port))
                if !host.contains(':') && port.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                host
            }
            Some(_) => return Err(()),
            None => host_and_port,
        };
        if host.is_empty() {
            return Err(());
        }
        let Some(mut host) = Self::normalize_percent_encoded_host(host)? else {
            return Ok(None);
        };
        if host.ends_with('.') {
            host.pop();
        }
        if Self::is_ipv4_address(&host) {
            return Ok(None);
        }
        if !Self::is_valid_dns_name(&host) {
            return Err(());
        }
        Ok(Some(host))
    }

    fn has_valid_uri_characters(uri: &str) -> bool {
        let bytes = uri.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'%' {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                index += 3;
                continue;
            }
            if !(byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b':'
                        | b'/'
                        | b'?'
                        | b'#'
                        | b'['
                        | b']'
                        | b'@'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                ))
            {
                return false;
            }
            index += 1;
        }
        true
    }

    fn is_ipv4_address(host: &str) -> bool {
        let mut octets = host.split('.');
        (0..4).all(|_| {
            octets
                .next()
                .filter(|octet| {
                    !octet.is_empty()
                        && octet.len() <= 3
                        && (octet.len() == 1 || !octet.starts_with('0'))
                        && octet.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|octet| octet.parse::<u8>().ok())
                .is_some()
        }) && octets.next().is_none()
    }

    fn parse_smtp_ipv4_address(address: &str) -> Option<[u8; 4]> {
        let mut octets = address.split('.');
        let mut parsed = [0u8; 4];
        for octet in &mut parsed {
            let value = octets.next()?;
            if value.is_empty()
                || value.len() > 3
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            *octet = value.parse().ok()?;
        }
        octets.next().is_none().then_some(parsed)
    }

    fn is_valid_smtp_ipv4_address(address: &str) -> bool {
        Self::parse_smtp_ipv4_address(address).is_some()
    }

    fn parse_smtp_ipv6_address(address: &str) -> Option<[u16; 8]> {
        if address.is_empty() || address.contains('%') {
            return None;
        }

        let mut compressed = address.split("::");
        let left = compressed.next().unwrap_or("");
        let right = compressed.next();
        if compressed.next().is_some() || right.is_some() && left.contains('.') {
            return None;
        }

        let parse_parts = |side: &str, groups: &mut [u16; 8]| -> Option<usize> {
            if side.is_empty() {
                return Some(0);
            }
            let mut count = 0;
            let mut parts = side.split(':').peekable();
            while let Some(part) = parts.next() {
                if part.is_empty() {
                    return None;
                }
                if part.contains('.') {
                    if parts.peek().is_some() || count > 6 {
                        return None;
                    }
                    let address = Self::parse_smtp_ipv4_address(part)?;
                    groups[count] = u16::from_be_bytes([address[0], address[1]]);
                    groups[count + 1] = u16::from_be_bytes([address[2], address[3]]);
                    count += 2;
                } else {
                    if part.len() > 4 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return None;
                    }
                    if count == groups.len() {
                        return None;
                    }
                    groups[count] = u16::from_str_radix(part, 16).ok()?;
                    count += 1;
                }
            }
            Some(count)
        };

        let mut address = [0u16; 8];
        let left_count = parse_parts(left, &mut address)?;
        match right {
            Some(right) => {
                let mut right_groups = [0u16; 8];
                let right_count = parse_parts(right, &mut right_groups)?;
                if left_count.checked_add(right_count)? > 6 {
                    return None;
                }
                address[8 - right_count..].copy_from_slice(&right_groups[..right_count]);
                Some(address)
            }
            None => (left_count == 8).then_some(address),
        }
    }

    fn is_valid_smtp_ipv6_address(address: &str) -> bool {
        Self::parse_smtp_ipv6_address(address).is_some()
    }

    fn is_valid_ipv6_address(address: &str) -> bool {
        if address.is_empty() || address.contains('%') {
            return false;
        }

        let mut compressed = address.split("::");
        let left = compressed.next().unwrap_or("");
        let right = compressed.next();
        if compressed.next().is_some() {
            return false;
        }
        if right.is_some() && left.contains('.') {
            return false;
        }

        let count_parts = |side: &str| -> Option<usize> {
            if side.is_empty() {
                return Some(0);
            }
            let mut count = 0;
            let mut parts = side.split(':').peekable();
            while let Some(part) = parts.next() {
                if part.is_empty() {
                    return None;
                }
                if part.contains('.') {
                    if parts.peek().is_some() || !Self::is_ipv4_address(part) {
                        return None;
                    }
                    count += 2;
                } else {
                    if part.len() > 4 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return None;
                    }
                    count += 1;
                }
            }
            Some(count)
        };

        let left_count = match count_parts(left) {
            Some(count) => count,
            None => return false,
        };
        match right {
            Some(right) => match count_parts(right) {
                Some(right_count) => left_count + right_count < 8,
                None => false,
            },
            None => left_count == 8,
        }
    }

    fn is_valid_ipvfuture_address(address: &str) -> bool {
        let Some(address) = address
            .strip_prefix('v')
            .or_else(|| address.strip_prefix('V'))
        else {
            return false;
        };
        let Some((version, value)) = address.split_once('.') else {
            return false;
        };
        !version.is_empty()
            && version.bytes().all(|byte| byte.is_ascii_hexdigit())
            && !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'-' | b'.'
                            | b'_'
                            | b'~'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                            | b':'
                    )
            })
    }

    fn is_valid_ip_constraint(constraint: &[u8]) -> bool {
        if !matches!(constraint.len(), 8 | 32) {
            return false;
        }
        let (address, mask) = constraint.split_at(constraint.len() / 2);
        let mut zero_seen = false;
        for byte in mask {
            for bit in (0..8).rev() {
                let set = *byte & (1 << bit) != 0;
                if zero_seen && set {
                    return false;
                }
                zero_seen |= !set;
            }
        }
        address
            .iter()
            .zip(mask)
            .all(|(&address, &mask)| address & !mask == 0)
    }

    /// An IP constraint contains an address followed by a same-sized mask.
    fn ip_within_constraint(ip: &[u8], constraint: &[u8]) -> bool {
        if constraint.len() != ip.len() * 2
            || !matches!(ip.len(), 4 | 16)
            || !Self::is_valid_ip_constraint(constraint)
        {
            return false;
        }
        let (address, mask) = constraint.split_at(ip.len());
        ip.iter()
            .zip(address.iter())
            .zip(mask.iter())
            .all(|((&value, &base), &mask)| value & mask == base & mask)
    }

    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_name_within_constraint(name: &GeneralName, constraint: &GeneralName) -> bool {
        match (name, constraint) {
            (GeneralName::DnsName(name), GeneralName::DnsName(constraint)) => {
                Self::dns_within_constraint(name, constraint)
            }
            (GeneralName::Rfc822Name(name), GeneralName::Rfc822Name(constraint)) => {
                Self::email_within_constraint(name, constraint)
            }
            (GeneralName::Uri(name), GeneralName::Uri(constraint)) => {
                Self::uri_within_constraint(name, constraint)
            }
            (GeneralName::IpAddress(name), GeneralName::IpAddress(constraint)) => {
                Self::ip_within_constraint(name, constraint)
            }
            (GeneralName::DirectoryName(name), GeneralName::DirectoryName(constraint)) => {
                Self::dn_within_subtree(name, constraint)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
impl Default for Validator<RingBackend> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::x509::limbo::LimboRunner;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    #[test]
    fn test_validation_options() {
        let opts = ValidationOptions::default();
        assert!(opts.check_signature);
        assert!(opts.check_extensions);
        assert_eq!(opts.max_chain_depth, 10);

        let opts = ValidationOptions::new()
            .skip_signature_validation()
            .with_max_chain_depth(5);
        assert!(!opts.check_signature);
        assert_eq!(opts.max_chain_depth, 5);
    }

    #[test]
    fn test_validator_creation() {
        let _validator = Validator::new();
        let _validator2 = Validator::default();
    }

    #[test]
    fn test_name_constraints_x509_limbo_conformance() {
        let runner =
            LimboRunner::from_json(include_str!("../../etc/name_constraints_x509_limbo.json"))
                .expect("valid x509-limbo fixture");
        let validator = Validator::default();
        let mut options = ValidationOptions::default().skip_signature_validation();
        options.check_time = false;

        let summary = runner.assert_conformance(|testcase| {
            validator.validate_chain(&testcase.leaf_first_chain()?, &options)
        });

        assert_eq!(summary.total, 6);
        assert_eq!(summary.expected_successes, 2);
        assert_eq!(summary.expected_failures, 4);
        assert_eq!(
            runner.source().repository,
            "https://github.com/C2SP/x509-limbo"
        );
        assert_eq!(
            runner.source().revision,
            "972626160c26b45426bbd8c935a605219bd93207"
        );
        assert_eq!(runner.source().license, "Apache-2.0");
    }

    #[test]
    fn test_rfc5280_core_x509_limbo_conformance() {
        let runner = LimboRunner::from_json(include_str!("../../etc/rfc5280_core_x509_limbo.json"))
            .expect("valid x509-limbo fixture");
        let validator = Validator::default();
        let options = ValidationOptions {
            check_time: false,
            ..ValidationOptions::default()
        };

        let summary = runner.assert_conformance(|testcase| {
            validator.validate_chain(&testcase.leaf_first_chain()?, &options)
        });

        assert_eq!(summary.total, 5);
        assert_eq!(summary.expected_successes, 2);
        assert_eq!(summary.expected_failures, 3);
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
        let opts = ValidationOptions::default();
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
        let opts = ValidationOptions::default();
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
        let opts = ValidationOptions::default();
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
        let opts = ValidationOptions::default();
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
        let opts = ValidationOptions::default().with_max_chain_depth(2); // chain has 3 certs
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
        let opts = ValidationOptions::default();
        let validator = Validator::new();
        assert!(validator.validate_chain(&chain, &opts).is_err());
    }

    #[test]
    fn test_validate_chain_issuer_mismatch_rejected() {
        let ca_256 = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let leaf_384 = load_cert(&test_key_path("ecp384/end_responder.cert.der"));

        // Mixed: ecp384 leaf with ecp256 CA — issuer DN won't match
        let chain = CertificateChain::new(vec![leaf_384, ca_256]);
        let opts = ValidationOptions::default();
        let validator = Validator::new();
        assert!(validator.validate_chain(&chain, &opts).is_err());
    }

    #[test]
    fn test_validate_chain_skip_signature() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions::default().skip_signature_validation();
        let validator = Validator::new();
        assert!(validator.validate_chain(&chain, &opts).is_ok());
    }

    #[test]
    fn test_validate_chain_uses_prepared_issuer_name_matching() {
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let mut inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let mut leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        leaf.tbs_certificate.issuer = dn(&[(ORGANIZATION_NAME, "ACME")]);
        inter.tbs_certificate.subject = dn(&[(ORGANIZATION_NAME, "acme")]);

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let opts = ValidationOptions {
            check_signature: false,
            check_extensions: true,
            check_time: false,
            max_chain_depth: 10,
        };
        assert!(Validator::new().validate_chain(&chain, &opts).is_ok());
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
        let opts = ValidationOptions::default();
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
        let opts = ValidationOptions::default();
        let validator = Validator::new();
        let result = validator.validate_chain(&chain, &opts);
        assert!(result.is_ok(), "ecp384 chain failed: {:?}", result.err());
    }

    // ── Name Constraints (RFC 5280 §4.2.1.10) ──

    use crate::certificate::name::{
        AttributeTypeAndValue, DirectoryString, RDNSequence, RelativeDistinguishedName, CN,
        EMAIL_ADDRESS, ORGANIZATION_NAME,
    };
    use crate::x509::extensions::{GeneralSubtree, NameConstraints};

    fn dn(parts: &[(ObjectIdentifier, &str)]) -> Name {
        let mut seq = RDNSequence::new();
        for (oid, value) in parts {
            let attr = AttributeTypeAndValue::new_utf8(*oid, value).unwrap();
            seq.push(RelativeDistinguishedName::new(attr).unwrap());
        }
        seq
    }

    fn der_wrap(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if value.len() < 128 {
            encoded.push(value.len() as u8);
        } else if value.len() <= u8::MAX as usize {
            encoded.extend_from_slice(&[0x81, value.len() as u8]);
        } else {
            encoded.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]);
        }
        encoded.extend_from_slice(value);
        encoded
    }

    fn name_constraints_der(permitted: &[GeneralName], excluded: &[GeneralName]) -> Vec<u8> {
        use der::Encode;

        fn encode_subtrees(tag: u8, bases: &[GeneralName]) -> Vec<u8> {
            let mut content = Vec::new();
            for base in bases {
                content.extend_from_slice(&der_wrap(0x30, &base.to_der().unwrap()));
            }
            der_wrap(tag, &content)
        }

        let mut content = Vec::new();
        if !permitted.is_empty() {
            content.extend_from_slice(&encode_subtrees(0xA0, permitted));
        }
        if !excluded.is_empty() {
            content.extend_from_slice(&encode_subtrees(0xA1, excluded));
        }
        der_wrap(0x30, &content)
    }

    fn set_extension(
        cert: &mut Certificate,
        oid: ObjectIdentifier,
        critical: bool,
        value: Vec<u8>,
    ) {
        use crate::certificate::{Extension, Extensions};

        let extensions = cert
            .tbs_certificate
            .extensions
            .get_or_insert_with(Extensions::new);
        extensions.extensions.retain(|ext| ext.extn_id != oid);
        extensions
            .extensions
            .push(Extension::new(oid, critical, value).unwrap());
    }

    fn remove_extension(cert: &mut Certificate, oid: ObjectIdentifier) {
        if let Some(extensions) = &mut cert.tbs_certificate.extensions {
            extensions.extensions.retain(|ext| ext.extn_id != oid);
        }
    }

    fn set_subject_alt_names(cert: &mut Certificate, names: Vec<GeneralName>) {
        use der::Encode;
        let san = SubjectAltName::new(names).to_der().unwrap();
        set_extension(cert, SUBJECT_ALT_NAME, false, san);
    }

    fn set_subject_alt_names_unchecked(cert: &mut Certificate, names: &[GeneralName]) {
        use der::Encode;
        let mut content = Vec::new();
        for name in names {
            content.extend_from_slice(&name.to_der().unwrap());
        }
        set_extension(cert, SUBJECT_ALT_NAME, false, der_wrap(0x30, &content));
    }

    fn set_name_constraints(
        cert: &mut Certificate,
        permitted: &[GeneralName],
        excluded: &[GeneralName],
    ) {
        set_extension(
            cert,
            NAME_CONSTRAINTS,
            true,
            name_constraints_der(permitted, excluded),
        );
    }

    fn set_subject_email(cert: &mut Certificate, email: &str) {
        let email = der::asn1::Ia5String::new(email).unwrap();
        cert.tbs_certificate.subject =
            RDNSequence::from_rdns(vec![RelativeDistinguishedName::new(
                AttributeTypeAndValue::new(EMAIL_ADDRESS, DirectoryString::Ia5String(email))
                    .unwrap(),
            )
            .unwrap()]);
    }

    fn constrained_chain(
        san_names: Vec<GeneralName>,
        permitted: Vec<GeneralName>,
        excluded: Vec<GeneralName>,
    ) -> CertificateChain {
        let mut ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let mut leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));

        set_name_constraints(&mut ca, &permitted, &excluded);
        if !san_names.is_empty() {
            set_subject_alt_names(&mut leaf, san_names);
        }

        CertificateChain::new(vec![leaf, inter, ca])
    }

    fn validate_constrained_chain(chain: &CertificateChain) -> Result<()> {
        Validator::new().validate_chain(
            chain,
            &ValidationOptions::default().skip_signature_validation(),
        )
    }

    #[test]
    fn test_dns_within_constraint() {
        type V = Validator<RingBackend>;
        assert!(V::dns_within_constraint("example.com", "example.com"));
        assert!(V::dns_within_constraint("host.example.com", "example.com"));
        assert!(V::dns_within_constraint("a.b.example.com", "example.com"));
        assert!(V::dns_within_constraint("HOST.Example.COM", "example.com"));
        assert!(!V::dns_within_constraint(
            "host.example.com",
            ".example.com"
        ));
        assert!(!V::dns_within_constraint("example.com", ".example.com"));
        assert!(!V::dns_within_constraint(
            "host.example.com",
            "*.example.com"
        ));
        assert!(!V::dns_within_constraint("example.com", "host.example.com"));
        assert!(!V::dns_within_constraint("notexample.com", "example.com"));
        assert!(!V::dns_within_constraint(
            "example.com.evil.com",
            "example.com"
        ));
        assert!(!V::dns_within_constraint("bad..example.com", "example.com"));
        assert!(!V::dns_within_constraint("-bad.example.com", "example.com"));
        assert!(!V::dns_within_constraint("example.com", ""));

        let label63 = "a".repeat(63);
        let label64 = "a".repeat(64);
        assert!(V::is_valid_dns_name(&format!("{label63}.example")));
        assert!(!V::is_valid_dns_name(&format!("{label64}.example")));
        assert!(V::is_valid_dns_name(&format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        )));
        assert!(!V::is_valid_dns_name(&format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        )));
        assert!(V::is_valid_dns_name("3com.example"));
        assert!(!V::is_valid_dns_name("8.8.8.8"));
        assert!(!V::is_valid_dns_name("bad_name.example"));
        assert!(!V::is_valid_dns_name("example.com."));
    }

    #[test]
    fn test_email_within_constraint() {
        type V = Validator<RingBackend>;
        // Specific mailbox.
        assert!(V::email_within_constraint(
            "user@example.com",
            "user@example.com"
        ));
        assert!(!V::email_within_constraint(
            "other@example.com",
            "user@example.com"
        ));
        // Host constraint.
        assert!(V::email_within_constraint(
            "user@example.com",
            "example.com"
        ));
        assert!(!V::email_within_constraint(
            "user@sub.example.com",
            "example.com"
        ));
        // Domain (leading dot) constraint: sub-domains only.
        assert!(V::email_within_constraint(
            "user@sub.example.com",
            ".example.com"
        ));
        assert!(!V::email_within_constraint(
            "user@example.com",
            ".example.com"
        ));
        // RFC 5280 §7.5: mailbox local-parts are case-sensitive.
        assert!(!V::email_within_constraint(
            "user@example.com",
            "User@example.com"
        ));
        assert!(V::email_within_constraint(
            "\"user@device\"@Example.COM",
            "\"user@device\"@example.com"
        ));
        assert!(V::email_within_constraint(
            "\"user\"@example.com",
            "user@example.com"
        ));
        assert!(!V::email_within_constraint(
            "\"User\"@example.com",
            "user@example.com"
        ));
        assert!(V::email_within_constraint(
            "user@[192.0.2.1]",
            "user@[192.0.2.1]"
        ));
        assert!(V::email_within_constraint(
            "user@[192.000.002.001]",
            "user@[192.0.2.1]"
        ));
        assert!(V::email_within_constraint(
            "user@[IPv6:0:0:0:0:0:0:0:1]",
            "user@[IPv6:::1]"
        ));
        assert!(V::email_within_constraint(
            "user@[IPv6:::ffff:192.000.002.001]",
            "user@[IPv6:0:0:0:0:0:ffff:c000:201]"
        ));
        assert!(!V::email_within_constraint(
            "User@[IPv6:0:0:0:0:0:0:0:1]",
            "user@[IPv6:::1]"
        ));
        assert!(V::email_within_constraint(
            "user@[TAG:opaque-value]",
            "user@[tag:opaque-value]"
        ));
        assert!(!V::email_within_constraint(
            "user@@example.com",
            "example.com"
        ));
        assert!(!V::email_within_constraint(
            "user@bad..example.com",
            ".example.com"
        ));
        assert!(V::email_parts("user@[TAG:opaque-value]").is_some());
        assert!(V::email_parts("user@[TAG:opaque@value]").is_some());
        assert!(V::email_parts("user@[192.000.002.001]").is_some());
        assert!(V::email_parts("user@[IPv6:::ffff:192.000.002.001]").is_some());
        assert!(V::email_parts("user@[IPv6:1:2:3:4:5:6:7:8]").is_some());
        assert!(V::email_parts("user@[IPv6:1:2:3:4:5:6:7::]").is_none());
        assert!(V::email_parts("user@[TAG-:opaque-value]").is_none());
        assert!(V::email_parts("user@[TAG:bad\\value]").is_none());
        assert!(V::email_parts("user@localhost").is_none());
    }

    #[test]
    fn test_uri_and_ip_within_constraints() {
        type V = Validator<RingBackend>;

        assert!(V::uri_within_constraint(
            "https://Device.Sub.Example.COM:8443/path",
            ".example.com"
        ));
        assert!(V::uri_within_constraint(
            "spdm://device.example.com/status",
            "device.example.com"
        ));
        assert!(V::uri_within_constraint(
            "https://device.example.com./status",
            "device.example.com"
        ));
        assert!(!V::uri_within_constraint(
            "https://example.com/path",
            ".example.com"
        ));
        assert!(!V::uri_within_constraint(
            "urn:example:device",
            "example.com"
        ));
        assert!(!V::uri_within_constraint(
            "1https://device.example.com/status",
            "device.example.com"
        ));
        assert!(!V::uri_within_constraint(
            "https://bad..example.com/status",
            ".example.com"
        ));
        assert!(!V::uri_within_constraint(
            "https://user@@device.example.com/status",
            "device.example.com"
        ));
        assert!(!V::uri_within_constraint(
            "https://device.example.com/a#b#c",
            "device.example.com"
        ));
        assert!(!V::uri_within_constraint(
            "https://device.example.com/a[bad]",
            "device.example.com"
        ));
        assert_eq!(
            V::parse_uri_dns_host("https://[v1.fe80::abcd]/status"),
            Ok(None)
        );
        assert_eq!(
            V::parse_uri_dns_host("https://%C3%A9xample.com/status"),
            Ok(Some(String::from("xn--xample-9ua.com")))
        );
        assert_eq!(
            V::parse_uri_dns_host("https://shop.%C3%A9xample%E3%80%82com/status"),
            Ok(Some(String::from("shop.xn--xample-9ua.com")))
        );
        assert_eq!(
            V::parse_uri_dns_host("https://%66%61%C3%9F.de/status"),
            Ok(Some(String::from("fass.de")))
        );
        assert_eq!(
            V::parse_uri_dns_host("https://a%C2%AD.example.com/status"),
            Ok(Some(String::from("a.example.com")))
        );
        assert_eq!(
            V::parse_uri_dns_host("https://%E4%BE%8B%E3%81%88.%E3%83%86%E3%82%B9%E3%83%88/status"),
            Ok(Some(String::from("xn--r8jz45g.xn--zckzah")))
        );
        assert_eq!(
            V::parse_uri_dns_host(
                "https://%D9%85%D8%AB%D8%A7%D9%84.%D8%A5%D8%AE%D8%AA%D8%A8%D8%A7%D8%B1/status"
            ),
            Ok(Some(String::from("xn--mgbh0fb.xn--kgbechtv")))
        );
        assert_eq!(
            V::parse_uri_dns_host("https://XN--XAMPLE-9UA.COM/status"),
            Ok(Some(String::from("xn--xample-9ua.com")))
        );
        assert_eq!(
            V::parse_uri_dns_host("https://%D3%80.example.com/status"),
            Ok(Some(String::from("xn--d5a.example.com")))
        );
        assert!(V::is_valid_dns_name("xn--xample-9ua.com"));
        assert!(V::is_valid_dns_name("xn--d5a.example.com"));
        assert!(!V::is_valid_dns_name("xn--e28h.example.com"));
        assert!(!V::is_valid_dns_name("xn--fa-hia.example.com"));
        for invalid in [
            "https://%C3%28.example.com/status",
            "https://%C2%A0.example.com/status",
            "https://%E1%B4%AC.example.com/status",
            "https://%C8%BD.example.com/status",
            "https://%C2%AD.example.com/status",
            "https://a%D8%A7.example.com/status",
            "https://%F0%9F%98%80.example.com/status",
            "https://bad%5Fname.example.com/status",
            "https://xn--.example.com/status",
            "https://xn--abc-.example.com/status",
            "https://xn--0.example.com/status",
            "https://xn--fa-hia.example.com/status",
            "https://xn--e28h.example.com/status",
            "https://xn--a-0hc.example.com/status",
            "https://xn--r6j.example.com/status",
            "https://%C3.%A9.example.com/status",
            "https://%00.example.com/status",
            "https://example%.com/status",
            "https://example%0.com/status",
            "https://example%GG.com/status",
        ] {
            assert_eq!(V::parse_uri_dns_host(invalid), Err(()));
        }
        assert!(V::idna_host_to_ascii(&"a".repeat(MAX_IDNA_HOST_INPUT_BYTES + 1)).is_err());
        let label63 = "a".repeat(63);
        let label64 = "a".repeat(64);
        assert_eq!(V::idna_label_to_ascii(&label63), Ok(label63.clone()));
        assert!(V::idna_label_to_ascii(&label64).is_err());
        let domain253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(domain253.len(), MAX_DNS_NAME_LEN);
        assert_eq!(V::idna_host_to_ascii(&domain253), Ok(domain253.clone()));
        assert_eq!(
            V::idna_host_to_ascii(&format!("{domain253}.")),
            Ok(format!("{domain253}."))
        );
        assert!(V::idna_host_to_ascii(&format!("{domain253}a")).is_err());
        for (label, ace) in [
            ("\u{4c0}", "xn--d5a"),
            ("\u{10a0}", "xn--7md"),
            ("\u{13a0}", "xn--58d"),
        ] {
            assert_eq!(V::nameprep_label(label), Ok(String::from(label)));
            assert_eq!(V::idna_label_to_ascii(label), Ok(String::from(ace)));
            assert!(V::validate_ace_label(ace).is_ok());
        }
        assert_eq!(
            V::nameprep_label("\u{2f868}"),
            V::nameprep_label("\u{2136a}")
        );
        assert_eq!(
            V::parse_uri_dns_host("https://999.1.1.1/status"),
            Ok(Some(String::from("999.1.1.1")))
        );
        assert_eq!(V::parse_uri_dns_host("https://192.0.2.1./status"), Ok(None));
        assert_eq!(
            V::parse_uri_dns_host(
                "https://%EF%BC%91%EF%BC%99%EF%BC%92%E3%80%82%EF%BC%90%E3%80%82%EF%BC%92%E3%80%82%EF%BC%91/status"
            ),
            Ok(None)
        );

        let ipv4_constraint = [192, 0, 2, 0, 255, 255, 255, 0];
        assert!(V::ip_within_constraint(&[192, 0, 2, 42], &ipv4_constraint));
        assert!(!V::ip_within_constraint(&[192, 0, 3, 42], &ipv4_constraint));

        let mut ipv6_constraint = [0u8; 32];
        ipv6_constraint[..4].copy_from_slice(&[0x20, 0x01, 0x0D, 0xB8]);
        ipv6_constraint[16..20].fill(0xFF);
        let mut ipv6 = [0u8; 16];
        ipv6[..4].copy_from_slice(&[0x20, 0x01, 0x0D, 0xB8]);
        ipv6[15] = 1;
        assert!(V::ip_within_constraint(&ipv6, &ipv6_constraint));
        ipv6[3] = 0xB9;
        assert!(!V::ip_within_constraint(&ipv6, &ipv6_constraint));

        assert!(!V::is_valid_ip_constraint(&[192, 0, 2, 0, 255, 0, 255, 0]));
        assert!(!V::is_valid_ip_constraint(&[
            192, 0, 2, 1, 255, 255, 255, 0
        ]));
        assert!(V::is_valid_ip_constraint(&[0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(V::is_valid_ip_constraint(&[
            192, 0, 2, 1, 255, 255, 255, 255
        ]));
        assert!(V::ip_within_constraint(
            &[203, 0, 113, 9],
            &[0, 0, 0, 0, 0, 0, 0, 0]
        ));

        let mut ipv6_host_constraint = [0u8; 32];
        ipv6_host_constraint[..16].copy_from_slice(&ipv6);
        ipv6_host_constraint[16..].fill(0xFF);
        assert!(V::is_valid_ip_constraint(&ipv6_host_constraint));
        assert!(V::ip_within_constraint(&ipv6, &ipv6_host_constraint));

        let excluded_uri = NameConstraints {
            permitted_subtrees: None,
            excluded_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::Uri(String::from(".example.com")),
            }]),
        };
        assert!(V::check_uri_name("urn:example:device", &excluded_uri).is_err());
        assert!(V::check_uri_name("https://192.0.2.1/status", &excluded_uri).is_err());
        assert!(V::check_uri_name("https://[2001:db8::1]/status", &excluded_uri).is_err());
        assert!(V::check_uri_name("https://[v1.fe80::abcd]/status", &excluded_uri).is_err());
        assert!(V::check_uri_name("https://%C3%A9xample.com/status", &excluded_uri).is_ok());
        assert!(V::check_ip_address(&[192, 0, 2], &excluded_uri).is_err());
    }

    #[test]
    fn test_dn_within_subtree() {
        type V = Validator<RingBackend>;
        let base = dn(&[(ORGANIZATION_NAME, "Acme")]);
        let within = dn(&[(ORGANIZATION_NAME, "Acme"), (CN, "device-1")]);
        let outside = dn(&[(ORGANIZATION_NAME, "Other"), (CN, "device-1")]);
        let shorter = dn(&[(CN, "device-1")]);
        assert!(V::dn_within_subtree(&within, &base));
        assert!(V::dn_within_subtree(&base, &base));
        assert!(!V::dn_within_subtree(&outside, &base));
        assert!(!V::dn_within_subtree(&shorter, &base));

        let normalized_base = dn(&[(ORGANIZATION_NAME, "Acme Corporation")]);
        let normalized_name = dn(&[
            (ORGANIZATION_NAME, "  ACME   CORPORATION  "),
            (CN, "device-1"),
        ]);
        assert!(V::dn_within_subtree(&normalized_name, &normalized_base));
        assert!(V::distinguished_names_match(
            &normalized_base,
            &dn(&[(ORGANIZATION_NAME, "acme corporation")])
        ));
        assert!(V::distinguished_names_match(
            &dn(&[(ORGANIZATION_NAME, "Straße")]),
            &dn(&[(ORGANIZATION_NAME, "STRASSE")])
        ));
        assert!(V::distinguished_names_match(
            &dn(&[(ORGANIZATION_NAME, "Acme\0Corp")]),
            &dn(&[(ORGANIZATION_NAME, "AcmeCorp")])
        ));

        let duplicate_semantics = RelativeDistinguishedName::from_attributes(vec![
            AttributeTypeAndValue::new_utf8(ORGANIZATION_NAME, "Acme").unwrap(),
            AttributeTypeAndValue::new_printable(ORGANIZATION_NAME, "Acme").unwrap(),
        ])
        .unwrap();
        let only_one_match = RelativeDistinguishedName::from_attributes(vec![
            AttributeTypeAndValue::new_utf8(ORGANIZATION_NAME, "Acme").unwrap(),
            AttributeTypeAndValue::new_printable(ORGANIZATION_NAME, "Other").unwrap(),
        ])
        .unwrap();
        assert!(!V::relative_distinguished_names_match(
            &duplicate_semantics,
            &only_one_match
        ));

        let lower_email = der::asn1::Ia5String::new("user@example.com").unwrap();
        let upper_local = der::asn1::Ia5String::new("User@example.com").unwrap();
        let upper_host = der::asn1::Ia5String::new("user@EXAMPLE.COM").unwrap();
        let email_attr = |email| {
            AttributeTypeAndValue::new(EMAIL_ADDRESS, DirectoryString::Ia5String(email)).unwrap()
        };
        assert!(V::dn_attributes_match(
            &email_attr(lower_email.clone()),
            &email_attr(upper_local)
        ));
        assert!(V::dn_attributes_match(
            &email_attr(lower_email),
            &email_attr(upper_host)
        ));

        let excluded = NameConstraints {
            permitted_subtrees: None,
            excluded_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::DirectoryName(normalized_base),
            }]),
        };
        assert!(V::check_directory_name(&normalized_name, &excluded).is_err());
    }

    #[test]
    fn test_rfc4518_directory_string_preparation() {
        type V = Validator<RingBackend>;

        assert_eq!(
            V::prepare_directory_string("  ACME\tCORPORATION  "),
            Some(String::from(" acme  corporation "))
        );
        assert_eq!(
            V::prepare_directory_string("A\0\u{200b}\u{fffc}B"),
            Some(String::from(" ab "))
        );
        assert_eq!(
            V::prepare_directory_string("a \u{301}"),
            Some(String::from(" a \u{301} "))
        );
        assert_eq!(
            V::prepare_directory_string("\u{2ff0}"),
            Some(String::from(" \u{2ff0} "))
        );
        assert_eq!(V::prepare_directory_string("   "), Some(String::from("  ")));

        for preserved in ["\u{4c0}", "\u{10a0}", "\u{13a0}"] {
            assert_eq!(
                V::prepare_directory_string(preserved),
                Some(format!(" {preserved} "))
            );
        }

        for prohibited in ["\u{fffd}", "\u{fdd0}", "\u{e000}", "\u{1f600}"] {
            assert!(V::prepare_directory_string(prohibited).is_none());
        }

        for (unicode_32, corrected_later) in [
            ("\u{2f868}", "\u{2136a}"),
            ("\u{2f874}", "\u{5f33}"),
            ("\u{2f91f}", "\u{43ab}"),
            ("\u{2f95f}", "\u{7aae}"),
            ("\u{2f9bf}", "\u{4d57}"),
        ] {
            assert_eq!(
                V::prepare_directory_string(unicode_32),
                V::prepare_directory_string(corrected_later)
            );
        }
        assert_eq!(
            V::prepare_directory_string("a \u{6de}"),
            Some(String::from(" a \u{6de} "))
        );
        assert_eq!(
            V::prepare_directory_string("a \u{1885}"),
            Some(String::from(" a  \u{1885} "))
        );

        assert!(V::distinguished_names_match(
            &dn(&[(ORGANIZATION_NAME, "SŚ")]),
            &dn(&[(ORGANIZATION_NAME, "ß\u{301}")])
        ));
        assert!(V::distinguished_names_match(
            &dn(&[(ORGANIZATION_NAME, "℡")]),
            &dn(&[(ORGANIZATION_NAME, "TEL")])
        ));
        assert!(V::distinguished_names_match(
            &dn(&[(ORGANIZATION_NAME, "\u{3d2}")]),
            &dn(&[(ORGANIZATION_NAME, "\u{3c5}")])
        ));
        assert!(!V::distinguished_names_match(
            &dn(&[(ORGANIZATION_NAME, "\u{131}")]),
            &dn(&[(ORGANIZATION_NAME, "i")])
        ));
        assert!(!V::distinguished_names_match(
            &dn(&[(ORGANIZATION_NAME, "\u{10a0}")]),
            &dn(&[(ORGANIZATION_NAME, "\u{2d00}")])
        ));

        let utf8 = AttributeTypeAndValue::new_utf8(ORGANIZATION_NAME, "Acme").unwrap();
        let bmp = AttributeTypeAndValue::new(
            ORGANIZATION_NAME,
            DirectoryString::BmpString(vec![0, b'A', 0, b'c', 0, b'm', 0, b'e']),
        )
        .unwrap();
        let universal = AttributeTypeAndValue::new(
            ORGANIZATION_NAME,
            DirectoryString::UniversalString(vec![
                0, 0, 0, b'A', 0, 0, 0, b'c', 0, 0, 0, b'm', 0, 0, 0, b'e',
            ]),
        )
        .unwrap();
        assert!(V::dn_attributes_match(&utf8, &bmp));
        assert!(V::dn_attributes_match(&utf8, &universal));

        assert!(
            AttributeTypeAndValue::new(ORGANIZATION_NAME, DirectoryString::BmpString(vec![0]))
                .is_err()
        );

        use der::Decode;
        let wrong_cn_type = AttributeTypeAndValue::from_der(&[
            0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x05, 0x00,
        ])
        .unwrap();
        for final_arc in [41, 43, 44, 65] {
            let wrong_name_type = AttributeTypeAndValue::from_der(&[
                0x30, 0x07, 0x06, 0x03, 0x55, 0x04, final_arc, 0x05, 0x00,
            ])
            .unwrap();
            let malformed_rdn = RelativeDistinguishedName::new(wrong_name_type).unwrap();
            let malformed_name = RDNSequence::from_rdns(vec![malformed_rdn]);
            assert!(!V::dn_is_comparable(&malformed_name));
        }
        let wrong_dn_qualifier_type = AttributeTypeAndValue::from_der(&[
            0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x2E, 0x0C, 0x02, b'A', b'1',
        ])
        .unwrap();
        assert!(!V::dn_is_comparable(&RDNSequence::from_rdns(vec![
            RelativeDistinguishedName::new(wrong_dn_qualifier_type).unwrap(),
        ])));
        assert!(V::dn_attributes_match(
            &AttributeTypeAndValue::new_utf8(INITIALS, "J.R.").unwrap(),
            &AttributeTypeAndValue::new_printable(INITIALS, "j.r.").unwrap(),
        ));
        assert!(V::dn_attributes_match(
            &AttributeTypeAndValue::new_printable(DN_QUALIFIER, "Branch-A").unwrap(),
            &AttributeTypeAndValue::new_printable(DN_QUALIFIER, "branch-a").unwrap(),
        ));
        for (oid, maximum) in [
            (CN, 64),
            (LOCALITY_NAME, 128),
            (STATE_OR_PROVINCE_NAME, 128),
            (ORGANIZATION_NAME, 64),
            (ORGANIZATIONAL_UNIT_NAME, 64),
            (TITLE, 64),
            (PSEUDONYM, 128),
        ] {
            let valid = AttributeTypeAndValue::new_utf8(oid, &"a".repeat(maximum)).unwrap();
            let overlong = AttributeTypeAndValue::new_utf8(oid, &"a".repeat(maximum + 1)).unwrap();
            assert!(V::dn_is_comparable(&RDNSequence::from_rdns(vec![
                RelativeDistinguishedName::new(valid).unwrap(),
            ])));
            assert!(!V::dn_is_comparable(&RDNSequence::from_rdns(vec![
                RelativeDistinguishedName::new(overlong).unwrap(),
            ])));
        }
        let malformed_dn =
            RDNSequence::from_rdns(vec![RelativeDistinguishedName::new(wrong_cn_type).unwrap()]);
        assert!(!V::dn_is_comparable(&malformed_dn));

        let mut cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        cert.tbs_certificate.subject = malformed_dn;
        assert!(V::validate_required_names(&cert).is_ok());
        cert.tbs_certificate.subject = cert.tbs_certificate.issuer.clone();
        cert.tbs_certificate.issuer = RDNSequence::new();
        assert!(V::validate_required_names(&cert).is_err());
    }

    #[test]
    fn test_unconstrained_leaf_accepts_unpreparable_subject() {
        let mut leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        leaf.tbs_certificate.subject = dn(&[(ORGANIZATION_NAME, "Device \u{20b9}")]);
        assert!(!Validator::<RingBackend>::dn_is_comparable(
            &leaf.tbs_certificate.subject
        ));

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let options = ValidationOptions {
            check_signature: false,
            check_extensions: true,
            check_time: false,
            max_chain_depth: 10,
        };
        assert!(Validator::new().validate_chain(&chain, &options).is_ok());
    }

    #[test]
    fn test_unrelated_name_constraint_accepts_unpreparable_subject() {
        let mut chain = constrained_chain(
            vec![GeneralName::DnsName(String::from("device.example"))],
            vec![GeneralName::DnsName(String::from("device.example"))],
            vec![],
        );
        chain.certificates[0].tbs_certificate.subject =
            dn(&[(ORGANIZATION_NAME, "Device \u{20b9}")]);

        assert!(validate_constrained_chain(&chain).is_ok());
    }

    #[test]
    fn test_unconstrained_chain_accepts_exact_legacy_printable_issuer_name() {
        use der::Decode;

        let attribute = AttributeTypeAndValue::from_der(&[
            0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x03, b'A', b'&', b'T',
        ])
        .unwrap();
        let legacy_name =
            RDNSequence::from_rdns(vec![RelativeDistinguishedName::new(attribute).unwrap()]);
        assert!(!Validator::<RingBackend>::dn_is_comparable(&legacy_name));

        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let mut inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let mut ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        inter.tbs_certificate.issuer = legacy_name.clone();
        ca.tbs_certificate.subject = legacy_name.clone();
        ca.tbs_certificate.issuer = legacy_name;

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let options = ValidationOptions {
            check_signature: false,
            check_extensions: true,
            check_time: false,
            max_chain_depth: 10,
        };
        assert!(Validator::new().validate_chain(&chain, &options).is_ok());
    }

    #[test]
    fn test_legacy_subject_email_is_constrained_without_san() {
        type V = Validator<RingBackend>;
        let email = der::asn1::Ia5String::new("blocked@example.com").unwrap();
        let subject = RDNSequence::from_rdns(vec![RelativeDistinguishedName::new(
            AttributeTypeAndValue::new(EMAIL_ADDRESS, DirectoryString::Ia5String(email)).unwrap(),
        )
        .unwrap()]);
        let nc = NameConstraints {
            permitted_subtrees: None,
            excluded_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::Rfc822Name(String::from("blocked@example.com")),
            }]),
        };

        assert!(V::check_names_against_constraints(&subject, None, &nc).is_err());
    }

    #[test]
    fn test_parse_name_constraints_dns_permitted() {
        // NameConstraints ::= SEQUENCE {
        //   permittedSubtrees [0] { GeneralSubtree { base dNSName "example.com" } } }
        let der = [
            0x30, 0x11, 0xA0, 0x0F, 0x30, 0x0D, 0x82, 0x0B, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', b'.', b'c', b'o', b'm',
        ];
        use der::Decode;
        let nc = NameConstraints::from_der(&der).unwrap();
        let permitted = nc.permitted_subtrees.expect("permitted present");
        assert_eq!(permitted.len(), 1);
        match &permitted[0].base {
            GeneralName::DnsName(d) => assert_eq!(d, "example.com"),
            other => panic!("unexpected base: {:?}", other),
        }
        assert!(nc.excluded_subtrees.is_none());
    }

    #[test]
    fn test_parse_name_constraints_dns_excluded() {
        let der = [
            0x30, 0x11, 0xA1, 0x0F, 0x30, 0x0D, 0x82, 0x0B, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', b'.', b'c', b'o', b'm',
        ];
        use der::Decode;
        let nc = NameConstraints::from_der(&der).unwrap();
        assert!(nc.permitted_subtrees.is_none());
        let excluded = nc.excluded_subtrees.expect("excluded present");
        assert_eq!(excluded.len(), 1);
    }

    #[test]
    fn test_check_dns_name_permitted_and_excluded() {
        type V = Validator<RingBackend>;
        let nc = NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::DnsName(String::from("example.com")),
            }]),
            excluded_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::DnsName(String::from("evil.example.com")),
            }]),
        };
        // Within permitted and not excluded.
        assert!(V::check_dns_name("host.example.com", &nc).is_ok());
        // Outside permitted.
        assert!(V::check_dns_name("host.other.com", &nc).is_err());
        // Excluded overrides permitted.
        assert!(V::check_dns_name("evil.example.com", &nc).is_err());
    }

    #[test]
    fn test_check_directory_name_enforcement() {
        type V = Validator<RingBackend>;
        let nc = NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::DirectoryName(dn(&[(ORGANIZATION_NAME, "Acme")])),
            }]),
            excluded_subtrees: None,
        };
        let within = dn(&[(ORGANIZATION_NAME, "Acme"), (CN, "dev")]);
        let outside = dn(&[(ORGANIZATION_NAME, "Other"), (CN, "dev")]);
        assert!(V::check_directory_name(&within, &nc).is_ok());
        assert!(V::check_directory_name(&outside, &nc).is_err());
    }

    #[test]
    fn test_name_constraints_extension_profile_is_enforced() {
        type V = Validator<RingBackend>;
        let permitted = [GeneralName::DnsName(String::from("example.com"))];

        let mut ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        set_extension(
            &mut ca,
            NAME_CONSTRAINTS,
            false,
            name_constraints_der(&permitted, &[]),
        );
        assert!(V::validate_name_constraints_extension(&ca, true).is_err());

        let mut leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        set_extension(
            &mut leaf,
            NAME_CONSTRAINTS,
            true,
            name_constraints_der(&permitted, &[]),
        );
        assert!(V::validate_name_constraints_extension(&leaf, false).is_err());

        let mut legacy_ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        remove_extension(&mut legacy_ca, BASIC_CONSTRAINTS);
        set_name_constraints(&mut legacy_ca, &permitted, &[]);
        assert!(V::validate_name_constraints_extension(&legacy_ca, true).is_ok());
        assert!(V::validate_name_constraints_extension(&legacy_ca, false).is_err());

        let mut legacy_chain = constrained_chain(
            vec![GeneralName::DnsName(String::from("device.example.com"))],
            permitted.to_vec(),
            vec![],
        );
        remove_extension(&mut legacy_chain.certificates[2], BASIC_CONSTRAINTS);
        assert!(validate_constrained_chain(&legacy_chain).is_ok());

        let unsupported = NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::OtherName(vec![
                    0x06, 0x03, 0x2A, 0x03, 0x04, 0xA0, 0x03, 0x02, 0x01, 0x01,
                ]),
            }]),
            excluded_subtrees: None,
        };
        assert!(V::validate_constraint_bases(&unsupported).is_ok());

        let malformed_ip = NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::IpAddress(vec![192, 0, 2, 0]),
            }]),
            excluded_subtrees: None,
        };
        assert!(V::validate_constraint_bases(&malformed_ip).is_err());

        let empty_dns = NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::DnsName(String::new()),
            }]),
            excluded_subtrees: None,
        };
        assert!(V::validate_constraint_bases(&empty_dns).is_err());
        assert!(!V::dns_within_constraint("outside.example", ""));
    }

    #[test]
    fn test_unsupported_other_name_constraint_is_noop_until_form_appears() {
        // OtherName { type-id 1.2.3.4, value [0] EXPLICIT INTEGER 1 }.
        let other_name = GeneralName::OtherName(vec![
            0x06, 0x03, 0x2A, 0x03, 0x04, 0xA0, 0x03, 0x02, 0x01, 0x01,
        ]);

        let mut absent = constrained_chain(vec![], vec![other_name.clone()], vec![]);
        remove_extension(&mut absent.certificates[0], SUBJECT_ALT_NAME);
        remove_extension(&mut absent.certificates[1], SUBJECT_ALT_NAME);
        let absent_result = validate_constrained_chain(&absent);
        assert!(absent_result.is_ok(), "unexpected error: {absent_result:?}");

        let mut present = constrained_chain(vec![other_name.clone()], vec![other_name], vec![]);
        remove_extension(&mut present.certificates[1], SUBJECT_ALT_NAME);
        assert!(validate_constrained_chain(&present).is_err());
    }

    #[test]
    fn test_empty_san_cannot_bypass_legacy_email_constraint() {
        let mut chain = constrained_chain(
            vec![],
            vec![],
            vec![GeneralName::Rfc822Name(String::from("blocked@example.com"))],
        );
        let email = der::asn1::Ia5String::new("blocked@example.com").unwrap();
        chain.certificates[0].tbs_certificate.subject =
            RDNSequence::from_rdns(vec![RelativeDistinguishedName::new(
                AttributeTypeAndValue::new(EMAIL_ADDRESS, DirectoryString::Ia5String(email))
                    .unwrap(),
            )
            .unwrap()]);
        set_extension(
            &mut chain.certificates[0],
            SUBJECT_ALT_NAME,
            false,
            vec![0x30, 0x00],
        );

        assert!(validate_constrained_chain(&chain).is_err());
    }

    #[test]
    fn test_constraints_accumulate_in_trust_anchor_to_target_order() {
        let mut chain = constrained_chain(
            vec![GeneralName::DnsName(String::from("device.sub.example.com"))],
            vec![GeneralName::DnsName(String::from("example.com"))],
            vec![],
        );
        set_name_constraints(
            &mut chain.certificates[1],
            &[GeneralName::DnsName(String::from("sub.example.com"))],
            &[GeneralName::DnsName(String::from(
                "blocked.sub.example.com",
            ))],
        );
        set_subject_alt_names(
            &mut chain.certificates[1],
            vec![GeneralName::DnsName(String::from("ca.example.com"))],
        );

        // The intermediate's constraints take effect after that certificate:
        // its own name need only satisfy the trust anchor's state.
        assert!(validate_constrained_chain(&chain).is_ok());

        let mut outside_intersection = chain.clone();
        set_subject_alt_names(
            &mut outside_intersection.certificates[0],
            vec![GeneralName::DnsName(String::from("device.example.com"))],
        );
        assert!(validate_constrained_chain(&outside_intersection).is_err());

        let mut accumulated_exclusion = chain;
        set_subject_alt_names(
            &mut accumulated_exclusion.certificates[0],
            vec![GeneralName::DnsName(String::from(
                "blocked.sub.example.com",
            ))],
        );
        assert!(validate_constrained_chain(&accumulated_exclusion).is_err());

        let mut later_widening = constrained_chain(
            vec![GeneralName::DnsName(String::from("device.example.com"))],
            vec![GeneralName::DnsName(String::from("sub.example.com"))],
            vec![],
        );
        set_name_constraints(
            &mut later_widening.certificates[1],
            &[GeneralName::DnsName(String::from("example.com"))],
            &[],
        );
        assert!(validate_constrained_chain(&later_widening).is_err());
    }

    #[test]
    fn test_every_present_name_is_checked_and_absent_forms_are_allowed() {
        let permitted = vec![GeneralName::DnsName(String::from("example.com"))];

        let mixed_names = constrained_chain(
            vec![
                GeneralName::DnsName(String::from("allowed.example.com")),
                GeneralName::DnsName(String::from("outside.test")),
            ],
            permitted.clone(),
            vec![],
        );
        assert!(validate_constrained_chain(&mixed_names).is_err());

        let no_dns_name = constrained_chain(
            vec![GeneralName::IpAddress(vec![192, 0, 2, 1])],
            permitted,
            vec![],
        );
        assert!(validate_constrained_chain(&no_dns_name).is_ok());
    }

    #[test]
    fn test_name_constraints_reject_malformed_supported_bases() {
        type V = Validator<RingBackend>;
        for malformed in [
            GeneralName::DnsName(String::new()),
            GeneralName::DnsName(String::from(".example.com")),
            GeneralName::DnsName(String::from("*.example.com")),
            GeneralName::DnsName(String::from("bad..example.com")),
            GeneralName::Rfc822Name(String::from("@example.com")),
            GeneralName::Rfc822Name(String::from("example..com")),
            GeneralName::Rfc822Name(String::from("user@@example.com")),
            GeneralName::DirectoryName(dn(&[(ORGANIZATION_NAME, "Acme\u{fffd}Corp")])),
            GeneralName::Uri(String::from("https://example.com")),
            GeneralName::Uri(String::from("bad_domain.example")),
            GeneralName::IpAddress(vec![192, 0, 2, 1, 255, 255, 255, 0]),
            GeneralName::IpAddress(vec![192, 0, 2, 0, 255, 0, 255, 0]),
            GeneralName::OtherName(vec![]),
        ] {
            let constraints = NameConstraints {
                permitted_subtrees: Some(vec![GeneralSubtree { base: malformed }]),
                excluded_subtrees: None,
            };
            assert!(V::validate_constraint_bases(&constraints).is_err());
        }
    }

    #[test]
    fn test_registered_id_constraint_is_deferred_until_form_appears() {
        let registered_id =
            GeneralName::RegisteredId(ObjectIdentifier::new_unwrap("1.2.840.113549"));

        let mut absent = constrained_chain(vec![], vec![registered_id.clone()], vec![]);
        remove_extension(&mut absent.certificates[0], SUBJECT_ALT_NAME);
        remove_extension(&mut absent.certificates[1], SUBJECT_ALT_NAME);
        assert!(validate_constrained_chain(&absent).is_ok());

        let mut present =
            constrained_chain(vec![registered_id.clone()], vec![registered_id], vec![]);
        remove_extension(&mut present.certificates[1], SUBJECT_ALT_NAME);
        assert!(validate_constrained_chain(&present).is_err());
    }

    #[test]
    fn test_validate_rejects_malformed_subject_alt_name() {
        let mut cert = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        set_extension(
            &mut cert,
            SUBJECT_ALT_NAME,
            true,
            vec![0x30, 0x07, 0x87, 0x05, 0, 0, 0, 0, 0],
        );

        let mut options = ValidationOptions::default().skip_signature_validation();
        options.check_time = false;
        assert!(matches!(
            Validator::new().validate(&cert, &options),
            Err(Error::Asn1(_))
        ));
    }

    #[test]
    fn test_name_constraints_parser_errors_propagate_when_extension_checks_are_disabled() {
        type V = Validator<RingBackend>;
        let malformed = vec![0x30, 0x02, 0xA0, 0x00];
        let mut ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        set_extension(&mut ca, NAME_CONSTRAINTS, true, malformed);

        let mut options = ValidationOptions::default().skip_signature_validation();
        options.check_extensions = false;
        options.check_time = false;
        let chain = CertificateChain::new(vec![
            load_cert(&test_key_path("ecp256/end_responder.cert.der")),
            load_cert(&test_key_path("ecp256/inter.cert.der")),
            ca,
        ]);

        assert!(matches!(
            V::validate_name_constraints_extension(&chain.certificates[2], true),
            Err(Error::Asn1(_))
        ));
        assert!(matches!(
            Validator::new().validate_chain(&chain, &options),
            Err(Error::Asn1(_))
        ));
    }

    #[test]
    fn test_duplicate_extension_oids_are_rejected_before_constraint_processing() {
        type V = Validator<RingBackend>;
        let permitted = [GeneralName::DnsName(String::from("example.com"))];
        let mut ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        set_extension(
            &mut ca,
            NAME_CONSTRAINTS,
            true,
            name_constraints_der(&permitted, &[]),
        );
        ca.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .extensions
            .push(
                crate::certificate::Extension::new(
                    NAME_CONSTRAINTS,
                    true,
                    vec![0x30, 0x02, 0xA0, 0x00],
                )
                .unwrap(),
            );

        let mut options = ValidationOptions::default().skip_signature_validation();
        options.check_time = false;
        assert!(matches!(
            Validator::new().validate(&ca, &options),
            Err(Error::ExtensionError(
                crate::error::ExtensionError::DuplicateExtension(_)
            ))
        ));
        assert!(matches!(
            V::validate_name_constraints_extension(&ca, true),
            Err(Error::ExtensionError(
                crate::error::ExtensionError::DuplicateExtension(_)
            ))
        ));

        options.check_extensions = false;
        let chain = CertificateChain::new(vec![
            load_cert(&test_key_path("ecp256/end_responder.cert.der")),
            load_cert(&test_key_path("ecp256/inter.cert.der")),
            ca,
        ]);
        assert!(matches!(
            Validator::new().validate_chain(&chain, &options),
            Err(Error::ExtensionError(
                crate::error::ExtensionError::DuplicateExtension(_)
            ))
        ));
    }

    #[test]
    fn test_subject_alt_name_general_name_profile_validation() {
        use der::Encode;
        type V = Validator<RingBackend>;

        let valid_names = [
            GeneralName::DnsName(String::from("Device.Example.com")),
            GeneralName::DnsName(String::from("*.example.com")),
            GeneralName::DnsName(String::from("service*.example.com")),
            GeneralName::Rfc822Name(String::from("user@example.com")),
            GeneralName::Rfc822Name(String::from("user@[192.0.2.1]")),
            GeneralName::Rfc822Name(String::from("user@[TAG:opaque-value]")),
            GeneralName::Uri(String::from("spdm://device.example.com/status")),
            GeneralName::Uri(String::from("https://device.example.com./status")),
            GeneralName::Uri(String::from("https://[v1.fe80::abcd]/status")),
            GeneralName::Uri(String::from("https://%C3%A9xample.com/status")),
            GeneralName::Uri(String::from("urn:example:device")),
            GeneralName::IpAddress(vec![192, 0, 2, 1]),
            GeneralName::IpAddress(vec![0; 16]),
        ];
        for name in valid_names {
            let extension = crate::certificate::Extension::new(
                SUBJECT_ALT_NAME,
                false,
                SubjectAltName::new(vec![name]).to_der().unwrap(),
            )
            .unwrap();
            assert!(V::decode_subject_alt_name(&extension).is_ok());
        }

        let malformed_names = [
            GeneralName::DnsName(String::from("bad..example.com")),
            GeneralName::DnsName(String::from("*..example.com")),
            GeneralName::DnsName(String::from("8.8.8.8")),
            GeneralName::Rfc822Name(String::from("user@@example.com")),
            GeneralName::DirectoryName(RDNSequence::new()),
            GeneralName::DirectoryName(dn(&[(ORGANIZATION_NAME, "Acme\u{fffd}")])),
            GeneralName::Uri(String::from("relative/path")),
            GeneralName::Uri(String::from("https://bad..example.com")),
            GeneralName::Uri(String::from("https://example.com/a#b#c")),
        ];
        for name in malformed_names {
            let extension = crate::certificate::Extension::new(
                SUBJECT_ALT_NAME,
                false,
                SubjectAltName::new(vec![name]).to_der().unwrap(),
            )
            .unwrap();
            assert!(V::decode_subject_alt_name(&extension).is_err());
        }

        for malformed in [
            vec![0x30, 0x02, 0xA0, 0x00],
            vec![0x30, 0x02, 0xA3, 0x00],
            vec![0x30, 0x02, 0xA5, 0x00],
        ] {
            let extension =
                crate::certificate::Extension::new(SUBJECT_ALT_NAME, false, malformed).unwrap();
            assert!(V::decode_subject_alt_name(&extension).is_err());
        }
    }

    #[test]
    fn test_limbo_malformed_constrained_sans_fail_closed() {
        let malformed = [
            (
                GeneralName::DnsName(String::from(".example.com")),
                GeneralName::DnsName(String::from("example.com")),
            ),
            (
                GeneralName::IpAddress(vec![192, 0, 2, 0, 255, 255, 255, 0]),
                GeneralName::IpAddress(vec![192, 0, 2, 0, 255, 255, 255, 0]),
            ),
            (
                GeneralName::IpAddress(vec![0; 32]),
                GeneralName::IpAddress(vec![0; 32]),
            ),
            (
                GeneralName::Rfc822Name(String::from("invalid@address@example.com")),
                GeneralName::Rfc822Name(String::from("example.com")),
            ),
        ];

        for (san, constraint) in malformed {
            let mut chain = constrained_chain(vec![], vec![constraint], vec![]);
            set_subject_alt_names_unchecked(&mut chain.certificates[0], &[san]);
            assert!(validate_constrained_chain(&chain).is_err());
        }
    }

    #[test]
    fn test_wildcard_dns_san_is_rejected_only_when_dns_is_constrained() {
        let wildcard = GeneralName::DnsName(String::from("*.example.com"));

        let unrelated_constraint = constrained_chain(
            vec![wildcard.clone()],
            vec![GeneralName::IpAddress(vec![0, 0, 0, 0, 0, 0, 0, 0])],
            vec![],
        );
        assert!(validate_constrained_chain(&unrelated_constraint).is_ok());

        let dns_constraint = constrained_chain(
            vec![wildcard],
            vec![GeneralName::DnsName(String::from("example.com"))],
            vec![GeneralName::DnsName(String::from("bar.example.com"))],
        );
        assert!(validate_constrained_chain(&dns_constraint).is_err());
    }

    #[test]
    fn test_unsupported_constraint_is_conditional_on_name_form_presence() {
        let other_name = GeneralName::OtherName(vec![0x06, 0x01, 0x2A, 0xA0, 0x02, 0x05, 0x00]);
        let permitted_dns = GeneralName::DnsName(String::from("example.com"));

        let no_other_name = constrained_chain(
            vec![GeneralName::DnsName(String::from("example.com"))],
            vec![permitted_dns.clone()],
            vec![other_name.clone()],
        );
        assert!(validate_constrained_chain(&no_other_name).is_ok());

        let matching_form = constrained_chain(
            vec![
                GeneralName::DnsName(String::from("example.com")),
                other_name.clone(),
            ],
            vec![permitted_dns],
            vec![other_name],
        );
        assert!(validate_constrained_chain(&matching_form).is_err());
    }

    #[test]
    fn test_validate_chain_enforces_dns_and_excluded_precedence() {
        let permitted = GeneralName::DnsName(String::from("example.com"));

        let allowed = constrained_chain(
            vec![GeneralName::DnsName(String::from("host.example.com"))],
            vec![permitted.clone()],
            vec![],
        );
        assert!(validate_constrained_chain(&allowed).is_ok());

        let outside = constrained_chain(
            vec![GeneralName::DnsName(String::from("host.other.test"))],
            vec![permitted.clone()],
            vec![],
        );
        assert!(validate_constrained_chain(&outside).is_err());

        let excluded = constrained_chain(
            vec![GeneralName::DnsName(String::from("blocked.example.com"))],
            vec![permitted],
            vec![GeneralName::DnsName(String::from("blocked.example.com"))],
        );
        assert!(validate_constrained_chain(&excluded).is_err());
    }

    #[test]
    fn test_multiple_permitted_subtrees_union_and_intersection() {
        let mut chain = constrained_chain(
            vec![GeneralName::DnsName(String::from(
                "api.service.example.com",
            ))],
            vec![
                GeneralName::DnsName(String::from("example.com")),
                GeneralName::DnsName(String::from("unrelated.test")),
            ],
            vec![],
        );
        set_name_constraints(
            &mut chain.certificates[1],
            &[
                GeneralName::DnsName(String::from("service.example.com")),
                GeneralName::DnsName(String::from("other.test")),
            ],
            &[],
        );
        assert!(validate_constrained_chain(&chain).is_ok());

        set_subject_alt_names(
            &mut chain.certificates[0],
            vec![GeneralName::DnsName(String::from("host.other.test"))],
        );
        assert!(validate_constrained_chain(&chain).is_err());
    }

    #[test]
    fn test_validate_chain_enforces_email_uri_and_ip_constraints() {
        let cases = [
            (
                GeneralName::Rfc822Name(String::from("user@example.com")),
                GeneralName::Rfc822Name(String::from("example.com")),
                GeneralName::Rfc822Name(String::from("user@other.test")),
            ),
            (
                GeneralName::Uri(String::from("https://device.example.com/status")),
                GeneralName::Uri(String::from(".example.com")),
                GeneralName::Uri(String::from("https://device.other.test/status")),
            ),
            (
                GeneralName::IpAddress(vec![192, 0, 2, 42]),
                GeneralName::IpAddress(vec![192, 0, 2, 0, 255, 255, 255, 0]),
                GeneralName::IpAddress(vec![192, 0, 3, 42]),
            ),
        ];

        for (allowed_name, constraint, rejected_name) in cases {
            let allowed = constrained_chain(vec![allowed_name], vec![constraint.clone()], vec![]);
            assert!(validate_constrained_chain(&allowed).is_ok());

            let rejected = constrained_chain(vec![rejected_name], vec![constraint], vec![]);
            assert!(validate_constrained_chain(&rejected).is_err());
        }

        for (name, constraint) in [
            ("user@[192.000.002.001]", "user@[192.0.2.1]"),
            ("user@[IPv6:0:0:0:0:0:0:0:1]", "user@[IPv6:::1]"),
        ] {
            let excluded = constrained_chain(
                vec![GeneralName::Rfc822Name(String::from(name))],
                vec![],
                vec![GeneralName::Rfc822Name(String::from(constraint))],
            );
            assert!(validate_constrained_chain(&excluded).is_err());
        }
    }

    #[test]
    fn test_validate_chain_enforces_mixed_name_forms_and_ipv6() {
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let leaf_subject = leaf.tbs_certificate.subject.clone();
        let inter_subject = load_cert(&test_key_path("ecp256/inter.cert.der"))
            .tbs_certificate
            .subject;
        let ipv6 = vec![
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
        ];
        let mut ipv6_constraint = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ipv6_constraint
            .extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let san = vec![
            GeneralName::DnsName(String::from("device.example.com")),
            GeneralName::Rfc822Name(String::from("user@example.com")),
            GeneralName::Uri(String::from("https://device.example.com/status")),
            GeneralName::IpAddress(vec![192, 0, 2, 42]),
            GeneralName::IpAddress(ipv6.clone()),
            GeneralName::DirectoryName(leaf_subject.clone()),
        ];
        let permitted = vec![
            GeneralName::DnsName(String::from("example.com")),
            GeneralName::Rfc822Name(String::from("example.com")),
            GeneralName::Uri(String::from(".example.com")),
            GeneralName::IpAddress(vec![192, 0, 2, 0, 255, 255, 255, 0]),
            GeneralName::IpAddress(ipv6_constraint.clone()),
            GeneralName::DirectoryName(leaf_subject),
            GeneralName::DirectoryName(inter_subject),
        ];
        let allowed = constrained_chain(san.clone(), permitted.clone(), vec![]);
        assert!(validate_constrained_chain(&allowed).is_ok());

        let excluded = constrained_chain(
            san,
            permitted,
            vec![GeneralName::IpAddress(ipv6_constraint)],
        );
        assert!(validate_constrained_chain(&excluded).is_err());
    }

    #[test]
    fn test_validate_chain_enforces_directory_name_constraints() {
        let leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let leaf_subject = GeneralName::DirectoryName(leaf.tbs_certificate.subject.clone());

        let allowed = constrained_chain(
            vec![],
            vec![],
            vec![GeneralName::DirectoryName(dn(&[(
                ORGANIZATION_NAME,
                "Unrelated",
            )]))],
        );
        assert!(validate_constrained_chain(&allowed).is_ok());

        let excluded = constrained_chain(vec![], vec![], vec![leaf_subject]);
        assert!(validate_constrained_chain(&excluded).is_err());
    }

    #[test]
    fn test_excluded_directory_name_cannot_be_bypassed_with_soft_hyphen() {
        let mut chain = constrained_chain(
            vec![],
            vec![],
            vec![GeneralName::DirectoryName(dn(&[(
                ORGANIZATION_NAME,
                "Acme",
            )]))],
        );
        chain.certificates[0].tbs_certificate.subject =
            dn(&[(ORGANIZATION_NAME, "Ac\u{ad}me"), (CN, "device")]);
        assert!(validate_constrained_chain(&chain).is_err());
    }

    #[test]
    fn test_subject_email_fallback_depends_on_san_presence() {
        let excluded_email = GeneralName::Rfc822Name(String::from("blocked@example.com"));

        let mut without_san = constrained_chain(vec![], vec![], vec![excluded_email.clone()]);
        remove_extension(&mut without_san.certificates[0], SUBJECT_ALT_NAME);
        set_subject_email(&mut without_san.certificates[0], "blocked@example.com");
        assert!(validate_constrained_chain(&without_san).is_err());

        let mut with_san = constrained_chain(
            vec![GeneralName::DnsName(String::from("device.example.com"))],
            vec![],
            vec![excluded_email],
        );
        set_subject_email(&mut with_san.certificates[0], "blocked@example.com");
        assert!(validate_constrained_chain(&with_san).is_ok());
    }

    #[test]
    fn test_empty_subject_requires_critical_san() {
        use der::Encode;

        let mut chain = constrained_chain(
            vec![GeneralName::DnsName(String::from("device.example.com"))],
            vec![GeneralName::DnsName(String::from("example.com"))],
            vec![],
        );
        chain.certificates[0].tbs_certificate.subject = RDNSequence::new();
        assert!(validate_constrained_chain(&chain).is_err());

        let mut missing_san = chain.clone();
        remove_extension(&mut missing_san.certificates[0], SUBJECT_ALT_NAME);
        assert!(validate_constrained_chain(&missing_san).is_err());

        set_extension(
            &mut chain.certificates[0],
            SUBJECT_ALT_NAME,
            true,
            SubjectAltName::new(vec![GeneralName::DnsName(String::from(
                "device.example.com",
            ))])
            .to_der()
            .unwrap(),
        );
        assert!(validate_constrained_chain(&chain).is_ok());
    }

    #[test]
    fn test_uri_percent_encoding_cannot_bypass_constraints() {
        let excluded = constrained_chain(
            vec![GeneralName::Uri(String::from(
                "https://evil%2Eexample.com/device",
            ))],
            vec![],
            vec![GeneralName::Uri(String::from(".example.com"))],
        );
        assert!(validate_constrained_chain(&excluded).is_err());

        let permitted = constrained_chain(
            vec![GeneralName::Uri(String::from(
                "https://device.%65xample.com/status",
            ))],
            vec![GeneralName::Uri(String::from(".example.com"))],
            vec![],
        );
        assert!(validate_constrained_chain(&permitted).is_ok());

        let permitted_idn = constrained_chain(
            vec![GeneralName::Uri(String::from(
                "https://shop.%C3%A9xample.com/status",
            ))],
            vec![GeneralName::Uri(String::from(".xn--xample-9ua.com"))],
            vec![],
        );
        assert!(validate_constrained_chain(&permitted_idn).is_ok());

        let excluded_idn = constrained_chain(
            vec![GeneralName::Uri(String::from(
                "https://shop.%C3%A9xample.com/status",
            ))],
            vec![],
            vec![GeneralName::Uri(String::from(".xn--xample-9ua.com"))],
        );
        assert!(validate_constrained_chain(&excluded_idn).is_err());

        let unassigned_idn = constrained_chain(
            vec![GeneralName::Uri(String::from(
                "https://%E1%B4%AC.example.com/status",
            ))],
            vec![GeneralName::Uri(String::from(".example.com"))],
            vec![],
        );
        assert!(validate_constrained_chain(&unassigned_idn).is_err());
    }

    #[test]
    fn test_validate_chain_skips_self_issued_intermediate_constraints() {
        let inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let inter_subject = inter.tbs_certificate.subject.clone();
        let mut chain = constrained_chain(
            vec![],
            vec![],
            vec![GeneralName::DirectoryName(inter_subject.clone())],
        );

        chain.certificates[1].tbs_certificate.issuer = inter_subject.clone();
        chain.certificates[2].tbs_certificate.subject = inter_subject.clone();
        chain.certificates[2].tbs_certificate.issuer = inter_subject;

        assert!(validate_constrained_chain(&chain).is_ok());
    }

    #[test]
    fn test_email_case_does_not_disable_self_issued_exception() {
        let mut leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let mut inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let mut root = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let email_name = |email| {
            RDNSequence::from_rdns(vec![RelativeDistinguishedName::new(
                AttributeTypeAndValue::new(
                    EMAIL_ADDRESS,
                    DirectoryString::Ia5String(der::asn1::Ia5String::new(email).unwrap()),
                )
                .unwrap(),
            )
            .unwrap()])
        };
        let subject = email_name("subscriber@example.com");
        let issuer = email_name("SUBSCRIBER@EXAMPLE.COM");

        leaf.tbs_certificate.issuer = subject.clone();
        inter.tbs_certificate.subject = subject.clone();
        inter.tbs_certificate.issuer = issuer.clone();
        root.tbs_certificate.subject = issuer.clone();
        root.tbs_certificate.issuer = issuer;
        set_subject_alt_names(
            &mut inter,
            vec![GeneralName::DnsName(String::from("blocked.example.com"))],
        );
        set_name_constraints(
            &mut root,
            &[],
            &[GeneralName::DnsName(String::from("blocked.example.com"))],
        );

        assert!(Validator::<RingBackend>::distinguished_names_match(
            &subject,
            &inter.tbs_certificate.issuer,
        ));
        let chain = CertificateChain::new(vec![leaf, inter, root]);
        assert!(validate_constrained_chain(&chain).is_ok());
    }

    #[test]
    fn test_self_issued_intermediate_constraints_apply_to_following_certificates() {
        let mut ca = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let mut inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let mut leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let inter_subject = inter.tbs_certificate.subject.clone();

        inter.tbs_certificate.issuer = inter_subject.clone();
        ca.tbs_certificate.subject = inter_subject.clone();
        ca.tbs_certificate.issuer = inter_subject;
        set_name_constraints(
            &mut inter,
            &[],
            &[GeneralName::DnsName(String::from("blocked.example.com"))],
        );
        set_subject_alt_names(
            &mut leaf,
            vec![GeneralName::DnsName(String::from("blocked.example.com"))],
        );

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        assert!(validate_constrained_chain(&chain).is_err());
    }

    #[test]
    fn test_self_issued_final_certificate_is_constrained() {
        let mut chain = constrained_chain(
            vec![GeneralName::DnsName(String::from("blocked.example.com"))],
            vec![],
            vec![GeneralName::DnsName(String::from("blocked.example.com"))],
        );
        let leaf_subject = chain.certificates[0].tbs_certificate.subject.clone();
        chain.certificates[0].tbs_certificate.issuer = leaf_subject.clone();
        chain.certificates[1].tbs_certificate.subject = leaf_subject;

        assert!(validate_constrained_chain(&chain).is_err());
    }

    #[test]
    fn test_dns_constraints_skip_self_issued_intermediate_but_not_leaf() {
        let mut leaf = load_cert(&test_key_path("ecp256/end_responder.cert.der"));
        let mut inter = load_cert(&test_key_path("ecp256/inter.cert.der"));
        let mut root = load_cert(&test_key_path("ecp256/ca.cert.der"));
        let rollover_name = root.tbs_certificate.subject.clone();
        inter.tbs_certificate.subject = rollover_name.clone();
        inter.tbs_certificate.issuer = rollover_name.clone();
        leaf.tbs_certificate.issuer = rollover_name.clone();

        set_subject_alt_names(
            &mut leaf,
            vec![GeneralName::DnsName(String::from("device.example.com"))],
        );
        set_subject_alt_names(
            &mut inter,
            vec![GeneralName::DnsName(String::from("not-example.test"))],
        );
        set_name_constraints(
            &mut root,
            &[GeneralName::DnsName(String::from("example.com"))],
            &[],
        );

        let rollover_chain = CertificateChain::new(vec![leaf, inter, root]);
        assert!(validate_constrained_chain(&rollover_chain).is_ok());

        let mut self_issued_leaf = rollover_chain;
        self_issued_leaf.certificates[0].tbs_certificate.subject = rollover_name;
        set_subject_alt_names(
            &mut self_issued_leaf.certificates[0],
            vec![GeneralName::DnsName(String::from("not-example.test"))],
        );
        assert!(validate_constrained_chain(&self_issued_leaf).is_err());
    }
}
