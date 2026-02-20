// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Error types for X.509 certificate validation
//!
//! This module defines comprehensive error types for all validation scenarios,
//! compatible with both `std` and `no_std` environments.

extern crate alloc;

use alloc::string::{String, ToString};
use core::fmt;

/// Result type alias for X.509 validation operations
pub type Result<T> = core::result::Result<T, Error>;

/// Comprehensive error type for X.509 certificate validation
///
/// This enum covers all possible error conditions that can occur during
/// certificate parsing, validation, and chain verification.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Errors during DER/ASN.1 parsing
    ParseError(ParseError),

    /// Errors during DER/ASN.1 parsing (from der crate)
    Asn1(der::Error),

    /// Errors related to cryptographic signature verification
    SignatureError(SignatureError),

    /// Errors related to time validation
    TimeError(TimeError),

    /// Unsupported or invalid cryptographic algorithms
    AlgorithmError(AlgorithmError),

    /// Certificate extension validation errors
    ExtensionError(ExtensionError),

    /// Certificate chain validation errors
    ChainError(ChainError),

    /// Certificate encoding errors (PEM/DER conversion)
    EncodingError(EncodingError),

    /// Certificate constraint violations
    ConstraintError(ConstraintError),

    /// Invalid public key or key parameters
    KeyError(KeyError),

    /// Name validation errors (subject/issuer)
    NameError(NameError),

    /// Generic validation error with custom message
    ValidationError(String),

    /// Invalid certificate version
    InvalidVersion(u8),

    /// Certificate has been revoked
    Revoked,

    /// Internal error (should not occur in normal operation)
    InternalError(String),
}

/// Errors that occur during DER/ASN.1 parsing
#[derive(Debug, Clone)]
pub enum ParseError {
    /// Invalid DER encoding
    InvalidDer(String),

    /// Unexpected end of input
    UnexpectedEof,

    /// Invalid tag encountered
    InvalidTag { expected: u8, found: u8 },

    /// Invalid length encoding
    InvalidLength(String),

    /// Invalid integer encoding
    InvalidInteger(String),

    /// Invalid OID encoding
    InvalidOid(String),

    /// Invalid bit string encoding
    InvalidBitString(String),

    /// Invalid octet string encoding
    InvalidOctetString(String),

    /// Invalid UTF-8 string encoding
    InvalidUtf8String,

    /// Invalid time encoding
    InvalidTimeEncoding(String),

    /// Missing required field
    MissingField(String),

    /// Malformed certificate structure
    MalformedCertificate(String),

    /// Invalid PEM encoding
    InvalidPem(String),

    /// Unsupported ASN.1 type
    UnsupportedType(String),

    /// Error from der crate
    DerError(String),
}

/// Errors related to cryptographic signature verification
#[derive(Debug, Clone)]
pub enum SignatureError {
    /// Signature verification failed
    VerificationFailed,

    /// Signature algorithm mismatch between certificate and TBS certificate
    AlgorithmMismatch { cert_algo: String, tbs_algo: String },

    /// Invalid signature format
    InvalidSignatureFormat(String),

    /// Invalid signature length
    InvalidSignatureLength { expected: usize, found: usize },

    /// Public key cannot verify signature
    InvalidPublicKey(String),

    /// Signature algorithm not supported
    UnsupportedSignatureAlgorithm(String),

    /// Error from ring cryptographic library
    RingError(String),
}

/// Errors related to time validation
#[derive(Debug, Clone)]
pub enum TimeError {
    /// Certificate not yet valid
    NotYetValid,

    /// Certificate has expired
    Expired,

    /// Invalid validity period (notAfter before notBefore)
    InvalidValidityPeriod {
        not_before: String,
        not_after: String,
    },

    /// Time parsing error
    ParseError(String),

    /// Time format not supported
    UnsupportedTimeFormat(String),

    /// Invalid time value
    InvalidTime,
}

/// Errors related to cryptographic algorithms
#[derive(Debug, Clone)]
pub enum AlgorithmError {
    /// Algorithm not supported
    Unsupported(String),

    /// Algorithm parameters invalid
    InvalidParameters(String),

    /// Algorithm parameters missing
    MissingParameters,

    /// Weak or insecure algorithm
    WeakAlgorithm(String),

    /// Algorithm mismatch in certificate chain
    Mismatch { parent: String, child: String },

    /// Unknown algorithm OID
    UnknownOid(String),
}

/// Errors related to certificate extensions
#[derive(Debug, Clone)]
pub enum ExtensionError {
    /// Critical extension not recognized
    UnrecognizedCriticalExtension(String),

    /// Unknown critical extension
    UnknownCriticalExtension(String),

    /// Invalid extension encoding
    InvalidEncoding(String),

    /// Duplicate extension
    DuplicateExtension(String),

    /// Extension value invalid
    InvalidValue(String),

    /// Required extension missing
    MissingRequiredExtension(String),

    /// Basic Constraints extension errors
    BasicConstraints(String),

    /// Key Usage extension errors
    KeyUsage(String),

    /// Extended Key Usage extension errors
    ExtendedKeyUsage(String),

    /// Subject Alternative Name errors
    SubjectAltName(String),

    /// Name Constraints errors
    NameConstraints(String),

    /// Policy extension errors
    PolicyError(String),
}

/// Errors related to certificate chain validation
#[derive(Debug, Clone)]
pub enum ChainError {
    /// Empty certificate chain
    EmptyChain,

    /// Chain too long (exceeds maximum path length)
    ChainTooLong,

    /// Chain too short (missing intermediate certificates)
    TooShort { minimum: usize, found: usize },

    /// Cannot find issuer certificate
    IssuerNotFound(String),

    /// Issuer name mismatch (issuer field doesn't match next cert's subject)
    IssuerMismatch,

    /// Issuer is not a CA
    IssuerNotCA,

    /// Path length constraint violated
    PathLengthExceeded,

    /// Self-signed certificate not allowed at this position
    UnexpectedSelfSigned,

    /// Root certificate not trusted
    UntrustedRoot(String),

    /// CA certificate used as end-entity
    CaUsedAsEndEntity,

    /// End-entity certificate used as CA
    EndEntityUsedAsCa,

    /// Name constraints violated
    NameConstraintViolation(String),

    /// Policy constraints violated
    PolicyViolation(String),

    /// Circular chain detected
    CircularChain,
}

/// Errors related to certificate encoding
#[derive(Debug, Clone)]
pub enum EncodingError {
    /// Invalid PEM format
    InvalidPem(String),

    /// PEM label mismatch
    InvalidPemLabel { expected: String, found: String },

    /// Invalid base64 encoding
    InvalidBase64(String),

    /// Invalid DER encoding
    InvalidDer(String),

    /// Encoding conversion error
    ConversionError(String),
}

/// Errors related to certificate constraints
#[derive(Debug, Clone)]
pub enum ConstraintError {
    /// Basic Constraints: pathLenConstraint violated
    PathLength { max: u8, actual: u8 },

    /// Basic Constraints: CA flag not set but certificate used as CA
    NotCa,

    /// Basic Constraints: CA flag set but certificate used as end-entity
    UnexpectedCa,

    /// Key Usage: required usage not permitted
    KeyUsageViolation(String),

    /// Extended Key Usage: required usage not permitted
    ExtendedKeyUsageViolation(String),

    /// Name Constraints: name not permitted
    NameNotPermitted(String),

    /// Name Constraints: name excluded
    NameExcluded(String),

    /// Policy Constraints: required policy not present
    PolicyNotPermitted(String),
}

/// Errors related to public keys
#[derive(Debug, Clone)]
pub enum KeyError {
    /// Invalid key encoding
    InvalidEncoding(String),

    /// Unsupported key type
    UnsupportedKeyType(String),

    /// Invalid key parameters
    InvalidParameters(String),

    /// Key too weak (insufficient key length)
    WeakKey { algorithm: String, bits: usize },

    /// Invalid RSA public key
    InvalidRsaKey(String),

    /// Invalid ECDSA public key
    InvalidEcdsaKey(String),

    /// Invalid EdDSA public key
    InvalidEddsaKey(String),

    /// Public key mismatch
    Mismatch(String),

    /// Missing required key parameters
    MissingParameters,
}

/// Errors related to distinguished names
#[derive(Debug, Clone)]
pub enum NameError {
    /// Invalid name encoding
    InvalidEncoding(String),

    /// Empty distinguished name
    EmptyName,

    /// Invalid attribute value
    InvalidAttribute(String),

    /// Unsupported attribute type
    UnsupportedAttributeType(String),

    /// Name comparison failed
    ComparisonFailed(String),

    /// Invalid DNS name in SAN
    InvalidDnsName(String),

    /// Invalid email address in SAN
    InvalidEmail(String),

    /// Invalid IP address in SAN
    InvalidIpAddress(String),

    /// Invalid URI in SAN
    InvalidUri(String),
}

// ============================================================================
// Error Display Implementation (works in both std and no_std)
// ============================================================================

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ParseError(e) => write!(f, "Parse error: {}", e),
            Error::Asn1(e) => write!(f, "ASN.1 error: {}", e),
            Error::SignatureError(e) => write!(f, "Signature error: {}", e),
            Error::TimeError(e) => write!(f, "Time validation error: {}", e),
            Error::AlgorithmError(e) => write!(f, "Algorithm error: {}", e),
            Error::ExtensionError(e) => write!(f, "Extension error: {}", e),
            Error::ChainError(e) => write!(f, "Chain validation error: {}", e),
            Error::EncodingError(e) => write!(f, "Encoding error: {}", e),
            Error::ConstraintError(e) => write!(f, "Constraint violation: {}", e),
            Error::KeyError(e) => write!(f, "Public key error: {}", e),
            Error::NameError(e) => write!(f, "Name error: {}", e),
            Error::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            Error::InvalidVersion(v) => write!(f, "Invalid certificate version: {}", v),
            Error::Revoked => write!(f, "Certificate has been revoked"),
            Error::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidDer(msg) => write!(f, "Invalid DER encoding: {}", msg),
            ParseError::UnexpectedEof => write!(f, "Unexpected end of input"),
            ParseError::InvalidTag { expected, found } => {
                write!(
                    f,
                    "Invalid tag: expected 0x{:02x}, found 0x{:02x}",
                    expected, found
                )
            }
            ParseError::InvalidLength(msg) => write!(f, "Invalid length: {}", msg),
            ParseError::InvalidInteger(msg) => write!(f, "Invalid integer: {}", msg),
            ParseError::InvalidOid(msg) => write!(f, "Invalid OID: {}", msg),
            ParseError::InvalidBitString(msg) => write!(f, "Invalid bit string: {}", msg),
            ParseError::InvalidOctetString(msg) => write!(f, "Invalid octet string: {}", msg),
            ParseError::InvalidUtf8String => write!(f, "Invalid UTF-8 string"),
            ParseError::InvalidTimeEncoding(msg) => write!(f, "Invalid time encoding: {}", msg),
            ParseError::MissingField(field) => write!(f, "Missing required field: {}", field),
            ParseError::MalformedCertificate(msg) => write!(f, "Malformed certificate: {}", msg),
            ParseError::InvalidPem(msg) => write!(f, "Invalid PEM: {}", msg),
            ParseError::UnsupportedType(msg) => write!(f, "Unsupported ASN.1 type: {}", msg),
            ParseError::DerError(msg) => write!(f, "DER error: {}", msg),
        }
    }
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::VerificationFailed => write!(f, "Signature verification failed"),
            SignatureError::AlgorithmMismatch {
                cert_algo,
                tbs_algo,
            } => {
                write!(
                    f,
                    "Signature algorithm mismatch: cert={}, tbs={}",
                    cert_algo, tbs_algo
                )
            }
            SignatureError::InvalidSignatureFormat(msg) => {
                write!(f, "Invalid signature format: {}", msg)
            }
            SignatureError::InvalidSignatureLength { expected, found } => {
                write!(
                    f,
                    "Invalid signature length: expected {}, found {}",
                    expected, found
                )
            }
            SignatureError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
            SignatureError::UnsupportedSignatureAlgorithm(algo) => {
                write!(f, "Unsupported signature algorithm: {}", algo)
            }
            SignatureError::RingError(msg) => write!(f, "Cryptographic error: {}", msg),
        }
    }
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeError::NotYetValid => write!(f, "Certificate not yet valid"),
            TimeError::Expired => write!(f, "Certificate has expired"),
            TimeError::InvalidValidityPeriod {
                not_before,
                not_after,
            } => {
                write!(
                    f,
                    "Invalid validity period: notBefore={}, notAfter={}",
                    not_before, not_after
                )
            }
            TimeError::ParseError(msg) => write!(f, "Time parse error: {}", msg),
            TimeError::UnsupportedTimeFormat(fmt) => write!(f, "Unsupported time format: {}", fmt),
            TimeError::InvalidTime => write!(f, "Invalid time"),
        }
    }
}

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlgorithmError::Unsupported(algo) => write!(f, "Unsupported algorithm: {}", algo),
            AlgorithmError::InvalidParameters(msg) => {
                write!(f, "Invalid algorithm parameters: {}", msg)
            }
            AlgorithmError::MissingParameters => write!(f, "Missing algorithm parameters"),
            AlgorithmError::WeakAlgorithm(algo) => write!(f, "Weak/insecure algorithm: {}", algo),
            AlgorithmError::Mismatch { parent, child } => {
                write!(f, "Algorithm mismatch: parent={}, child={}", parent, child)
            }
            AlgorithmError::UnknownOid(oid) => write!(f, "Unknown algorithm OID: {}", oid),
        }
    }
}

impl fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtensionError::UnrecognizedCriticalExtension(oid) => {
                write!(f, "Unrecognized critical extension: {}", oid)
            }
            ExtensionError::InvalidEncoding(msg) => {
                write!(f, "Invalid extension encoding: {}", msg)
            }
            ExtensionError::DuplicateExtension(oid) => write!(f, "Duplicate extension: {}", oid),
            ExtensionError::InvalidValue(msg) => write!(f, "Invalid extension value: {}", msg),
            ExtensionError::MissingRequiredExtension(name) => {
                write!(f, "Missing required extension: {}", name)
            }
            ExtensionError::BasicConstraints(msg) => {
                write!(f, "Basic Constraints error: {}", msg)
            }
            ExtensionError::KeyUsage(msg) => write!(f, "Key Usage error: {}", msg),
            ExtensionError::ExtendedKeyUsage(msg) => write!(f, "Extended Key Usage error: {}", msg),
            ExtensionError::SubjectAltName(msg) => {
                write!(f, "Subject Alternative Name error: {}", msg)
            }
            ExtensionError::NameConstraints(msg) => write!(f, "Name Constraints error: {}", msg),
            ExtensionError::PolicyError(msg) => write!(f, "Policy error: {}", msg),
            ExtensionError::UnknownCriticalExtension(oid) => {
                write!(f, "Unknown critical extension: {}", oid)
            }
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::EmptyChain => write!(f, "Certificate chain is empty"),
            ChainError::TooShort { minimum, found } => {
                write!(f, "Chain too short: minimum {}, found {}", minimum, found)
            }
            ChainError::ChainTooLong => write!(f, "Certificate chain too long"),
            ChainError::IssuerNotFound(name) => write!(f, "Issuer not found: {}", name),
            ChainError::IssuerMismatch => write!(f, "Issuer name mismatch in chain"),
            ChainError::UnexpectedSelfSigned => {
                write!(f, "Self-signed certificate in unexpected position")
            }
            ChainError::UntrustedRoot(name) => write!(f, "Untrusted root certificate: {}", name),
            ChainError::PathLengthExceeded => write!(f, "Path length constraint exceeded"),
            ChainError::CaUsedAsEndEntity => write!(f, "CA certificate used as end-entity"),
            ChainError::EndEntityUsedAsCa => write!(f, "End-entity certificate used as CA"),
            ChainError::NameConstraintViolation(msg) => {
                write!(f, "Name constraint violation: {}", msg)
            }
            ChainError::PolicyViolation(msg) => write!(f, "Policy violation: {}", msg),
            ChainError::CircularChain => write!(f, "Circular certificate chain detected"),
            ChainError::IssuerNotCA => write!(f, "Issuer is not a CA certificate"),
        }
    }
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodingError::InvalidPem(msg) => write!(f, "Invalid PEM: {}", msg),
            EncodingError::InvalidPemLabel { expected, found } => {
                write!(
                    f,
                    "Invalid PEM label: expected '{}', found '{}'",
                    expected, found
                )
            }
            EncodingError::InvalidBase64(msg) => write!(f, "Invalid base64: {}", msg),
            EncodingError::InvalidDer(msg) => write!(f, "Invalid DER: {}", msg),
            EncodingError::ConversionError(msg) => write!(f, "Conversion error: {}", msg),
        }
    }
}

impl fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstraintError::PathLength { max, actual } => {
                write!(
                    f,
                    "Path length constraint violated: max={}, actual={}",
                    max, actual
                )
            }
            ConstraintError::NotCa => write!(f, "Certificate is not a CA but used as one"),
            ConstraintError::UnexpectedCa => {
                write!(f, "Certificate is a CA but used as end-entity")
            }
            ConstraintError::KeyUsageViolation(msg) => write!(f, "Key usage violation: {}", msg),
            ConstraintError::ExtendedKeyUsageViolation(msg) => {
                write!(f, "Extended key usage violation: {}", msg)
            }
            ConstraintError::NameNotPermitted(name) => write!(f, "Name not permitted: {}", name),
            ConstraintError::NameExcluded(name) => write!(f, "Name excluded: {}", name),
            ConstraintError::PolicyNotPermitted(policy) => {
                write!(f, "Policy not permitted: {}", policy)
            }
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::InvalidEncoding(msg) => write!(f, "Invalid key encoding: {}", msg),
            KeyError::UnsupportedKeyType(typ) => write!(f, "Unsupported key type: {}", typ),
            KeyError::InvalidParameters(msg) => write!(f, "Invalid key parameters: {}", msg),
            KeyError::WeakKey { algorithm, bits } => {
                write!(f, "Weak key: {} with only {} bits", algorithm, bits)
            }
            KeyError::InvalidRsaKey(msg) => write!(f, "Invalid RSA key: {}", msg),
            KeyError::InvalidEcdsaKey(msg) => write!(f, "Invalid ECDSA key: {}", msg),
            KeyError::InvalidEddsaKey(msg) => write!(f, "Invalid EdDSA key: {}", msg),
            KeyError::Mismatch(msg) => write!(f, "Key mismatch: {}", msg),
            KeyError::MissingParameters => write!(f, "Missing key parameters"),
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::InvalidEncoding(msg) => write!(f, "Invalid name encoding: {}", msg),
            NameError::EmptyName => write!(f, "Empty distinguished name"),
            NameError::InvalidAttribute(attr) => write!(f, "Invalid attribute: {}", attr),
            NameError::UnsupportedAttributeType(typ) => {
                write!(f, "Unsupported attribute type: {}", typ)
            }
            NameError::ComparisonFailed(msg) => write!(f, "Name comparison failed: {}", msg),
            NameError::InvalidDnsName(name) => write!(f, "Invalid DNS name: {}", name),
            NameError::InvalidEmail(email) => write!(f, "Invalid email address: {}", email),
            NameError::InvalidIpAddress(ip) => write!(f, "Invalid IP address: {}", ip),
            NameError::InvalidUri(uri) => write!(f, "Invalid URI: {}", uri),
        }
    }
}

// ============================================================================
// std::error::Error implementation (when std feature is enabled)
// ============================================================================

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// ============================================================================
// Conversions from external crate errors
// ============================================================================

/// Convert from der crate errors
impl From<der::Error> for Error {
    fn from(err: der::Error) -> Self {
        Error::ParseError(ParseError::DerError(err.to_string()))
    }
}

/// Convert from ring's Unspecified error
#[cfg(feature = "ring-backend")]
impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::SignatureError(SignatureError::RingError(
            "Cryptographic operation failed".to_string(),
        ))
    }
}

/// Convert from ring's KeyRejected error
#[cfg(feature = "ring-backend")]
impl From<ring::error::KeyRejected> for Error {
    fn from(err: ring::error::KeyRejected) -> Self {
        Error::KeyError(KeyError::InvalidEncoding(err.to_string()))
    }
}

/// Convert from PEM decoding errors
impl From<pem_rfc7468::Error> for Error {
    fn from(err: pem_rfc7468::Error) -> Self {
        Error::EncodingError(EncodingError::InvalidPem(err.to_string()))
    }
}

// ============================================================================
// Helper constructors for common error cases
// ============================================================================

impl Error {
    /// Create a parse error for invalid DER
    pub fn invalid_der<S: Into<String>>(msg: S) -> Self {
        Error::ParseError(ParseError::InvalidDer(msg.into()))
    }

    /// Create a signature verification failure
    pub fn signature_failed() -> Self {
        Error::SignatureError(SignatureError::VerificationFailed)
    }

    /// Create an unsupported algorithm error
    pub fn unsupported_algorithm<S: Into<String>>(algo: S) -> Self {
        Error::AlgorithmError(AlgorithmError::Unsupported(algo.into()))
    }

    /// Create a certificate expired error
    pub fn expired() -> Self {
        Error::TimeError(TimeError::Expired)
    }

    /// Create a certificate not yet valid error
    pub fn not_yet_valid() -> Self {
        Error::TimeError(TimeError::NotYetValid)
    }

    /// Create a missing field error
    pub fn missing_field<S: Into<String>>(field: S) -> Self {
        Error::ParseError(ParseError::MissingField(field.into()))
    }

    /// Create an unrecognized critical extension error
    pub fn critical_extension<S: Into<String>>(oid: S) -> Self {
        Error::ExtensionError(ExtensionError::UnrecognizedCriticalExtension(oid.into()))
    }

    /// Create an issuer not found error
    pub fn issuer_not_found<S: Into<String>>(name: S) -> Self {
        Error::ChainError(ChainError::IssuerNotFound(name.into()))
    }

    /// Create a weak key error
    pub fn weak_key<S: Into<String>>(algorithm: S, bits: usize) -> Self {
        Error::KeyError(KeyError::WeakKey {
            algorithm: algorithm.into(),
            bits,
        })
    }

    /// Create a validation error with a custom message
    pub fn validation<S: Into<String>>(msg: S) -> Self {
        Error::ValidationError(msg.into())
    }

    /// Create an internal error (should be rare)
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Error::InternalError(msg.into())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::signature_failed();
        assert_eq!(
            err.to_string(),
            "Signature error: Signature verification failed"
        );

        let err = Error::expired();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn test_error_conversions() {
        let der_err = der::Error::new(der::ErrorKind::Failed, der::Length::ZERO);
        let err: Error = der_err.into();
        assert!(matches!(err, Error::ParseError(ParseError::DerError(_))));
    }

    #[test]
    fn test_helper_constructors() {
        let err = Error::invalid_der("test");
        assert!(matches!(err, Error::ParseError(ParseError::InvalidDer(_))));

        let err = Error::unsupported_algorithm("MD5");
        assert!(matches!(
            err,
            Error::AlgorithmError(AlgorithmError::Unsupported(_))
        ));

        let err = Error::weak_key("RSA", 512);
        assert!(matches!(
            err,
            Error::KeyError(KeyError::WeakKey { bits: 512, .. })
        ));
    }

    #[test]
    fn test_clone() {
        let err = Error::signature_failed();
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }
}
