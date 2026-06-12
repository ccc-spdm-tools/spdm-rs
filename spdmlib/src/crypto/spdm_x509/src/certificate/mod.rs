// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! X.509 v3 Certificate structure and parsing.
//!
//! This module implements the complete X.509 v3 certificate structure as defined in RFC 5280.
//! It provides:
//! - TBSCertificate (To Be Signed Certificate) with all fields
//! - Certificate structure with signature
//! - DER and PEM encoding/decoding
//! - no_std compatible implementation
//!
//! # Examples
//!
//! ```no_run
//! use spdm_x509::Certificate;
//!
//! # fn example(der_bytes: &[u8], pem_string: &str) -> spdm_x509::Result<()> {
//! // Parse from DER
//! let cert = Certificate::from_der(der_bytes)?;
//! println!("Subject: {}", cert.tbs_certificate.subject);
//!
//! // Parse from PEM
//! let cert = Certificate::from_pem(pem_string)?;
//!
//! // Convert back to DER
//! let der_bytes = cert.to_der()?;
//! # let _ = der_bytes;
//! # Ok(())
//! # }
//! ```

pub mod name;

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

use der::{
    asn1::{BitString, UintRef},
    Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Tag, TagMode,
    TagNumber, Writer,
};

use crate::certificate::name::Name;
use crate::error::{Error, Result};
use crate::time::Validity;
use spki::AlgorithmIdentifier;

// Re-export spki types
pub use spki::SubjectPublicKeyInfo as SpkiInfo;

/// Type alias for SubjectPublicKeyInfo with flexible parameters
pub type SubjectPublicKeyInfo = SpkiInfo<der::Any, BitString>;

// ============================================================================
// Version - RFC 5280 Section 4.1.2.1
// ============================================================================

/// X.509 certificate version.
///
/// ```asn1
/// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Version {
    /// Version 1 (value 0)
    V1 = 0,
    /// Version 2 (value 1)
    V2 = 1,
    /// Version 3 (value 2) - Default for modern certificates
    #[default]
    V3 = 2,
}

impl Version {
    /// Get the integer value of the version
    pub fn value(&self) -> u8 {
        *self as u8
    }

    /// Create a Version from an integer value
    pub fn from_value(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            2 => Ok(Version::V3),
            _ => Err(Error::Asn1(der::Error::from(der::ErrorKind::Value {
                tag: Tag::Integer,
            }))),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::V1 => write!(f, "v1"),
            Version::V2 => write!(f, "v2"),
            Version::V3 => write!(f, "v3"),
        }
    }
}

// ============================================================================
// Extensions - RFC 5280 Section 4.1.2.9
// ============================================================================

/// Extension represents a single X.509 v3 extension.
///
/// ```asn1
/// Extension  ::=  SEQUENCE  {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Extension {
    /// Extension OID
    pub extn_id: const_oid::ObjectIdentifier,

    /// Whether this extension is critical
    #[asn1(default = "default_false")]
    pub critical: bool,

    /// Extension value (DER-encoded)
    pub extn_value: der::asn1::OctetString,
}

fn default_false() -> bool {
    false
}

impl Extension {
    /// Create a new extension
    pub fn new(
        extn_id: const_oid::ObjectIdentifier,
        critical: bool,
        extn_value: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self {
            extn_id,
            critical,
            extn_value: der::asn1::OctetString::new(extn_value).map_err(Error::Asn1)?,
        })
    }

    /// Get the extension value as a byte slice
    pub fn value(&self) -> &[u8] {
        self.extn_value.as_bytes()
    }
}

/// Extensions is a SEQUENCE OF Extension.
///
/// In X.509 v3 certificates, extensions are EXPLICIT `[3]`:
/// ```asn1
/// extensions      [3]  EXPLICIT Extensions OPTIONAL
/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions {
    /// List of extensions
    pub extensions: Vec<Extension>,
}

impl Extensions {
    /// Create a new empty Extensions
    pub fn new() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }

    /// Create Extensions from a vector of Extension
    pub fn from_vec(extensions: Vec<Extension>) -> Self {
        Self { extensions }
    }

    /// Add an extension
    pub fn push(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }

    /// Get an iterator over the extensions
    pub fn iter(&self) -> core::slice::Iter<'_, Extension> {
        self.extensions.iter()
    }

    /// Find an extension by OID
    pub fn find(&self, oid: &const_oid::ObjectIdentifier) -> Option<&Extension> {
        self.extensions.iter().find(|e| &e.extn_id == oid)
    }

    /// Check if extensions list is empty
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    /// Get the number of extensions
    pub fn len(&self) -> usize {
        self.extensions.len()
    }
}

// Manual implementation for SEQUENCE OF
impl<'a> DecodeValue<'a> for Extensions {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let mut extensions = Vec::new();
        reader.read_nested(header.length, |seq_reader| {
            while !seq_reader.is_finished() {
                extensions.push(Extension::decode(seq_reader)?);
            }
            Ok(())
        })?;

        Ok(Self { extensions })
    }
}

impl EncodeValue for Extensions {
    fn value_len(&self) -> der::Result<Length> {
        let mut len = Length::ZERO;
        for ext in &self.extensions {
            len = (len + ext.encoded_len()?)?;
        }
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        for ext in &self.extensions {
            ext.encode(writer)?;
        }
        Ok(())
    }
}

impl der::FixedTag for Extensions {
    const TAG: Tag = Tag::Sequence;
}

// ============================================================================
// TBSCertificate - RFC 5280 Section 4.1
// ============================================================================

/// TBSCertificate (To Be Signed Certificate) contains all certificate fields
/// that are signed by the issuer.
///
/// ```asn1
/// TBSCertificate  ::=  SEQUENCE  {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///     extensions      [3]  EXPLICIT Extensions OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TBSCertificate {
    /// Certificate version (default v3)
    pub version: Version,

    /// Certificate serial number (unique per issuer) - stored as owned bytes
    serial_number_bytes: alloc::vec::Vec<u8>,

    /// Signature algorithm identifier (should match Certificate.signatureAlgorithm)
    pub signature: AlgorithmIdentifier<der::Any>,

    /// Issuer Distinguished Name
    pub issuer: Name,

    /// Validity period (notBefore and notAfter)
    pub validity: Validity,

    /// Subject Distinguished Name
    pub subject: Name,

    /// Subject's public key information
    pub subject_public_key_info: SpkiInfo<der::Any, BitString>,

    /// Issuer unique identifier (v2/v3 only, rarely used)
    pub issuer_unique_id: Option<BitString>,

    /// Subject unique identifier (v2/v3 only, rarely used)
    pub subject_unique_id: Option<BitString>,

    /// Extensions (v3 only)
    pub extensions: Option<Extensions>,
}

impl TBSCertificate {
    /// Create a new TBSCertificate with the minimum required fields.
    pub fn new(
        serial_number: Vec<u8>,
        signature: AlgorithmIdentifier<der::Any>,
        issuer: Name,
        validity: Validity,
        subject: Name,
        subject_public_key_info: SpkiInfo<der::Any, BitString>,
    ) -> Self {
        Self {
            version: Version::V3,
            serial_number_bytes: serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        }
    }

    /// Get the serial number as bytes
    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number_bytes
    }

    /// Get the serial number as UintRef for encoding
    fn serial_number_ref(&self) -> der::Result<UintRef<'_>> {
        UintRef::new(&self.serial_number_bytes)
    }

    /// Set the extensions
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Get the DER encoding of this TBSCertificate.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        use der::Encode;
        Encode::to_der(self).map_err(Error::Asn1)
    }
}

// Custom DER encoding for TBSCertificate due to complex tagging rules
impl<'a> DecodeValue<'a> for TBSCertificate {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let version = reader
                .context_specific::<UintRef<'a>>(TagNumber::N0, TagMode::Explicit)?
                .and_then(|v| {
                    let val = v.as_bytes();
                    if val.len() == 1 {
                        Version::from_value(val[0]).ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(Version::V1);

            let serial_number = UintRef::decode(reader)?;
            let serial_number_bytes = serial_number.as_bytes().to_vec();
            let signature = AlgorithmIdentifier::decode(reader)?;
            let issuer = Name::decode(reader)?;
            let validity = Validity::decode(reader)?;
            let subject = Name::decode(reader)?;
            let subject_public_key_info = SpkiInfo::<der::Any, BitString>::decode(reader)?;

            let issuer_unique_id =
                reader.context_specific::<BitString>(TagNumber::N1, TagMode::Implicit)?;
            let subject_unique_id =
                reader.context_specific::<BitString>(TagNumber::N2, TagMode::Implicit)?;
            let extensions =
                reader.context_specific::<Extensions>(TagNumber::N3, TagMode::Explicit)?;

            Ok(Self {
                version,
                serial_number_bytes,
                signature,
                issuer,
                validity,
                subject,
                subject_public_key_info,
                issuer_unique_id,
                subject_unique_id,
                extensions,
            })
        })
    }
}

impl EncodeValue for TBSCertificate {
    fn value_len(&self) -> der::Result<Length> {
        let mut len = Length::ZERO;

        if self.version != Version::V1 {
            let version_bytes = [self.version.value()];
            let version_int = UintRef::new(&version_bytes)?;
            len = (len
                + der::asn1::ContextSpecific {
                    tag_number: TagNumber::N0,
                    tag_mode: TagMode::Explicit,
                    value: version_int,
                }
                .encoded_len()?)?;
        }

        len = (len + self.serial_number_ref()?.encoded_len()?)?;
        len = (len + self.signature.encoded_len()?)?;
        len = (len + self.issuer.encoded_len()?)?;
        len = (len + self.validity.encoded_len()?)?;
        len = (len + self.subject.encoded_len()?)?;
        len = (len + self.subject_public_key_info.encoded_len()?)?;

        if let Some(ref issuer_uid) = self.issuer_unique_id {
            len = (len
                + der::asn1::ContextSpecific {
                    tag_number: TagNumber::N1,
                    tag_mode: TagMode::Implicit,
                    value: issuer_uid.clone(),
                }
                .encoded_len()?)?;
        }

        if let Some(ref subject_uid) = self.subject_unique_id {
            len = (len
                + der::asn1::ContextSpecific {
                    tag_number: TagNumber::N2,
                    tag_mode: TagMode::Implicit,
                    value: subject_uid.clone(),
                }
                .encoded_len()?)?;
        }

        if let Some(ref extensions) = self.extensions {
            len = (len + Length::from(1u8))?;
            let ext_len = extensions.encoded_len()?;
            let ext_len_encoded = ext_len.encoded_len()?;
            len = (len + ext_len_encoded)?;
            len = (len + ext_len)?;
        }

        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        if self.version != Version::V1 {
            let version_bytes = [self.version.value()];
            let version_int = UintRef::new(&version_bytes)?;
            der::asn1::ContextSpecific {
                tag_number: TagNumber::N0,
                tag_mode: TagMode::Explicit,
                value: version_int,
            }
            .encode(writer)?;
        }

        self.serial_number_ref()?.encode(writer)?;
        self.signature.encode(writer)?;
        self.issuer.encode(writer)?;
        self.validity.encode(writer)?;
        self.subject.encode(writer)?;
        self.subject_public_key_info.encode(writer)?;

        if let Some(ref issuer_uid) = self.issuer_unique_id {
            der::asn1::ContextSpecific {
                tag_number: TagNumber::N1,
                tag_mode: TagMode::Implicit,
                value: issuer_uid.clone(),
            }
            .encode(writer)?;
        }

        if let Some(ref subject_uid) = self.subject_unique_id {
            der::asn1::ContextSpecific {
                tag_number: TagNumber::N2,
                tag_mode: TagMode::Implicit,
                value: subject_uid.clone(),
            }
            .encode(writer)?;
        }

        if let Some(ref extensions) = self.extensions {
            writer.write_byte(0xA3)?;
            let ext_bytes = extensions.to_der()?;
            Length::try_from(ext_bytes.len())?.encode(writer)?;
            writer.write(&ext_bytes)?;
        }

        Ok(())
    }
}

impl der::FixedTag for TBSCertificate {
    const TAG: Tag = Tag::Sequence;
}

// ============================================================================
// Certificate - RFC 5280 Section 4.1
// ============================================================================

/// X.509 Certificate structure.
///
/// ```asn1
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The certificate content to be signed
    pub tbs_certificate: TBSCertificate,

    /// The signature algorithm used by the issuer
    pub signature_algorithm: AlgorithmIdentifier<der::Any>,

    /// The signature value (signature of DER-encoded tbsCertificate)
    pub signature_value: BitString,
}

impl Certificate {
    /// Create a new Certificate.
    pub fn new(
        tbs_certificate: TBSCertificate,
        signature_algorithm: AlgorithmIdentifier<der::Any>,
        signature_value: BitString,
    ) -> Self {
        Self {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        }
    }

    /// Parse a Certificate from DER-encoded bytes.
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        Self::decode(&mut der::SliceReader::new(bytes).map_err(Error::Asn1)?).map_err(Error::Asn1)
    }

    /// Parse a Certificate from PEM-encoded string.
    pub fn from_pem(pem: &str) -> Result<Self> {
        use pem_rfc7468::Decoder;

        let mut decoder = Decoder::new(pem.as_bytes()).map_err(|e| {
            Error::EncodingError(crate::error::EncodingError::InvalidPem(e.to_string()))
        })?;

        let label = decoder.type_label();
        if label != "CERTIFICATE" {
            return Err(Error::EncodingError(
                crate::error::EncodingError::InvalidPem("Wrong PEM label".to_string()),
            ));
        }

        let der_len = decoder.remaining_len();
        let mut der_bytes = alloc::vec![0u8; der_len];
        decoder.decode(&mut der_bytes).map_err(|e| {
            Error::EncodingError(crate::error::EncodingError::InvalidPem(e.to_string()))
        })?;

        Self::decode(&mut der::SliceReader::new(&der_bytes).map_err(Error::Asn1)?)
            .map_err(Error::Asn1)
    }

    /// Encode the certificate to DER format.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        use der::Encode;
        Encode::to_der(self).map_err(Error::Asn1)
    }

    /// Encode the certificate to PEM format.
    pub fn to_pem(&self) -> Result<alloc::string::String> {
        use pem_rfc7468::LineEnding;

        let der = self.to_der()?;
        pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, &der).map_err(|e| {
            Error::EncodingError(crate::error::EncodingError::InvalidPem(e.to_string()))
        })
    }

    /// Get the DER encoding of the TBSCertificate.
    pub fn tbs_certificate_der(&self) -> Result<Vec<u8>> {
        self.tbs_certificate.to_der()
    }

    /// Get the signature bytes.
    pub fn signature_bytes(&self) -> &[u8] {
        self.signature_value.raw_bytes()
    }

    /// Get the subject distinguished name.
    pub fn subject(&self) -> &Name {
        &self.tbs_certificate.subject
    }

    /// Get the issuer distinguished name.
    pub fn issuer(&self) -> &Name {
        &self.tbs_certificate.issuer
    }

    /// Get the certificate's serial number as bytes.
    pub fn serial_number(&self) -> &[u8] {
        self.tbs_certificate.serial_number()
    }

    /// Get the validity period.
    pub fn validity(&self) -> &Validity {
        &self.tbs_certificate.validity
    }

    /// Get the certificate version.
    pub fn version(&self) -> Version {
        self.tbs_certificate.version
    }

    /// Get the extensions if present.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.tbs_certificate.extensions.as_ref()
    }

    /// Check if this is a CA certificate.
    /// Based on RFC 5280 Basic Constraints extension (2.5.29.19).
    pub fn is_ca(&self) -> bool {
        #[derive(Sequence)]
        struct BasicConstraintsView {
            #[asn1(default = "default_false")]
            ca: bool,
            #[asn1(optional = "true")]
            _path_len_constraint: Option<u32>,
        }

        fn default_false() -> bool {
            false
        }

        let basic_constraints_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.19");

        let extensions = match self.extensions() {
            Some(exts) => exts,
            None => return false,
        };

        for ext in extensions.iter() {
            if ext.extn_id == basic_constraints_oid {
                return BasicConstraintsView::from_der(ext.value())
                    .map(|bc| bc.ca)
                    .unwrap_or(false);
            }
        }

        false
    }

    /// Get the subject public key info.
    pub fn subject_public_key_info(&self) -> &SpkiInfo<der::Any, BitString> {
        &self.tbs_certificate.subject_public_key_info
    }

    /// Get the signature algorithm.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier<der::Any> {
        &self.signature_algorithm
    }
}

// DER encoding/decoding for Certificate
impl<'a> DecodeValue<'a> for Certificate {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let tbs_certificate = TBSCertificate::decode(reader)?;
            let signature_algorithm = AlgorithmIdentifier::decode(reader)?;
            let signature_value = BitString::decode(reader)?;

            Ok(Self {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            })
        })
    }
}

impl EncodeValue for Certificate {
    fn value_len(&self) -> der::Result<Length> {
        self.tbs_certificate.encoded_len()?
            + self.signature_algorithm.encoded_len()?
            + self.signature_value.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.tbs_certificate.encode(writer)?;
        self.signature_algorithm.encode(writer)?;
        self.signature_value.encode(writer)?;
        Ok(())
    }
}

impl der::FixedTag for Certificate {
    const TAG: Tag = Tag::Sequence;
}

// Display implementation
impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Certificate:")?;
        writeln!(f, "  Version: {}", self.tbs_certificate.version)?;
        writeln!(f, "  Serial Number: {:02x?}", self.serial_number())?;
        writeln!(f, "  Signature Algorithm: {}", self.signature_algorithm.oid)?;
        writeln!(f, "  Issuer: {}", self.tbs_certificate.issuer)?;
        writeln!(f, "  Validity:")?;
        writeln!(
            f,
            "    Not Before: {:?}",
            self.tbs_certificate.validity.not_before
        )?;
        writeln!(
            f,
            "    Not After: {:?}",
            self.tbs_certificate.validity.not_after
        )?;
        writeln!(f, "  Subject: {}", self.tbs_certificate.subject)?;

        if let Some(ref extensions) = self.tbs_certificate.extensions {
            writeln!(f, "  Extensions: {} extension(s)", extensions.len())?;
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_version() {
        assert_eq!(Version::V1.value(), 0);
        assert_eq!(Version::V2.value(), 1);
        assert_eq!(Version::V3.value(), 2);
        assert_eq!(Version::default(), Version::V3);

        assert_eq!(Version::from_value(0).unwrap(), Version::V1);
        assert_eq!(Version::from_value(1).unwrap(), Version::V2);
        assert_eq!(Version::from_value(2).unwrap(), Version::V3);
        assert!(Version::from_value(3).is_err());
    }

    #[test]
    fn test_version_display() {
        assert_eq!(Version::V1.to_string(), "v1");
        assert_eq!(Version::V2.to_string(), "v2");
        assert_eq!(Version::V3.to_string(), "v3");
    }

    #[test]
    fn test_extensions_new() {
        let ext = Extensions::new();
        assert!(ext.is_empty());
        assert_eq!(ext.len(), 0);
    }

    #[test]
    fn test_extension_create() {
        use const_oid::ObjectIdentifier;

        let oid = ObjectIdentifier::new_unwrap("2.5.29.19");
        let value = vec![0x30, 0x03, 0x01, 0x01, 0xFF];

        let ext = Extension::new(oid, true, value.clone()).unwrap();
        assert_eq!(ext.extn_id, oid);
        assert!(ext.critical);
        assert_eq!(ext.value(), &value);
    }
}
