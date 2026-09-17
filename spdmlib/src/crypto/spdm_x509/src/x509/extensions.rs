// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! X.509 v3 Certificate Extensions.
//!
//! This module provides support for parsing and validating X.509 v3 extensions
//! as defined in RFC 5280. Extensions provide additional information about the
//! certificate and its usage.
//!
//! # Common Extensions
//!
//! - Basic Constraints - Identifies whether the subject is a CA
//! - Key Usage - Defines the purpose of the key
//! - Extended Key Usage - Defines extended purposes
//! - Subject Alternative Name - Alternative names for the subject
//! - Authority Key Identifier - Identifies the issuing CA's public key
//! - Subject Key Identifier - Identifies the subject's public key

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use const_oid::ObjectIdentifier;
use der::{Decode, DecodeValue, Encode, Header, Reader, Sequence, Tag, TagNumber};

// Re-export Extension and Extensions from certificate module
pub use crate::certificate::{Extension, Extensions};
// Re-use the GeneralName type already defined for SubjectAltName parsing.
pub use crate::certificate::name::GeneralName;

// ============================================================================
// Extension OIDs - RFC 5280 Section 4.2
// ============================================================================

/// Basic Constraints - 2.5.29.19
pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// Key Usage - 2.5.29.15
pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// Extended Key Usage - 2.5.29.37
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// Subject Alternative Name - 2.5.29.17
pub const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// Name Constraints - 2.5.29.30
pub const NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");

/// Authority Key Identifier - 2.5.29.35
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// Subject Key Identifier - 2.5.29.14
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

// ============================================================================
// TCG (Trusted Computing Group) Extension OIDs
// ============================================================================

/// TCG Platform Certificate - 2.23.133.5.4.1
pub const TCG_PLATFORM_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.1");

// ============================================================================
// SPDM Extension OIDs - DSP0274 (DMTF SPDM Specification)
// ============================================================================
pub use super::oids::{
    DEVICE_INFO, DMTF_BASE, HARDWARE_IDENTITY, MUTABLE_CERTIFICATE, SPDM_BASE, SPDM_EXTENSION,
    SPDM_REQUESTER_AUTH, SPDM_RESPONDER_AUTH,
};

// ============================================================================
// Basic Constraints - RFC 5280 Section 4.2.1.9
// ============================================================================

/// Basic Constraints extension.
///
/// ```asn1
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct BasicConstraints {
    /// Whether the subject is a CA
    #[asn1(default = "default_false")]
    pub ca: bool,

    /// Maximum depth of valid certification paths
    #[asn1(optional = "true")]
    pub path_len_constraint: Option<u32>,
}

fn default_false() -> bool {
    false
}

impl BasicConstraints {
    /// Create a new BasicConstraints for a non-CA certificate
    pub fn new_end_entity() -> Self {
        Self {
            ca: false,
            path_len_constraint: None,
        }
    }

    /// Create a new BasicConstraints for a CA certificate
    pub fn new_ca(path_len: Option<u32>) -> Self {
        Self {
            ca: true,
            path_len_constraint: path_len,
        }
    }

    /// Parse from the extension value bytes
    pub fn from_extension(ext: &Extension) -> Result<Self, der::Error> {
        Self::from_der(ext.value())
    }
}

// ============================================================================
// Key Usage - RFC 5280 Section 4.2.1.3
// ============================================================================

/// Key Usage bit flags.
///
/// ```asn1
/// KeyUsage ::= BIT STRING {
///     digitalSignature        (0),
///     nonRepudiation          (1),
///     keyEncipherment         (2),
///     dataEncipherment        (3),
///     keyAgreement            (4),
///     keyCertSign             (5),
///     cRLSign                 (6),
///     encipherOnly            (7),
///     decipherOnly            (8)
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage {
    bits: u16,
}

impl KeyUsage {
    // Bit positions match DER BIT STRING encoding: bit 0 is the MSB of byte 0
    // (i.e. 0x80 in byte 0), bit 8 is the MSB of byte 1 (0x80 in byte 1).
    // We store the two raw bytes as a big-endian u16 so the constants below
    // can be used directly with `has()`.

    /// Digital signature (bit 0)
    pub const DIGITAL_SIGNATURE: u16 = 1 << 15;
    /// Non-repudiation / content commitment (bit 1)
    pub const NON_REPUDIATION: u16 = 1 << 14;
    /// Key encipherment (bit 2)
    pub const KEY_ENCIPHERMENT: u16 = 1 << 13;
    /// Data encipherment (bit 3)
    pub const DATA_ENCIPHERMENT: u16 = 1 << 12;
    /// Key agreement (bit 4)
    pub const KEY_AGREEMENT: u16 = 1 << 11;
    /// Certificate signing (bit 5)
    pub const KEY_CERT_SIGN: u16 = 1 << 10;
    /// CRL signing (bit 6)
    pub const CRL_SIGN: u16 = 1 << 9;
    /// Encipher only (bit 7)
    pub const ENCIPHER_ONLY: u16 = 1 << 8;
    /// Decipher only (bit 8)
    pub const DECIPHER_ONLY: u16 = 1 << 7;

    /// Create a new KeyUsage from bit flags
    pub fn new(bits: u16) -> Self {
        Self { bits }
    }

    /// Check if a specific usage is enabled
    pub fn has(&self, usage: u16) -> bool {
        (self.bits & usage) != 0
    }

    /// Parse from DER-encoded BIT STRING
    ///
    /// The raw bytes are stored as a big-endian u16 so that the MSB of byte 0
    /// maps to bit 15. This matches the constant definitions above.
    pub fn from_der(bytes: &[u8]) -> Result<Self, der::Error> {
        let bit_string = der::asn1::BitString::from_der(bytes)?;
        let raw_bytes = bit_string.raw_bytes();

        let bits = match raw_bytes.len() {
            1 => u16::from_be_bytes([raw_bytes[0], 0]),
            2 => u16::from_be_bytes([raw_bytes[0], raw_bytes[1]]),
            _ => 0,
        };

        Ok(Self { bits })
    }

    /// Parse from the extension value bytes
    pub fn from_extension(ext: &Extension) -> Result<Self, der::Error> {
        Self::from_der(ext.value())
    }
}

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut usages = Vec::new();
        if self.has(Self::DIGITAL_SIGNATURE) {
            usages.push("digitalSignature");
        }
        if self.has(Self::NON_REPUDIATION) {
            usages.push("nonRepudiation");
        }
        if self.has(Self::KEY_ENCIPHERMENT) {
            usages.push("keyEncipherment");
        }
        if self.has(Self::DATA_ENCIPHERMENT) {
            usages.push("dataEncipherment");
        }
        if self.has(Self::KEY_AGREEMENT) {
            usages.push("keyAgreement");
        }
        if self.has(Self::KEY_CERT_SIGN) {
            usages.push("keyCertSign");
        }
        if self.has(Self::CRL_SIGN) {
            usages.push("cRLSign");
        }
        if self.has(Self::ENCIPHER_ONLY) {
            usages.push("encipherOnly");
        }
        if self.has(Self::DECIPHER_ONLY) {
            usages.push("decipherOnly");
        }

        write!(f, "{}", usages.join(", "))
    }
}

// ============================================================================
// Extended Key Usage - RFC 5280 Section 4.2.1.12
// ============================================================================

/// Extended Key Usage OIDs
pub mod extended_key_usage_oids {
    use const_oid::ObjectIdentifier;

    /// TLS Web Server Authentication - 1.3.6.1.5.5.7.3.1
    pub const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

    /// TLS Web Client Authentication - 1.3.6.1.5.5.7.3.2
    pub const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

    /// Code Signing - 1.3.6.1.5.5.7.3.3
    pub const CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

    /// Email Protection - 1.3.6.1.5.5.7.3.4
    pub const EMAIL_PROTECTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

    /// Time Stamping - 1.3.6.1.5.5.7.3.8
    pub const TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

    /// OCSP Signing - 1.3.6.1.5.5.7.3.9
    pub const OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
}

/// Extended Key Usage extension.
///
/// ```asn1
/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
/// KeyPurposeId ::= OBJECT IDENTIFIER
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedKeyUsage {
    /// List of key purpose OIDs
    pub key_purposes: Vec<ObjectIdentifier>,
}

// Manual Decode implementation for SEQUENCE OF
impl<'a> DecodeValue<'a> for ExtendedKeyUsage {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let mut key_purposes = Vec::new();
            while !reader.is_finished() {
                key_purposes.push(ObjectIdentifier::decode(reader)?);
            }
            Ok(Self { key_purposes })
        })
    }
}

// Manual Encode implementation for SEQUENCE OF
impl Encode for ExtendedKeyUsage {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let mut len = der::Length::ZERO;
        for oid in &self.key_purposes {
            len = (len + oid.encoded_len()?)?;
        }
        Ok(len)
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        for oid in &self.key_purposes {
            oid.encode(encoder)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ExtendedKeyUsage {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let header = Header::decode(reader)?;
        Self::decode_value(reader, header)
    }
}

impl ExtendedKeyUsage {
    /// Create a new ExtendedKeyUsage
    pub fn new(key_purposes: Vec<ObjectIdentifier>) -> Self {
        Self { key_purposes }
    }

    /// Parse from the extension value bytes
    pub fn from_extension(ext: &Extension) -> Result<Self, der::Error> {
        Self::from_der(ext.value())
    }

    /// Check if a specific purpose is present
    pub fn has_purpose(&self, oid: &ObjectIdentifier) -> bool {
        self.key_purposes.iter().any(|p| p == oid)
    }

    /// Check if this certificate can be used for TLS server authentication
    pub fn is_server_auth(&self) -> bool {
        self.has_purpose(&extended_key_usage_oids::SERVER_AUTH)
    }

    /// Check if this certificate can be used for TLS client authentication
    pub fn is_client_auth(&self) -> bool {
        self.has_purpose(&extended_key_usage_oids::CLIENT_AUTH)
    }

    /// Check if this certificate can be used for code signing
    pub fn is_code_signing(&self) -> bool {
        self.has_purpose(&extended_key_usage_oids::CODE_SIGNING)
    }
}

// ============================================================================
// Name Constraints - RFC 5280 Section 4.2.1.10
// ============================================================================

/// A single name-space restriction (`GeneralSubtree`).
///
/// Only the `base` GeneralName is retained. RFC 5280 §4.2.1.10 mandates that
/// the `minimum` field be 0 and the `maximum` field be absent, so prohibited
/// distance values are rejected while parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralSubtree {
    /// The name (or name prefix) that bounds the subtree.
    pub base: GeneralName,
}

impl<'a> DecodeValue<'a> for GeneralSubtree {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let base = reader.read_nested(header.length, |reader| {
            let base_header = Header::decode(reader)?;
            let base = GeneralName::decode_value(reader, base_header)?;
            if !reader.is_finished() {
                let distance = Header::decode(reader)?;
                match distance.tag {
                    Tag::ContextSpecific {
                        constructed: false,
                        number: TagNumber::N0,
                    } => {
                        // BaseDistance is DEFAULT 0. DER requires default-valued
                        // fields to be omitted, while RFC 5280 prohibits every
                        // non-zero minimum.
                        let value = reader.read_slice(distance.length)?;
                        if value == [0] {
                            return Err(der::ErrorKind::Noncanonical { tag: distance.tag }.into());
                        }
                        return Err(der::ErrorKind::Value { tag: distance.tag }.into());
                    }
                    Tag::ContextSpecific {
                        constructed: false,
                        number: TagNumber::N1,
                    } => return Err(der::ErrorKind::Value { tag: distance.tag }.into()),
                    _ => {
                        return Err(der::ErrorKind::TagUnexpected {
                            expected: None,
                            actual: distance.tag,
                        }
                        .into())
                    }
                }
            }
            Ok(base)
        })?;
        Ok(Self { base })
    }
}

impl der::FixedTag for GeneralSubtree {
    const TAG: Tag = Tag::Sequence;
}

/// Name Constraints extension.
///
/// ```asn1
/// NameConstraints ::= SEQUENCE {
///     permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
///     excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
///
/// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
///
/// GeneralSubtree ::= SEQUENCE {
///     base                    GeneralName,
///     minimum         [0]     BaseDistance DEFAULT 0,
///     maximum         [1]     BaseDistance OPTIONAL }
/// ```
///
/// This extension appears only in CA certificates and constrains the name
/// space of all subject names in subsequent certificates of the path.  It MUST
/// be marked critical (RFC 5280 §4.2.1.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameConstraints {
    /// Names within which all subject names MUST fall (when present).
    pub permitted_subtrees: Option<Vec<GeneralSubtree>>,

    /// Names that all subject names MUST avoid (when present).
    pub excluded_subtrees: Option<Vec<GeneralSubtree>>,
}

impl NameConstraints {
    /// Parse from the extension value bytes.
    pub fn from_extension(ext: &Extension) -> Result<Self, der::Error> {
        Self::from_der(ext.value())
    }

    /// Decode the `GeneralSubtrees` content of an implicitly-tagged field.
    ///
    /// The `[0]`/`[1]` context tag replaces the `SEQUENCE OF` tag (implicit
    /// tagging), so the field content is a bare concatenation of
    /// `GeneralSubtree` values.
    fn decode_subtrees<'a, R: Reader<'a>>(
        reader: &mut R,
        length: der::Length,
    ) -> der::Result<Vec<GeneralSubtree>> {
        reader.read_nested(length, |reader| {
            let mut subtrees = Vec::new();
            while !reader.is_finished() {
                subtrees
                    .try_reserve(1)
                    .map_err(|_| der::ErrorKind::Overlength)?;
                subtrees.push(GeneralSubtree::decode(reader)?);
            }
            if subtrees.is_empty() {
                return Err(der::ErrorKind::Length { tag: Tag::Sequence }.into());
            }
            Ok(subtrees)
        })
    }
}

impl<'a> DecodeValue<'a> for NameConstraints {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let mut permitted_subtrees = None;
        let mut excluded_subtrees = None;

        reader.read_nested(header.length, |reader| {
            while !reader.is_finished() {
                let field_header = Header::decode(reader)?;
                let tag = field_header.tag;
                if !matches!(
                    tag,
                    Tag::ContextSpecific {
                        constructed: true,
                        number: TagNumber::N0 | TagNumber::N1,
                    }
                ) {
                    return Err(der::ErrorKind::TagUnexpected {
                        expected: None,
                        actual: tag,
                    }
                    .into());
                }
                match tag.number() {
                    TagNumber::N0 => {
                        if permitted_subtrees.is_some() || excluded_subtrees.is_some() {
                            return Err(der::ErrorKind::Value { tag }.into());
                        }
                        permitted_subtrees =
                            Some(Self::decode_subtrees(reader, field_header.length)?);
                    }
                    TagNumber::N1 => {
                        if excluded_subtrees.is_some() {
                            return Err(der::ErrorKind::Value { tag }.into());
                        }
                        excluded_subtrees =
                            Some(Self::decode_subtrees(reader, field_header.length)?);
                    }
                    _ => {
                        return Err(der::ErrorKind::TagUnexpected {
                            expected: None,
                            actual: tag,
                        }
                        .into());
                    }
                }
            }
            Ok(())
        })?;

        if permitted_subtrees.is_none() && excluded_subtrees.is_none() {
            return Err(der::ErrorKind::Value { tag: Tag::Sequence }.into());
        }

        Ok(Self {
            permitted_subtrees,
            excluded_subtrees,
        })
    }
}

impl der::FixedTag for NameConstraints {
    const TAG: Tag = Tag::Sequence;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128);
        let mut der = vec![tag, content.len() as u8];
        der.extend_from_slice(content);
        der
    }

    fn general_subtree(base_tag: u8, base: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut content = der_wrap(base_tag, base);
        content.extend_from_slice(suffix);
        der_wrap(0x30, &content)
    }

    fn name_constraints(fields: &[Vec<u8>]) -> Vec<u8> {
        let mut content = Vec::new();
        for field in fields {
            content.extend_from_slice(field);
        }
        der_wrap(0x30, &content)
    }

    #[test]
    fn test_name_constraints_parse_canonical_implicit_fields() {
        use der::Decode;

        let permitted = der_wrap(0xA0, &general_subtree(0x82, b"example.com", &[]));
        let excluded = der_wrap(
            0xA1,
            &general_subtree(0x87, &[192, 0, 2, 0, 255, 255, 255, 0], &[]),
        );
        let decoded = NameConstraints::from_der(&name_constraints(&[permitted, excluded])).unwrap();

        assert_eq!(decoded.permitted_subtrees.unwrap().len(), 1);
        assert_eq!(decoded.excluded_subtrees.unwrap().len(), 1);
    }

    #[test]
    fn test_name_constraints_parse_implicit_registered_id_base() {
        use der::Decode;

        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549");
        let permitted = der_wrap(0xA0, &general_subtree(0x88, oid.as_bytes(), &[]));
        let decoded = NameConstraints::from_der(&name_constraints(&[permitted])).unwrap();

        assert!(matches!(
            decoded.permitted_subtrees.unwrap()[0].base,
            GeneralName::RegisteredId(value) if value == oid
        ));
    }

    #[test]
    fn test_name_constraints_parse_structural_unsupported_bases() {
        use der::Decode;

        for (tag, value) in [
            (0xA0, &[0x06, 0x01, 0x2A, 0xA0, 0x02, 0x05, 0x00][..]),
            (0xA3, &[0x30, 0x00][..]),
            (
                0xA5,
                &[0xA1, 0x07, 0x0C, 0x05, b'p', b'a', b'r', b't', b'y'][..],
            ),
        ] {
            let permitted = der_wrap(0xA0, &general_subtree(tag, value, &[]));
            assert!(NameConstraints::from_der(&name_constraints(&[permitted])).is_ok());
        }
    }

    #[test]
    fn test_name_constraints_reject_present_minimum_and_maximum() {
        use der::Decode;

        for suffix in [
            &[0x80, 0x01, 0x00][..],
            &[0x80, 0x01, 0x01][..],
            &[0x80, 0x00][..],
            &[0x80, 0x02, 0x00, 0x00][..],
            &[0xA0, 0x03, 0x02, 0x01, 0x00][..],
            &[0x81, 0x01, 0x00][..],
            &[0x81, 0x01, 0x01][..],
        ] {
            let permitted = der_wrap(0xA0, &general_subtree(0x82, b"example.com", suffix));
            assert!(NameConstraints::from_der(&name_constraints(&[permitted])).is_err());
        }
    }

    #[test]
    fn test_name_constraints_reject_empty_duplicate_and_out_of_order_fields() {
        use der::Decode;

        let subtree = general_subtree(0x82, b"example.com", &[]);
        let permitted = der_wrap(0xA0, &subtree);
        let excluded = der_wrap(0xA1, &subtree);

        for malformed in [
            der_wrap(0x30, &[]),
            name_constraints(&[der_wrap(0xA0, &[])]),
            name_constraints(&[der_wrap(0xA1, &[])]),
            name_constraints(&[permitted.clone(), permitted.clone()]),
            name_constraints(&[excluded.clone(), excluded.clone()]),
            name_constraints(&[excluded, permitted]),
        ] {
            assert!(NameConstraints::from_der(&malformed).is_err());
        }
    }

    #[test]
    fn test_name_constraints_reject_explicit_or_wrongly_tagged_fields() {
        use der::Decode;

        let subtree = general_subtree(0x82, b"example.com", &[]);
        let explicitly_wrapped = der_wrap(0xA0, &der_wrap(0x30, &subtree));
        let primitive_field = der_wrap(0x80, &subtree);
        let unknown_field = der_wrap(0xA2, &subtree);

        for malformed in [explicitly_wrapped, primitive_field, unknown_field] {
            assert!(NameConstraints::from_der(&name_constraints(&[malformed])).is_err());
        }
    }

    #[test]
    fn test_name_constraints_reject_malformed_general_subtree_base() {
        use der::Decode;

        let cases = [
            der_wrap(0x30, &[]),
            general_subtree(0xA2, b"example.com", &[]),
            general_subtree(0x84, &[0x30, 0x00], &[]),
            general_subtree(0xA7, &[192, 0, 2, 1], &[]),
            general_subtree(0x87, &[192, 0, 2, 1, 0], &[]),
            general_subtree(0x82, &[0xFF], &[]),
            general_subtree(0x88, &[0x2A, 0x80, 0x03], &[]),
            general_subtree(0xA0, &[], &[]),
            general_subtree(0xA0, &[0x06, 0x01, 0x2A], &[]),
            general_subtree(0xA3, &[], &[]),
            general_subtree(0xA3, &[0x05, 0x00], &[]),
            general_subtree(0xA5, &[], &[]),
            general_subtree(0xA5, &[0xA1, 0x00], &[]),
        ];

        for subtree in cases {
            let permitted = der_wrap(0xA0, &subtree);
            assert!(NameConstraints::from_der(&name_constraints(&[permitted])).is_err());
        }
    }

    #[test]
    fn test_name_constraints_reject_subtree_and_outer_trailing_data() {
        use der::Decode;

        let trailing_base = general_subtree(0x82, b"example.com", &[0x87, 0x04, 192, 0, 2, 1]);
        let permitted = der_wrap(0xA0, &trailing_base);
        assert!(NameConstraints::from_der(&name_constraints(&[permitted])).is_err());

        let permitted = der_wrap(0xA0, &general_subtree(0x82, b"example.com", &[]));
        let mut trailing_outer = name_constraints(&[permitted]);
        trailing_outer.push(0);
        assert!(NameConstraints::from_der(&trailing_outer).is_err());
    }

    #[test]
    fn test_name_constraints_reject_noncanonical_length_and_high_tag() {
        use der::Decode;

        let canonical = name_constraints(&[der_wrap(0xA0, &general_subtree(0x82, b"a", &[]))]);
        let mut noncanonical_length = vec![0x30, 0x81, canonical[1]];
        noncanonical_length.extend_from_slice(&canonical[2..]);
        assert!(NameConstraints::from_der(&noncanonical_length).is_err());

        let high_tag_subtree = der_wrap(0x30, &[0x9F, 0x02, 0x00]);
        let permitted = der_wrap(0xA0, &high_tag_subtree);
        assert!(NameConstraints::from_der(&name_constraints(&[permitted])).is_err());
    }

    #[test]
    fn test_basic_constraints() {
        let bc_ee = BasicConstraints::new_end_entity();
        assert!(!bc_ee.ca);
        assert_eq!(bc_ee.path_len_constraint, None);

        let bc_ca = BasicConstraints::new_ca(Some(3));
        assert!(bc_ca.ca);
        assert_eq!(bc_ca.path_len_constraint, Some(3));
    }

    #[test]
    fn test_key_usage() {
        let ku = KeyUsage::new(
            KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_ENCIPHERMENT | KeyUsage::KEY_CERT_SIGN,
        );

        assert!(ku.has(KeyUsage::DIGITAL_SIGNATURE));
        assert!(ku.has(KeyUsage::KEY_ENCIPHERMENT));
        assert!(ku.has(KeyUsage::KEY_CERT_SIGN));
        assert!(!ku.has(KeyUsage::CRL_SIGN));
        assert!(!ku.has(KeyUsage::DATA_ENCIPHERMENT));
    }

    #[test]
    fn test_extended_key_usage() {
        let eku = ExtendedKeyUsage::new(vec![
            extended_key_usage_oids::SERVER_AUTH,
            extended_key_usage_oids::CLIENT_AUTH,
        ]);

        assert!(eku.is_server_auth());
        assert!(eku.is_client_auth());
        assert!(!eku.is_code_signing());
    }
}
