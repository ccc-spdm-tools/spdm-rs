// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Distinguished Name (DN) and Subject Alternative Name (SAN) support for X.509 certificates.
//!
//! This module provides parsing and representation for X.509 distinguished names and
//! subject alternative names, including:
//! - RDNSequence (Distinguished Names)
//! - RelativeDistinguishedName (RDN)
//! - AttributeTypeAndValue
//! - Common DN attributes (CN, O, OU, C, ST, L, etc.)
//! - SubjectAltName extension with GeneralName variants

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use const_oid::ObjectIdentifier;
use der::{
    asn1::{Ia5String, PrintableString, SetOfVec, Utf8StringRef},
    Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, Header, Length, Reader, Sequence,
    Tag, TagNumber, Tagged, ValueOrd, Writer,
};

// ============================================================================
// Common Attribute Type OIDs (RFC 5280, Appendix A.1)
// ============================================================================

/// Common Name (CN) - 2.5.4.3
pub const CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Surname (SN) - 2.5.4.4
pub const SURNAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.4");

/// Serial Number - 2.5.4.5
pub const SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");

/// Country (C) - 2.5.4.6
pub const COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");

/// Locality (L) - 2.5.4.7
pub const LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");

/// State or Province (ST) - 2.5.4.8
pub const STATE_OR_PROVINCE_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");

/// Street Address - 2.5.4.9
pub const STREET_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.9");

/// Organization (O) - 2.5.4.10
pub const ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

/// Organizational Unit (OU) - 2.5.4.11
pub const ORGANIZATIONAL_UNIT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");

/// Title - 2.5.4.12
pub const TITLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.12");

/// Given Name - 2.5.4.42
pub const GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");

/// Domain Component (DC) - 0.9.2342.19200300.100.1.25
pub const DOMAIN_COMPONENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25");

/// Email Address - 1.2.840.113549.1.9.1
pub const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

// ============================================================================
// DirectoryString - RFC 5280 Section 4.1.2.4
// ============================================================================

/// DirectoryString represents various ASN.1 string types used in X.509 names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryString {
    /// TeletexString (T61String) - Tag 20
    TeletexString(Vec<u8>),
    /// PrintableString - Tag 19
    PrintableString(PrintableString),
    /// UniversalString - Tag 28
    UniversalString(Vec<u8>),
    /// UTF8String - Tag 12
    Utf8String(String),
    /// BMPString - Tag 30
    BmpString(Vec<u8>),
    /// IA5String - Tag 22 (used for email addresses)
    Ia5String(Ia5String),
}

impl DirectoryString {
    /// Get the string value as UTF-8, converting if necessary.
    pub fn as_str(&self) -> Result<String, Error> {
        match self {
            DirectoryString::Utf8String(s) => Ok(s.clone()),
            DirectoryString::PrintableString(s) => Ok(s.to_string()),
            DirectoryString::Ia5String(s) => Ok(s.as_str().to_string()),
            DirectoryString::TeletexString(bytes) => String::from_utf8(bytes.clone())
                .or_else(|_| Ok(String::from_utf8_lossy(bytes).to_string())),
            DirectoryString::BmpString(bytes) => {
                if bytes.len() % 2 != 0 {
                    return Err(ErrorKind::Length {
                        tag: Tag::BmpString,
                    }
                    .into());
                }
                let utf16_chars: Vec<u16> = bytes
                    .chunks(2)
                    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                    .collect();
                String::from_utf16(&utf16_chars).map_err(|_| {
                    ErrorKind::Value {
                        tag: Tag::BmpString,
                    }
                    .into()
                })
            }
            DirectoryString::UniversalString(bytes) => {
                if bytes.len() % 4 != 0 {
                    return Err(ErrorKind::Length {
                        tag: Tag::TeletexString,
                    }
                    .into());
                }
                let mut result = String::new();
                for chunk in bytes.chunks(4) {
                    let code_point = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let ch = char::from_u32(code_point).ok_or(ErrorKind::Value {
                        tag: Tag::TeletexString,
                    })?;
                    result.push(ch);
                }
                Ok(result)
            }
        }
    }
}

impl<'a> DecodeValue<'a> for DirectoryString {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        match header.tag {
            Tag::Utf8String => {
                let s = Utf8StringRef::decode_value(reader, header)?;
                Ok(DirectoryString::Utf8String(s.as_str().to_string()))
            }
            Tag::PrintableString => {
                let s = PrintableString::decode_value(reader, header)?;
                Ok(DirectoryString::PrintableString(s))
            }
            Tag::Ia5String => {
                let s = Ia5String::decode_value(reader, header)?;
                Ok(DirectoryString::Ia5String(s))
            }
            Tag::TeletexString => {
                let bytes = reader.read_vec(header.length)?;
                Ok(DirectoryString::TeletexString(bytes))
            }
            Tag::BmpString => {
                let bytes = reader.read_vec(header.length)?;
                Ok(DirectoryString::BmpString(bytes))
            }
            _ => Err(ErrorKind::TagUnexpected {
                expected: Some(Tag::Utf8String),
                actual: header.tag,
            }
            .into()),
        }
    }
}

impl EncodeValue for DirectoryString {
    fn value_len(&self) -> der::Result<Length> {
        match self {
            DirectoryString::Utf8String(s) => s.len().try_into(),
            DirectoryString::PrintableString(s) => s.value_len(),
            DirectoryString::Ia5String(s) => s.value_len(),
            DirectoryString::TeletexString(bytes) => bytes.len().try_into(),
            DirectoryString::BmpString(bytes) => bytes.len().try_into(),
            DirectoryString::UniversalString(bytes) => bytes.len().try_into(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            DirectoryString::Utf8String(s) => writer.write(s.as_bytes()),
            DirectoryString::PrintableString(s) => s.encode_value(writer),
            DirectoryString::Ia5String(s) => s.encode_value(writer),
            DirectoryString::TeletexString(bytes) => writer.write(bytes),
            DirectoryString::BmpString(bytes) => writer.write(bytes),
            DirectoryString::UniversalString(bytes) => writer.write(bytes),
        }
    }
}

impl DirectoryString {
    /// Get the raw ASN.1 tag byte for encoding.
    ///
    /// The `der` crate (0.7) does not include `Tag::UniversalString` (0x1C),
    /// so we handle encoding manually to ensure correct round-trip fidelity.
    fn encoding_tag_byte(&self) -> u8 {
        match self {
            DirectoryString::Utf8String(_) => 0x0C,
            DirectoryString::PrintableString(_) => 0x13,
            DirectoryString::Ia5String(_) => 0x16,
            DirectoryString::TeletexString(_) => 0x14,
            DirectoryString::BmpString(_) => 0x1E,
            DirectoryString::UniversalString(_) => 0x1C,
        }
    }
}

// Manual `Encode` implementation to handle UniversalString (tag 0x1C)
// which is not representable via the `der` crate's `Tag` enum.
impl Encode for DirectoryString {
    fn encoded_len(&self) -> der::Result<Length> {
        let value_len = self.value_len()?;
        (Length::ONE + value_len.encoded_len()?)? + value_len
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write_byte(self.encoding_tag_byte())?;
        self.value_len()?.encode(writer)?;
        self.encode_value(writer)
    }
}

impl fmt::Display for DirectoryString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "<invalid encoding>"),
        }
    }
}

// ============================================================================
// AttributeTypeAndValue - RFC 5280 Section 4.1.2.4
// ============================================================================

/// AttributeTypeAndValue represents a single attribute in an RDN.
///
/// Uses raw DER bytes for the value field to support ASN.1 tags not
/// representable in [`der::Tag`] (e.g., UniversalString tag 0x1C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeTypeAndValue {
    /// Attribute type (OID)
    pub oid: ObjectIdentifier,
    /// Raw DER-encoded value (tag + length + content).
    raw_value: Vec<u8>,
}

// Manual Sequence / DecodeValue / EncodeValue impls so we can handle unknown
// tag bytes (like UniversalString 0x1C) that the `der` crate rejects.

impl<'a> DecodeValue<'a> for AttributeTypeAndValue {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |nested| {
            let oid = ObjectIdentifier::decode(nested)?;

            // Read all remaining bytes as the raw DER TLV of the value field.
            let remaining = nested.remaining_len();
            let raw_value = nested.read_vec(remaining)?;

            if raw_value.is_empty() {
                return Err(ErrorKind::Length { tag: Tag::Sequence }.into());
            }

            Ok(Self { oid, raw_value })
        })
    }
}

impl EncodeValue for AttributeTypeAndValue {
    fn value_len(&self) -> der::Result<Length> {
        let oid_len = self.oid.encoded_len()?;
        let raw_len = Length::try_from(self.raw_value.len())?;
        oid_len + raw_len
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.oid.encode(writer)?;
        writer.write(&self.raw_value)
    }
}

impl Sequence<'_> for AttributeTypeAndValue {}

impl AttributeTypeAndValue {
    /// Create a new AttributeTypeAndValue with a DirectoryString value.
    pub fn new(oid: ObjectIdentifier, value: DirectoryString) -> Result<Self, Error> {
        use der::Encode;
        let raw_value = value.to_der()?;
        Ok(Self { oid, raw_value })
    }

    /// Create a new AttributeTypeAndValue with a UTF-8 string value.
    pub fn new_utf8(oid: ObjectIdentifier, value: &str) -> Result<Self, Error> {
        Self::new(oid, DirectoryString::Utf8String(value.to_string()))
    }

    /// Create a new AttributeTypeAndValue with a PrintableString value.
    pub fn new_printable(oid: ObjectIdentifier, value: &str) -> Result<Self, Error> {
        let printable = PrintableString::new(value).map_err(|_| ErrorKind::Value {
            tag: Tag::PrintableString,
        })?;
        Self::new(oid, DirectoryString::PrintableString(printable))
    }

    /// The raw tag byte of the attribute value.
    pub fn value_tag_byte(&self) -> u8 {
        self.raw_value.first().copied().unwrap_or(0)
    }

    /// The content bytes of the attribute value (after tag + length).
    pub fn value_content(&self) -> &[u8] {
        if self.raw_value.len() < 2 {
            return &[];
        }
        let len_byte = self.raw_value[1];
        if len_byte & 0x80 == 0 {
            // short form
            self.raw_value.get(2..).unwrap_or(&[])
        } else {
            let n = (len_byte & 0x7F) as usize;
            self.raw_value.get(2 + n..).unwrap_or(&[])
        }
    }

    /// Get the attribute value as a [`DirectoryString`].
    ///
    /// Handles all standard string types including UniversalString (tag 0x1C)
    /// which is not representable in [`der::Tag`].
    pub fn directory_string(&self) -> Result<DirectoryString, Error> {
        let tag_byte = self.value_tag_byte();
        let content = self.value_content();

        if content.is_empty() && tag_byte != 0 {
            return Err(ErrorKind::Length {
                tag: Tag::Utf8String,
            }
            .into());
        }

        match tag_byte {
            // UTF8String (0x0C)
            0x0C => String::from_utf8(content.to_vec())
                .map(DirectoryString::Utf8String)
                .map_err(|_| {
                    ErrorKind::Value {
                        tag: Tag::Utf8String,
                    }
                    .into()
                }),
            // PrintableString (0x13)
            0x13 => {
                let ps = PrintableString::new(core::str::from_utf8(content).map_err(|_| {
                    ErrorKind::Value {
                        tag: Tag::PrintableString,
                    }
                })?)
                .map_err(|_| ErrorKind::Value {
                    tag: Tag::PrintableString,
                })?;
                Ok(DirectoryString::PrintableString(ps))
            }
            // IA5String (0x16)
            0x16 => {
                let ia5 = Ia5String::new(core::str::from_utf8(content).map_err(|_| {
                    ErrorKind::Value {
                        tag: Tag::Ia5String,
                    }
                })?)
                .map_err(|_| ErrorKind::Value {
                    tag: Tag::Ia5String,
                })?;
                Ok(DirectoryString::Ia5String(ia5))
            }
            // TeletexString / T61String (0x14)
            0x14 => Ok(DirectoryString::TeletexString(content.to_vec())),
            // BMPString (0x1E)
            0x1E => Ok(DirectoryString::BmpString(content.to_vec())),
            // UniversalString (0x1C)
            0x1C => Ok(DirectoryString::UniversalString(content.to_vec())),
            _ => Err(ErrorKind::TagUnexpected {
                expected: Some(Tag::Utf8String),
                actual: Tag::try_from(tag_byte).unwrap_or(Tag::Utf8String),
            }
            .into()),
        }
    }

    /// Get the attribute value as a UTF-8 string.
    pub fn value_as_str(&self) -> Result<String, Error> {
        self.directory_string()?.as_str()
    }

    /// Get a short name for the attribute type if known.
    pub fn attr_name(&self) -> &str {
        match self.oid {
            CN => "CN",
            SURNAME => "SN",
            SERIAL_NUMBER => "SERIALNUMBER",
            COUNTRY_NAME => "C",
            LOCALITY_NAME => "L",
            STATE_OR_PROVINCE_NAME => "ST",
            STREET_ADDRESS => "STREET",
            ORGANIZATION_NAME => "O",
            ORGANIZATIONAL_UNIT_NAME => "OU",
            TITLE => "TITLE",
            GIVEN_NAME => "GIVENNAME",
            DOMAIN_COMPONENT => "DC",
            EMAIL_ADDRESS => "emailAddress",
            _ => "OID",
        }
    }
}

impl fmt::Display for AttributeTypeAndValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.attr_name();
        match self.value_as_str() {
            Ok(value) => {
                if name == "OID" {
                    write!(f, "{}={}", self.oid, value)
                } else {
                    write!(f, "{}={}", name, value)
                }
            }
            Err(_) => write!(f, "{}=<error>", name),
        }
    }
}

impl ValueOrd for AttributeTypeAndValue {
    fn value_cmp(&self, other: &Self) -> der::Result<core::cmp::Ordering> {
        match self.oid.cmp(&other.oid) {
            core::cmp::Ordering::Equal => Ok(self.raw_value.cmp(&other.raw_value)),
            other_order => Ok(other_order),
        }
    }
}

// ============================================================================
// RelativeDistinguishedName - RFC 5280 Section 4.1.2.4
// ============================================================================

/// RelativeDistinguishedName (RDN) is a SET OF AttributeTypeAndValue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativeDistinguishedName {
    /// Set of attributes
    pub attributes: SetOfVec<AttributeTypeAndValue>,
}

impl RelativeDistinguishedName {
    /// Create a new RDN with a single attribute.
    pub fn new(attr: AttributeTypeAndValue) -> Result<Self, Error> {
        let mut attributes = SetOfVec::new();
        attributes
            .insert(attr)
            .map_err(|_| ErrorKind::Value { tag: Tag::Set })?;
        Ok(Self { attributes })
    }

    /// Create a new RDN from multiple attributes.
    pub fn from_attributes(attrs: Vec<AttributeTypeAndValue>) -> Result<Self, Error> {
        let mut attributes = SetOfVec::new();
        for attr in attrs {
            attributes
                .insert(attr)
                .map_err(|_| ErrorKind::Value { tag: Tag::Set })?;
        }
        Ok(Self { attributes })
    }

    /// Get the first (or only) attribute in this RDN.
    pub fn first(&self) -> Option<&AttributeTypeAndValue> {
        self.attributes.iter().next()
    }

    /// Check if this is a multi-valued RDN.
    pub fn is_multi_valued(&self) -> bool {
        self.attributes.len() > 1
    }
}

impl<'a> DecodeValue<'a> for RelativeDistinguishedName {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let attributes = SetOfVec::decode_value(reader, header)?;
        Ok(Self { attributes })
    }
}

impl EncodeValue for RelativeDistinguishedName {
    fn value_len(&self) -> der::Result<Length> {
        self.attributes.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.attributes.encode_value(writer)
    }
}

impl der::FixedTag for RelativeDistinguishedName {
    const TAG: Tag = Tag::Set;
}

impl fmt::Display for RelativeDistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attrs: Vec<String> = self.attributes.iter().map(|a| a.to_string()).collect();
        write!(f, "{}", attrs.join("+"))
    }
}

// ============================================================================
// RDNSequence (Name) - RFC 5280 Section 4.1.2.4
// ============================================================================

/// RDNSequence represents a Distinguished Name (DN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RDNSequence {
    /// Sequence of RDNs, ordered from root to leaf
    pub rdns: Vec<RelativeDistinguishedName>,
}

impl<'a> DecodeValue<'a> for RDNSequence {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let mut rdns = Vec::new();
            while !reader.is_finished() {
                rdns.push(RelativeDistinguishedName::decode(reader)?);
            }
            Ok(Self { rdns })
        })
    }
}

impl EncodeValue for RDNSequence {
    fn value_len(&self) -> der::Result<Length> {
        let mut len = Length::ZERO;
        for rdn in &self.rdns {
            len = (len + rdn.encoded_len()?)?;
        }
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        for rdn in &self.rdns {
            rdn.encode(writer)?;
        }
        Ok(())
    }
}

impl der::FixedTag for RDNSequence {
    const TAG: Tag = Tag::Sequence;
}

impl RDNSequence {
    /// Create a new empty RDNSequence.
    pub fn new() -> Self {
        Self { rdns: Vec::new() }
    }

    /// Create an RDNSequence from a vector of RDNs.
    pub fn from_rdns(rdns: Vec<RelativeDistinguishedName>) -> Self {
        Self { rdns }
    }

    /// Add an RDN to the sequence.
    pub fn push(&mut self, rdn: RelativeDistinguishedName) {
        self.rdns.push(rdn);
    }

    /// Get an iterator over the RDNs.
    pub fn iter(&self) -> core::slice::Iter<'_, RelativeDistinguishedName> {
        self.rdns.iter()
    }

    /// Find the first attribute with the given OID.
    pub fn find_attr(&self, oid: ObjectIdentifier) -> Option<&AttributeTypeAndValue> {
        for rdn in &self.rdns {
            for attr in rdn.attributes.iter() {
                if attr.oid == oid {
                    return Some(attr);
                }
            }
        }
        None
    }

    /// Get the Common Name (CN) if present.
    pub fn common_name(&self) -> Option<String> {
        self.find_attr(CN).and_then(|a| a.value_as_str().ok())
    }

    /// Get the Organization (O) if present.
    pub fn organization(&self) -> Option<String> {
        self.find_attr(ORGANIZATION_NAME)
            .and_then(|a| a.value_as_str().ok())
    }

    /// Get the Country (C) if present.
    pub fn country(&self) -> Option<String> {
        self.find_attr(COUNTRY_NAME)
            .and_then(|a| a.value_as_str().ok())
    }
}

impl Default for RDNSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RDNSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rdns.is_empty() {
            return write!(f, "");
        }
        let rdns: Vec<String> = self.rdns.iter().rev().map(|r| r.to_string()).collect();
        write!(f, "{}", rdns.join(", "))
    }
}

/// Type alias for Name (which is just RDNSequence in practice).
pub type Name = RDNSequence;

// ============================================================================
// GeneralName - RFC 5280 Section 4.2.1.6
// ============================================================================

/// GeneralName represents various name types in SubjectAltName extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralName {
    /// otherName `[0]`
    OtherName(Vec<u8>),
    /// rfc822Name `[1]` - Email address
    Rfc822Name(String),
    /// dNSName `[2]` - DNS hostname
    DnsName(String),
    /// x400Address `[3]`
    X400Address(Vec<u8>),
    /// directoryName `[4]` - Distinguished Name
    DirectoryName(Name),
    /// ediPartyName `[5]`
    EdiPartyName(Vec<u8>),
    /// uniformResourceIdentifier `[6]` - URI
    Uri(String),
    /// iPAddress `[7]` - IPv4 or IPv6 address
    IpAddress(Vec<u8>),
    /// registeredID `[8]` - OID
    RegisteredId(ObjectIdentifier),
}

impl GeneralName {
    fn tag_number(&self) -> TagNumber {
        match self {
            GeneralName::OtherName(_) => TagNumber::N0,
            GeneralName::Rfc822Name(_) => TagNumber::N1,
            GeneralName::DnsName(_) => TagNumber::N2,
            GeneralName::X400Address(_) => TagNumber::N3,
            GeneralName::DirectoryName(_) => TagNumber::N4,
            GeneralName::EdiPartyName(_) => TagNumber::N5,
            GeneralName::Uri(_) => TagNumber::N6,
            GeneralName::IpAddress(_) => TagNumber::N7,
            GeneralName::RegisteredId(_) => TagNumber::N8,
        }
    }

    /// Parse an IP address (4 bytes for IPv4, 16 bytes for IPv6).
    pub fn ip_address_string(&self) -> Option<String> {
        if let GeneralName::IpAddress(bytes) = self {
            match bytes.len() {
                4 => Some(alloc::format!(
                    "{}.{}.{}.{}",
                    bytes[0],
                    bytes[1],
                    bytes[2],
                    bytes[3]
                )),
                16 => {
                    let parts: Vec<String> = bytes
                        .chunks(2)
                        .map(|c| alloc::format!("{:x}{:x}", c[0], c[1]))
                        .collect();
                    Some(parts.join(":"))
                }
                _ => None,
            }
        } else {
            None
        }
    }
}

impl<'a> DecodeValue<'a> for GeneralName {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let tag = header.tag;

        if !tag.is_context_specific() {
            return Err(ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            }
            .into());
        }

        match tag.number() {
            TagNumber::N0 => {
                let bytes = reader.read_vec(header.length)?;
                Ok(GeneralName::OtherName(bytes))
            }
            TagNumber::N1 => {
                let bytes = reader.read_vec(header.length)?;
                let s = core::str::from_utf8(&bytes)
                    .map_err(|_| ErrorKind::Value { tag })?
                    .to_string();
                Ok(GeneralName::Rfc822Name(s))
            }
            TagNumber::N2 => {
                let bytes = reader.read_vec(header.length)?;
                let s = core::str::from_utf8(&bytes)
                    .map_err(|_| ErrorKind::Value { tag })?
                    .to_string();
                Ok(GeneralName::DnsName(s))
            }
            TagNumber::N3 => {
                let bytes = reader.read_vec(header.length)?;
                Ok(GeneralName::X400Address(bytes))
            }
            TagNumber::N4 => {
                // DirectoryName is EXPLICIT [4] Name.  The outer header has
                // already been consumed; the inner bytes should start with a
                // SEQUENCE tag.  We use `read_nested` to scope reading to
                // exactly `header.length` bytes so we handle both EXPLICIT
                // (inner SEQUENCE present) and degenerate encodings safely.
                let name = reader.read_nested(header.length, Name::decode)?;
                Ok(GeneralName::DirectoryName(name))
            }
            TagNumber::N5 => {
                let bytes = reader.read_vec(header.length)?;
                Ok(GeneralName::EdiPartyName(bytes))
            }
            TagNumber::N6 => {
                let bytes = reader.read_vec(header.length)?;
                let s = core::str::from_utf8(&bytes)
                    .map_err(|_| ErrorKind::Value { tag })?
                    .to_string();
                Ok(GeneralName::Uri(s))
            }
            TagNumber::N7 => {
                let bytes = reader.read_vec(header.length)?;
                Ok(GeneralName::IpAddress(bytes))
            }
            TagNumber::N8 => {
                let oid = ObjectIdentifier::decode(reader)?;
                Ok(GeneralName::RegisteredId(oid))
            }
            _ => Err(ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            }
            .into()),
        }
    }
}

impl EncodeValue for GeneralName {
    fn value_len(&self) -> der::Result<Length> {
        match self {
            GeneralName::OtherName(bytes) => bytes.len().try_into(),
            GeneralName::Rfc822Name(s) => s.len().try_into(),
            GeneralName::DnsName(s) => s.len().try_into(),
            GeneralName::X400Address(bytes) => bytes.len().try_into(),
            GeneralName::DirectoryName(name) => name.encoded_len(),
            GeneralName::EdiPartyName(bytes) => bytes.len().try_into(),
            GeneralName::Uri(s) => s.len().try_into(),
            GeneralName::IpAddress(bytes) => bytes.len().try_into(),
            GeneralName::RegisteredId(oid) => oid.encoded_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            GeneralName::OtherName(bytes) => writer.write(bytes),
            GeneralName::Rfc822Name(s) => writer.write(s.as_bytes()),
            GeneralName::DnsName(s) => writer.write(s.as_bytes()),
            GeneralName::X400Address(bytes) => writer.write(bytes),
            GeneralName::DirectoryName(name) => name.encode(writer),
            GeneralName::EdiPartyName(bytes) => writer.write(bytes),
            GeneralName::Uri(s) => writer.write(s.as_bytes()),
            GeneralName::IpAddress(bytes) => writer.write(bytes),
            GeneralName::RegisteredId(oid) => oid.encode(writer),
        }
    }
}

impl Tagged for GeneralName {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: matches!(
                self,
                GeneralName::OtherName(_)
                    | GeneralName::DirectoryName(_)
                    | GeneralName::EdiPartyName(_)
            ),
            number: self.tag_number(),
        }
    }
}

impl fmt::Display for GeneralName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneralName::OtherName(_) => write!(f, "otherName:<unsupported>"),
            GeneralName::Rfc822Name(email) => write!(f, "email:{}", email),
            GeneralName::DnsName(dns) => write!(f, "DNS:{}", dns),
            GeneralName::X400Address(_) => write!(f, "X400:<unsupported>"),
            GeneralName::DirectoryName(name) => write!(f, "DirName:{}", name),
            GeneralName::EdiPartyName(_) => write!(f, "EDI:<unsupported>"),
            GeneralName::Uri(uri) => write!(f, "URI:{}", uri),
            GeneralName::IpAddress(_) => {
                if let Some(ip) = self.ip_address_string() {
                    write!(f, "IP:{}", ip)
                } else {
                    write!(f, "IP:<invalid>")
                }
            }
            GeneralName::RegisteredId(oid) => write!(f, "RegID:{}", oid),
        }
    }
}

// ============================================================================
// SubjectAltName - RFC 5280 Section 4.2.1.6
// ============================================================================

/// SubjectAltName extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectAltName {
    /// List of alternative names
    pub names: Vec<GeneralName>,
}

impl SubjectAltName {
    /// Create a new SubjectAltName.
    pub fn new(names: Vec<GeneralName>) -> Self {
        Self { names }
    }

    /// Get all DNS names.
    pub fn dns_names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().filter_map(|n| match n {
            GeneralName::DnsName(dns) => Some(dns.as_str()),
            _ => None,
        })
    }

    /// Get all email addresses.
    pub fn email_addresses(&self) -> impl Iterator<Item = &str> {
        self.names.iter().filter_map(|n| match n {
            GeneralName::Rfc822Name(email) => Some(email.as_str()),
            _ => None,
        })
    }

    /// Get all IP addresses.
    pub fn ip_addresses(&self) -> impl Iterator<Item = &[u8]> {
        self.names.iter().filter_map(|n| match n {
            GeneralName::IpAddress(ip) => Some(ip.as_slice()),
            _ => None,
        })
    }

    /// Get all URIs.
    pub fn uris(&self) -> impl Iterator<Item = &str> {
        self.names.iter().filter_map(|n| match n {
            GeneralName::Uri(uri) => Some(uri.as_str()),
            _ => None,
        })
    }
}

impl<'a> DecodeValue<'a> for SubjectAltName {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let mut names = Vec::new();
        reader.read_nested(header.length, |reader| {
            while !reader.is_finished() {
                let name_header = Header::decode(reader)?;
                let name = GeneralName::decode_value(reader, name_header)?;
                names.push(name);
            }
            Ok(())
        })?;
        Ok(Self { names })
    }
}

impl EncodeValue for SubjectAltName {
    fn value_len(&self) -> der::Result<Length> {
        let mut len = Length::ZERO;
        for name in &self.names {
            len = (len + name.encoded_len()?)?;
        }
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        for name in &self.names {
            name.encode(writer)?;
        }
        Ok(())
    }
}

impl der::FixedTag for SubjectAltName {
    const TAG: Tag = Tag::Sequence;
}

impl fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self.names.iter().map(|n| n.to_string()).collect();
        write!(f, "{}", names.join(", "))
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
    fn test_directory_string_utf8() {
        let ds = DirectoryString::Utf8String("Hello World".to_string());
        assert_eq!(ds.as_str().unwrap(), "Hello World");
        assert_eq!(ds.to_string(), "Hello World");
    }

    #[test]
    fn test_attribute_type_and_value() {
        let attr = AttributeTypeAndValue::new_utf8(CN, "Example Corp").unwrap();
        assert_eq!(attr.oid, CN);
        assert_eq!(attr.value_as_str().unwrap(), "Example Corp");
        assert_eq!(attr.attr_name(), "CN");
        assert_eq!(attr.to_string(), "CN=Example Corp");
    }

    #[test]
    fn test_rdn() {
        let attr = AttributeTypeAndValue::new_utf8(CN, "Test").unwrap();
        let rdn = RelativeDistinguishedName::new(attr).unwrap();
        assert!(!rdn.is_multi_valued());
        assert_eq!(rdn.to_string(), "CN=Test");
    }

    #[test]
    fn test_rdn_sequence() {
        let mut name = RDNSequence::new();

        let cn_attr = AttributeTypeAndValue::new_utf8(CN, "John Doe").unwrap();
        name.push(RelativeDistinguishedName::new(cn_attr).unwrap());

        let o_attr = AttributeTypeAndValue::new_utf8(ORGANIZATION_NAME, "Example Inc").unwrap();
        name.push(RelativeDistinguishedName::new(o_attr).unwrap());

        let c_attr = AttributeTypeAndValue::new_printable(COUNTRY_NAME, "US").unwrap();
        name.push(RelativeDistinguishedName::new(c_attr).unwrap());

        assert_eq!(name.common_name().unwrap(), "John Doe");
        assert_eq!(name.organization().unwrap(), "Example Inc");
        assert_eq!(name.country().unwrap(), "US");

        let dn_str = name.to_string();
        assert!(dn_str.starts_with("C=US"));
    }

    #[test]
    fn test_general_name_dns() {
        let gn = GeneralName::DnsName("example.com".to_string());
        assert_eq!(gn.to_string(), "DNS:example.com");
    }

    #[test]
    fn test_general_name_email() {
        let gn = GeneralName::Rfc822Name("user@example.com".to_string());
        assert_eq!(gn.to_string(), "email:user@example.com");
    }

    #[test]
    fn test_general_name_ip() {
        let gn = GeneralName::IpAddress(vec![192, 168, 1, 1]);
        assert_eq!(gn.ip_address_string().unwrap(), "192.168.1.1");
        assert_eq!(gn.to_string(), "IP:192.168.1.1");
    }

    #[test]
    fn test_subject_alt_name() {
        let san = SubjectAltName::new(vec![
            GeneralName::DnsName("example.com".to_string()),
            GeneralName::DnsName("www.example.com".to_string()),
            GeneralName::Rfc822Name("admin@example.com".to_string()),
            GeneralName::IpAddress(vec![192, 168, 1, 1]),
        ]);

        let dns_names: Vec<&str> = san.dns_names().collect();
        assert_eq!(dns_names.len(), 2);
        assert!(dns_names.contains(&"example.com"));
        assert!(dns_names.contains(&"www.example.com"));

        let emails: Vec<&str> = san.email_addresses().collect();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0], "admin@example.com");
    }

    #[test]
    fn test_common_oids() {
        assert_eq!(CN.to_string(), "2.5.4.3");
        assert_eq!(ORGANIZATION_NAME.to_string(), "2.5.4.10");
        assert_eq!(COUNTRY_NAME.to_string(), "2.5.4.6");
    }

    #[test]
    fn test_encode_decode_rdn_sequence() {
        let mut name = RDNSequence::new();

        let cn = AttributeTypeAndValue::new_utf8(CN, "Test User").unwrap();
        name.push(RelativeDistinguishedName::new(cn).unwrap());

        let o = AttributeTypeAndValue::new_utf8(ORGANIZATION_NAME, "Test Org").unwrap();
        name.push(RelativeDistinguishedName::new(o).unwrap());

        let der = name.to_der().unwrap();
        let decoded = RDNSequence::from_der(&der).unwrap();

        assert_eq!(name, decoded);
        assert_eq!(decoded.common_name().unwrap(), "Test User");
        assert_eq!(decoded.organization().unwrap(), "Test Org");
    }
}
