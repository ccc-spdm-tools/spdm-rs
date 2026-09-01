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
    Decode, DecodeValue, DerOrd, Encode, EncodeValue, Error, ErrorKind, Header, Length, Reader,
    Sequence, Tag, TagNumber, Tagged, ValueOrd, Writer,
};

fn owned_bytes(bytes: &[u8]) -> der::Result<Vec<u8>> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| ErrorKind::Overlength)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn read_owned_bytes<'a, R: Reader<'a>>(reader: &mut R, length: Length) -> der::Result<Vec<u8>> {
    owned_bytes(reader.read_slice(length)?)
}

fn owned_string(value: &str) -> der::Result<String> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| ErrorKind::Overlength)?;
    owned.push_str(value);
    Ok(owned)
}

const DIRECTORY_STRING_MAX_CHARS: usize = 32768;

fn utf8_string_value_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.chars().take(DIRECTORY_STRING_MAX_CHARS + 1).count() <= DIRECTORY_STRING_MAX_CHARS
}

fn bmp_string_value_is_valid(bytes: &[u8]) -> bool {
    matches!(bytes.len(), 2..=65536)
        && bytes.len() & 1 == 0
        && bytes.chunks_exact(2).all(|chunk| {
            !matches!(
                u16::from_be_bytes([chunk[0], chunk[1]]),
                0xD800..=0xDFFF | 0xFFFE | 0xFFFF
            )
        })
}

fn universal_string_value_is_valid(bytes: &[u8]) -> bool {
    matches!(bytes.len(), 4..=131072)
        && bytes.len() & 3 == 0
        && bytes.chunks_exact(4).all(|chunk| {
            let code = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            char::from_u32(code).is_some() && code & 0xFFFF < 0xFFFE
        })
}

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
            DirectoryString::Utf8String(s) if utf8_string_value_is_valid(s) => owned_string(s),
            DirectoryString::PrintableString(s)
                if (1..=DIRECTORY_STRING_MAX_CHARS).contains(&s.as_str().len()) =>
            {
                owned_string(s.as_str())
            }
            DirectoryString::Ia5String(s)
                if (1..=DIRECTORY_STRING_MAX_CHARS).contains(&s.as_str().len()) =>
            {
                owned_string(s.as_str())
            }
            // RFC 4518 leaves TeletexString transcoding as a local matter.
            // Support its invariant ASCII subset and fail closed otherwise.
            DirectoryString::TeletexString(bytes) => {
                if bytes.is_empty() || bytes.len() > DIRECTORY_STRING_MAX_CHARS || !bytes.is_ascii()
                {
                    return Err(ErrorKind::Value {
                        tag: Tag::TeletexString,
                    }
                    .into());
                }
                owned_string(core::str::from_utf8(bytes).map_err(|_| ErrorKind::Value {
                    tag: Tag::TeletexString,
                })?)
            }
            DirectoryString::BmpString(bytes) => {
                if !bmp_string_value_is_valid(bytes) {
                    return Err(ErrorKind::Value {
                        tag: Tag::BmpString,
                    }
                    .into());
                }
                let capacity = bytes.len().checked_mul(3).ok_or(ErrorKind::Overlength)? / 2;
                let mut result = String::new();
                result
                    .try_reserve_exact(capacity)
                    .map_err(|_| ErrorKind::Overlength)?;
                for chunk in bytes.chunks_exact(2) {
                    result.push(
                        char::from_u32(u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))).ok_or(
                            ErrorKind::Value {
                                tag: Tag::BmpString,
                            },
                        )?,
                    );
                }
                Ok(result)
            }
            DirectoryString::UniversalString(bytes) => {
                if !universal_string_value_is_valid(bytes) {
                    return Err(ErrorKind::Value {
                        tag: Tag::TeletexString,
                    }
                    .into());
                }
                let mut result = String::new();
                result
                    .try_reserve_exact(bytes.len())
                    .map_err(|_| ErrorKind::Overlength)?;
                for chunk in bytes.chunks_exact(4) {
                    let code_point = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let ch = char::from_u32(code_point).ok_or(ErrorKind::Value {
                        tag: Tag::TeletexString,
                    })?;
                    result.push(ch);
                }
                Ok(result)
            }
            _ => Err(ErrorKind::Value {
                tag: Tag::Utf8String,
            }
            .into()),
        }
    }
}

impl<'a> DecodeValue<'a> for DirectoryString {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        if header.length == Length::ZERO {
            return Err(ErrorKind::Length { tag: header.tag }.into());
        }
        let encoded_len = usize::try_from(header.length)?;
        let maximum = match header.tag {
            Tag::Utf8String => 131072,
            Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => {
                DIRECTORY_STRING_MAX_CHARS
            }
            Tag::BmpString => 65536,
            _ => 0,
        };
        if maximum != 0 && encoded_len > maximum {
            return Err(ErrorKind::Overlength.into());
        }
        match header.tag {
            Tag::Utf8String => {
                let s = Utf8StringRef::decode_value(reader, header)?;
                if !utf8_string_value_is_valid(s.as_str()) {
                    return Err(ErrorKind::Length {
                        tag: Tag::Utf8String,
                    }
                    .into());
                }
                owned_string(s.as_str()).map(DirectoryString::Utf8String)
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
                if !bmp_string_value_is_valid(&bytes) {
                    return Err(ErrorKind::Value {
                        tag: Tag::BmpString,
                    }
                    .into());
                }
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
            DirectoryString::Utf8String(s) if utf8_string_value_is_valid(s) => s.len().try_into(),
            DirectoryString::PrintableString(s)
                if (1..=DIRECTORY_STRING_MAX_CHARS).contains(&s.as_str().len()) =>
            {
                s.value_len()
            }
            DirectoryString::Ia5String(s)
                if (1..=DIRECTORY_STRING_MAX_CHARS).contains(&s.as_str().len()) =>
            {
                s.value_len()
            }
            DirectoryString::TeletexString(bytes)
                if (1..=DIRECTORY_STRING_MAX_CHARS).contains(&bytes.len()) =>
            {
                bytes.len().try_into()
            }
            DirectoryString::BmpString(bytes) if bmp_string_value_is_valid(bytes) => {
                bytes.len().try_into()
            }
            DirectoryString::UniversalString(bytes) if universal_string_value_is_valid(bytes) => {
                bytes.len().try_into()
            }
            DirectoryString::BmpString(_) => Err(ErrorKind::Value {
                tag: Tag::BmpString,
            }
            .into()),
            DirectoryString::UniversalString(_) => Err(ErrorKind::Value {
                tag: Tag::TeletexString,
            }
            .into()),
            _ => Err(ErrorKind::Length {
                tag: Tag::Utf8String,
            }
            .into()),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.value_len()?;
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
        let value_len = self.value_len()?;
        writer.write_byte(self.encoding_tag_byte())?;
        value_len.encode(writer)?;
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
            let raw_value = nested.read_slice(remaining)?;
            if raw_value.is_empty() {
                return Err(ErrorKind::Length { tag: Tag::Sequence }.into());
            }
            single_der_tlv_allowing_nonstandard_printable(raw_value, Tag::Sequence)?;

            Ok(Self {
                oid,
                raw_value: owned_bytes(raw_value)?,
            })
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
        Self::new(oid, DirectoryString::Utf8String(owned_string(value)?))
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
        let (content_offset, content_len) = if len_byte & 0x80 == 0 {
            (2, len_byte as usize)
        } else {
            let n = (len_byte & 0x7F) as usize;
            if n == 0 || n > core::mem::size_of::<usize>() || self.raw_value.len() < 2 + n {
                return &[];
            }
            let length_bytes = &self.raw_value[2..2 + n];
            if length_bytes[0] == 0 {
                return &[];
            }
            let mut content_len = 0usize;
            for byte in length_bytes {
                content_len = match content_len
                    .checked_mul(256)
                    .and_then(|length| length.checked_add(*byte as usize))
                {
                    Some(length) => length,
                    None => return &[],
                };
            }
            if content_len < 128 {
                return &[];
            }
            (2 + n, content_len)
        };
        if content_offset
            .checked_add(content_len)
            .filter(|total| *total == self.raw_value.len())
            .is_none()
        {
            return &[];
        }
        &self.raw_value[content_offset..]
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
            0x0C => {
                let value = core::str::from_utf8(content).map_err(|_| ErrorKind::Value {
                    tag: Tag::Utf8String,
                })?;
                if !utf8_string_value_is_valid(value) {
                    return Err(ErrorKind::Length {
                        tag: Tag::Utf8String,
                    }
                    .into());
                }
                owned_string(value).map(DirectoryString::Utf8String)
            }
            // PrintableString (0x13)
            0x13 => {
                if content.len() > DIRECTORY_STRING_MAX_CHARS {
                    return Err(ErrorKind::Overlength.into());
                }
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
                if content.len() > DIRECTORY_STRING_MAX_CHARS {
                    return Err(ErrorKind::Overlength.into());
                }
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
            0x14 if content.len() <= DIRECTORY_STRING_MAX_CHARS => {
                owned_bytes(content).map(DirectoryString::TeletexString)
            }
            0x14 => Err(ErrorKind::Overlength.into()),
            // BMPString (0x1E)
            0x1E if bmp_string_value_is_valid(content) => {
                owned_bytes(content).map(DirectoryString::BmpString)
            }
            // UniversalString (0x1C)
            0x1C if universal_string_value_is_valid(content) => {
                owned_bytes(content).map(DirectoryString::UniversalString)
            }
            0x1E => Err(ErrorKind::Value {
                tag: Tag::BmpString,
            }
            .into()),
            0x1C => Err(ErrorKind::Value {
                tag: Tag::TeletexString,
            }
            .into()),
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
        match self.oid.der_cmp(&other.oid)? {
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
        if attrs.is_empty() {
            return Err(ErrorKind::Length { tag: Tag::Set }.into());
        }
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
        reader.read_nested(header.length, |reader| {
            let mut decoded: Vec<AttributeTypeAndValue> = Vec::new();
            while !reader.is_finished() {
                let attribute = AttributeTypeAndValue::decode(reader)?;
                if let Some(previous) = decoded.last() {
                    match previous.der_cmp(&attribute)? {
                        core::cmp::Ordering::Less => {}
                        core::cmp::Ordering::Equal => return Err(ErrorKind::SetDuplicate.into()),
                        core::cmp::Ordering::Greater => return Err(ErrorKind::SetOrdering.into()),
                    }
                }
                decoded.try_reserve(1).map_err(|_| ErrorKind::Overlength)?;
                decoded.push(attribute);
            }
            if decoded.is_empty() {
                return Err(ErrorKind::Length { tag: Tag::Set }.into());
            }
            let attributes = SetOfVec::try_from(decoded)?;
            Ok(Self { attributes })
        })
    }
}

impl EncodeValue for RelativeDistinguishedName {
    fn value_len(&self) -> der::Result<Length> {
        if self.attributes.is_empty() {
            return Err(ErrorKind::Length { tag: Tag::Set }.into());
        }
        self.attributes.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        if self.attributes.is_empty() {
            return Err(ErrorKind::Length { tag: Tag::Set }.into());
        }
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
                rdns.try_reserve(1).map_err(|_| ErrorKind::Overlength)?;
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

    pub(crate) fn validate_structure(&self) -> der::Result<()> {
        match self {
            GeneralName::OtherName(bytes) => validate_opaque_general_name(
                TagNumber::N0,
                bytes,
                Tag::ContextSpecific {
                    constructed: true,
                    number: TagNumber::N0,
                },
            ),
            GeneralName::Rfc822Name(s) => validate_ia5_string(s, TagNumber::N1),
            GeneralName::DnsName(s) => validate_ia5_string(s, TagNumber::N2),
            GeneralName::X400Address(bytes) => validate_opaque_general_name(
                TagNumber::N3,
                bytes,
                Tag::ContextSpecific {
                    constructed: true,
                    number: TagNumber::N3,
                },
            ),
            GeneralName::EdiPartyName(bytes) => validate_opaque_general_name(
                TagNumber::N5,
                bytes,
                Tag::ContextSpecific {
                    constructed: true,
                    number: TagNumber::N5,
                },
            ),
            GeneralName::Uri(s) => validate_ia5_string(s, TagNumber::N6),
            GeneralName::IpAddress(bytes) if !matches!(bytes.len(), 4 | 8 | 16 | 32) => {
                Err(ErrorKind::Length {
                    tag: Tag::ContextSpecific {
                        constructed: false,
                        number: TagNumber::N7,
                    },
                }
                .into())
            }
            _ => Ok(()),
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

fn decode_ia5_string<'a, R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<String> {
    let bytes = reader.read_slice(header.length)?;
    if !bytes.is_ascii() {
        return Err(ErrorKind::Value { tag: header.tag }.into());
    }

    let value = core::str::from_utf8(bytes).map_err(|_| ErrorKind::Value { tag: header.tag })?;
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| ErrorKind::Overlength)?;
    owned.push_str(value);
    Ok(owned)
}

fn validate_ia5_string(value: &str, number: TagNumber) -> der::Result<()> {
    if value.is_ascii() {
        Ok(())
    } else {
        Err(ErrorKind::Value {
            tag: Tag::ContextSpecific {
                constructed: false,
                number,
            },
        }
        .into())
    }
}

fn oid_value_is_canonical(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    let mut at_arc_start = true;
    for &byte in bytes {
        if at_arc_start && byte == 0x80 {
            return false;
        }
        at_arc_start = byte & 0x80 == 0;
    }
    at_arc_start
}

#[derive(Clone, Copy)]
struct RawDerTlv<'a> {
    tag: u8,
    constructed: bool,
    value: &'a [u8],
    encoded: &'a [u8],
}

const MAX_OPAQUE_DER_DEPTH: usize = 32;

#[derive(Clone, Copy)]
enum DerValidation {
    Full,
    AllowNonstandardPrintable,
}

fn malformed_der(tag: Tag) -> Error {
    ErrorKind::Value { tag }.into()
}

fn integer_value_is_canonical(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && (bytes.len() == 1
            || !((bytes[0] == 0 && bytes[1] & 0x80 == 0)
                || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0)))
}

fn printable_string_is_valid(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
            )
    })
}

fn numeric_string_is_valid(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || *byte == b' ')
}

fn universal_constructed_bit_is_valid(identifier: u8) -> bool {
    if identifier & 0xC0 != 0 {
        return true;
    }
    match identifier & 0x1F {
        0 | 15 => false,
        8 | 11 | 16 | 17 | 29 => identifier & 0x20 != 0,
        1..=14 | 18..=28 | 30 => identifier & 0x20 == 0,
        _ => true,
    }
}

fn validate_primitive_der(
    tag: u8,
    value: &[u8],
    error_tag: Tag,
    validation: DerValidation,
) -> der::Result<()> {
    let valid = match tag {
        0x01 => value.len() == 1 && matches!(value[0], 0x00 | 0xFF),
        0x02 | 0x0A => integer_value_is_canonical(value),
        0x03 => {
            !value.is_empty()
                && value[0] <= 7
                && (value.len() > 1 || value[0] == 0)
                && (value[0] == 0 || value[value.len() - 1] & ((1u8 << value[0]) - 1) == 0)
        }
        0x05 => value.is_empty(),
        0x06 => oid_value_is_canonical(value),
        0x0C => core::str::from_utf8(value).is_ok(),
        0x12 => numeric_string_is_valid(value),
        0x13 => {
            printable_string_is_valid(value)
                || (matches!(validation, DerValidation::AllowNonstandardPrintable)
                    && value.is_ascii())
        }
        0x16 => value.is_ascii(),
        0x1C => universal_string_value_is_valid(value),
        0x1E => bmp_string_value_is_valid(value),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(malformed_der(error_tag))
    }
}

fn parse_der_tlv<'a>(input: &'a [u8], error_tag: Tag) -> der::Result<(RawDerTlv<'a>, &'a [u8])> {
    parse_der_tlv_at_depth(input, error_tag, 0, DerValidation::Full)
}

fn parse_der_tlv_at_depth<'a>(
    input: &'a [u8],
    error_tag: Tag,
    depth: usize,
    validation: DerValidation,
) -> der::Result<(RawDerTlv<'a>, &'a [u8])> {
    if depth > MAX_OPAQUE_DER_DEPTH {
        return Err(ErrorKind::Overlength.into());
    }
    let first = *input.first().ok_or_else(|| malformed_der(error_tag))?;
    if !universal_constructed_bit_is_valid(first) {
        return Err(malformed_der(error_tag));
    }

    let constructed = first & 0x20 != 0;
    let mut cursor = 1usize;
    if first & 0x1F == 0x1F {
        let first_high = *input.get(cursor).ok_or_else(|| malformed_der(error_tag))?;
        if first_high & 0x7F == 0 {
            return Err(malformed_der(error_tag));
        }
        loop {
            let byte = *input.get(cursor).ok_or_else(|| malformed_der(error_tag))?;
            cursor = cursor.checked_add(1).ok_or(ErrorKind::Overflow)?;
            if byte & 0x80 == 0 {
                if cursor == 2 && byte < 31 {
                    return Err(malformed_der(error_tag));
                }
                break;
            }
        }
    }

    let first_len = *input.get(cursor).ok_or_else(|| malformed_der(error_tag))?;
    cursor = cursor.checked_add(1).ok_or(ErrorKind::Overflow)?;
    let value_len = if first_len & 0x80 == 0 {
        usize::from(first_len)
    } else {
        let octets = usize::from(first_len & 0x7F);
        if octets == 0 || octets > core::mem::size_of::<usize>() {
            return Err(malformed_der(error_tag));
        }
        let length_end = cursor.checked_add(octets).ok_or(ErrorKind::Overflow)?;
        let length_bytes = input
            .get(cursor..length_end)
            .ok_or_else(|| malformed_der(error_tag))?;
        if length_bytes[0] == 0 {
            return Err(malformed_der(error_tag));
        }
        cursor = length_end;
        let mut length = 0usize;
        for byte in length_bytes {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(ErrorKind::Overflow)?;
        }
        if length < 128 {
            return Err(malformed_der(error_tag));
        }
        length
    };

    let end = cursor.checked_add(value_len).ok_or(ErrorKind::Overflow)?;
    let value = input
        .get(cursor..end)
        .ok_or_else(|| malformed_der(error_tag))?;
    let encoded = &input[..end];
    let rest = &input[end..];

    if constructed {
        let mut nested = value;
        let mut previous: Option<&[u8]> = None;
        while !nested.is_empty() {
            let (child, remaining) = parse_der_tlv_at_depth(
                nested,
                error_tag,
                depth.checked_add(1).ok_or(ErrorKind::Overflow)?,
                validation,
            )?;
            if first == 0x31 {
                if previous.is_some_and(|encoded| encoded > child.encoded) {
                    return Err(ErrorKind::SetOrdering.into());
                }
                previous = Some(child.encoded);
            }
            nested = remaining;
        }
    } else {
        validate_primitive_der(first, value, error_tag, validation)?;
    }

    Ok((
        RawDerTlv {
            tag: first,
            constructed,
            value,
            encoded,
        },
        rest,
    ))
}

fn single_der_tlv<'a>(bytes: &'a [u8], error_tag: Tag) -> der::Result<RawDerTlv<'a>> {
    let (tlv, rest) = parse_der_tlv(bytes, error_tag)?;
    if rest.is_empty() {
        Ok(tlv)
    } else {
        Err(malformed_der(error_tag))
    }
}

fn single_der_tlv_allowing_nonstandard_printable<'a>(
    bytes: &'a [u8],
    error_tag: Tag,
) -> der::Result<RawDerTlv<'a>> {
    let (tlv, rest) = parse_der_tlv_at_depth(
        bytes,
        error_tag,
        0,
        DerValidation::AllowNonstandardPrintable,
    )?;
    if rest.is_empty() {
        Ok(tlv)
    } else {
        Err(malformed_der(error_tag))
    }
}

fn validate_explicit_value(
    tlv: RawDerTlv<'_>,
    expected_tag: u8,
    error_tag: Tag,
) -> der::Result<()> {
    if tlv.tag != expected_tag || !tlv.constructed {
        return Err(malformed_der(error_tag));
    }
    single_der_tlv(tlv.value, error_tag).map(|_| ())
}

fn validate_other_name(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    let (oid, remaining) = parse_der_tlv(bytes, error_tag)?;
    if oid.tag != 0x06 {
        return Err(malformed_der(error_tag));
    }
    let (value, trailing) = parse_der_tlv(remaining, error_tag)?;
    if !trailing.is_empty() {
        return Err(malformed_der(error_tag));
    }
    validate_explicit_value(value, 0xA0, error_tag)
}

fn validate_directory_string(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    let value = single_der_tlv(bytes, error_tag)?;
    if value.constructed || value.value.is_empty() {
        return Err(malformed_der(error_tag));
    }

    let length = match value.tag {
        0x0C => core::str::from_utf8(value.value)
            .ok()
            .map(|string| string.chars().count()),
        0x13 if printable_string_is_valid(value.value) => Some(value.value.len()),
        0x14 => Some(value.value.len()),
        0x1C => (value.value.len() % 4 == 0
            && value.value.chunks_exact(4).all(|chunk| {
                char::from_u32(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .is_some()
            }))
        .then_some(value.value.len() / 4),
        0x1E => (value.value.len() % 2 == 0
            && value.value.chunks_exact(2).all(|chunk| {
                !matches!(
                    u16::from_be_bytes([chunk[0], chunk[1]]),
                    0xD800..=0xDFFF | 0xFFFE | 0xFFFF
                )
            }))
        .then_some(value.value.len() / 2),
        _ => None,
    };
    if length.is_some_and(|length| length <= 32768) {
        Ok(())
    } else {
        Err(malformed_der(error_tag))
    }
}

fn validate_edi_party_name(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    let (first, remaining) = parse_der_tlv(bytes, error_tag)?;
    let party = if first.tag == 0xA0 {
        validate_explicit_value(first, 0xA0, error_tag)?;
        validate_directory_string(first.value, error_tag)?;
        let (party, trailing) = parse_der_tlv(remaining, error_tag)?;
        if !trailing.is_empty() {
            return Err(malformed_der(error_tag));
        }
        party
    } else {
        if !remaining.is_empty() {
            return Err(malformed_der(error_tag));
        }
        first
    };
    validate_explicit_value(party, 0xA1, error_tag)?;
    validate_directory_string(party.value, error_tag)
}

fn validate_explicit_string_choice(
    value: RawDerTlv<'_>,
    expected_tag: u8,
    min_len: usize,
    max_len: usize,
    error_tag: Tag,
) -> der::Result<()> {
    if value.tag != expected_tag || !value.constructed {
        return Err(malformed_der(error_tag));
    }
    let string = single_der_tlv(value.value, error_tag)?;
    if !matches!(string.tag, 0x12 | 0x13)
        || !(min_len..=max_len).contains(&string.value.len())
        || (string.tag == 0x12 && !numeric_string_is_valid(string.value))
        || (string.tag == 0x13 && !printable_string_is_valid(string.value))
    {
        return Err(malformed_der(error_tag));
    }
    Ok(())
}

fn validate_personal_name(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    let mut remaining = bytes;
    let mut expected = 0x80u8;
    while !remaining.is_empty() {
        let (field, rest) = parse_der_tlv(remaining, error_tag)?;
        let max_len = match field.tag {
            0x80 => 40,
            0x81 => 16,
            0x82 => 5,
            0x83 => 3,
            _ => return Err(malformed_der(error_tag)),
        };
        if field.tag < expected
            || field.constructed
            || field.value.is_empty()
            || field.value.len() > max_len
            || !printable_string_is_valid(field.value)
        {
            return Err(malformed_der(error_tag));
        }
        if expected == 0x80 && field.tag != 0x80 {
            return Err(malformed_der(error_tag));
        }
        expected = field.tag.checked_add(1).ok_or(ErrorKind::Overflow)?;
        remaining = rest;
    }
    if expected > 0x80 {
        Ok(())
    } else {
        Err(malformed_der(error_tag))
    }
}

fn validate_organizational_unit_names(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    if bytes.is_empty() {
        return Err(malformed_der(error_tag));
    }
    let mut remaining = bytes;
    let mut count = 0usize;
    while !remaining.is_empty() {
        let (name, rest) = parse_der_tlv(remaining, error_tag)?;
        count = count.checked_add(1).ok_or(ErrorKind::Overflow)?;
        if count > 4
            || name.tag != 0x13
            || name.value.is_empty()
            || name.value.len() > 32
            || !printable_string_is_valid(name.value)
        {
            return Err(malformed_der(error_tag));
        }
        remaining = rest;
    }
    Ok(())
}

fn validate_builtin_standard_attributes(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    let mut remaining = bytes;
    let mut previous_rank = 0u8;
    while !remaining.is_empty() {
        let (field, rest) = parse_der_tlv(remaining, error_tag)?;
        let rank = match field.tag {
            0x61 => {
                validate_explicit_string_choice(field, 0x61, 2, 3, error_tag)?;
                let string = single_der_tlv(field.value, error_tag)?;
                if !matches!((string.tag, string.value.len()), (0x12, 3) | (0x13, 2)) {
                    return Err(malformed_der(error_tag));
                }
                1
            }
            0x62 => {
                validate_explicit_string_choice(field, 0x62, 0, 16, error_tag)?;
                2
            }
            0x80 => {
                if field.constructed
                    || field.value.is_empty()
                    || field.value.len() > 16
                    || !numeric_string_is_valid(field.value)
                {
                    return Err(malformed_der(error_tag));
                }
                3
            }
            0x81 => {
                if field.constructed
                    || field.value.is_empty()
                    || field.value.len() > 24
                    || !printable_string_is_valid(field.value)
                {
                    return Err(malformed_der(error_tag));
                }
                4
            }
            0xA2 => {
                validate_explicit_string_choice(field, 0xA2, 1, 16, error_tag)?;
                5
            }
            0x83 => {
                if field.constructed
                    || field.value.is_empty()
                    || field.value.len() > 64
                    || !printable_string_is_valid(field.value)
                {
                    return Err(malformed_der(error_tag));
                }
                6
            }
            0x84 => {
                if field.constructed
                    || field.value.is_empty()
                    || field.value.len() > 32
                    || !numeric_string_is_valid(field.value)
                {
                    return Err(malformed_der(error_tag));
                }
                7
            }
            0xA5 => {
                validate_personal_name(field.value, error_tag)?;
                8
            }
            0xA6 => {
                validate_organizational_unit_names(field.value, error_tag)?;
                9
            }
            _ => return Err(malformed_der(error_tag)),
        };
        if rank <= previous_rank {
            return Err(malformed_der(error_tag));
        }
        previous_rank = rank;
        remaining = rest;
    }
    Ok(())
}

fn validate_domain_defined_attributes(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    if bytes.is_empty() {
        return Err(malformed_der(error_tag));
    }
    let mut remaining = bytes;
    let mut count = 0usize;
    while !remaining.is_empty() {
        let (attribute, rest) = parse_der_tlv(remaining, error_tag)?;
        count = count.checked_add(1).ok_or(ErrorKind::Overflow)?;
        if attribute.tag != 0x30 {
            return Err(malformed_der(error_tag));
        }
        let (kind, value_bytes) = parse_der_tlv(attribute.value, error_tag)?;
        let (value, trailing) = parse_der_tlv(value_bytes, error_tag)?;
        if kind.tag != 0x13
            || value.tag != 0x13
            || kind.value.is_empty()
            || kind.value.len() > 8
            || value.value.is_empty()
            || value.value.len() > 128
            || !trailing.is_empty()
            || count > 4
        {
            return Err(malformed_der(error_tag));
        }
        remaining = rest;
    }
    Ok(())
}

fn nonnegative_integer_at_most(bytes: &[u8], maximum: usize) -> bool {
    if !integer_value_is_canonical(bytes) || bytes[0] & 0x80 != 0 {
        return false;
    }
    bytes
        .iter()
        .try_fold(0usize, |value, byte| {
            value.checked_mul(256)?.checked_add(usize::from(*byte))
        })
        .is_some_and(|value| value <= maximum)
}

fn validate_extension_attributes(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    if bytes.is_empty() {
        return Err(malformed_der(error_tag));
    }
    let mut remaining = bytes;
    let mut count = 0usize;
    while !remaining.is_empty() {
        let (attribute, rest) = parse_der_tlv(remaining, error_tag)?;
        count = count.checked_add(1).ok_or(ErrorKind::Overflow)?;
        if attribute.tag != 0x30 {
            return Err(malformed_der(error_tag));
        }
        let (kind, value_bytes) = parse_der_tlv(attribute.value, error_tag)?;
        let (value, trailing) = parse_der_tlv(value_bytes, error_tag)?;
        if kind.tag != 0x80
            || !nonnegative_integer_at_most(kind.value, 256)
            || value.tag != 0xA1
            || !trailing.is_empty()
            || count > 256
        {
            return Err(malformed_der(error_tag));
        }
        validate_explicit_value(value, 0xA1, error_tag)?;
        remaining = rest;
    }
    Ok(())
}

fn validate_x400_address(bytes: &[u8], error_tag: Tag) -> der::Result<()> {
    let (standard, mut remaining) = parse_der_tlv(bytes, error_tag)?;
    if standard.tag != 0x30 {
        return Err(malformed_der(error_tag));
    }
    validate_builtin_standard_attributes(standard.value, error_tag)?;

    if !remaining.is_empty() {
        let (optional, rest) = parse_der_tlv(remaining, error_tag)?;
        match optional.tag {
            0x30 => validate_domain_defined_attributes(optional.value, error_tag)?,
            0x31 => validate_extension_attributes(optional.value, error_tag)?,
            _ => return Err(malformed_der(error_tag)),
        }
        remaining = rest;
        if optional.tag == 0x30 && !remaining.is_empty() {
            let (extensions, rest) = parse_der_tlv(remaining, error_tag)?;
            if extensions.tag != 0x31 {
                return Err(malformed_der(error_tag));
            }
            validate_extension_attributes(extensions.value, error_tag)?;
            remaining = rest;
        }
    }

    if remaining.is_empty() {
        Ok(())
    } else {
        Err(malformed_der(error_tag))
    }
}

fn validate_opaque_general_name(number: TagNumber, bytes: &[u8], tag: Tag) -> der::Result<()> {
    match number {
        TagNumber::N0 => validate_other_name(bytes, tag),
        TagNumber::N3 => validate_x400_address(bytes, tag),
        TagNumber::N5 => validate_edi_party_name(bytes, tag),
        _ => Ok(()),
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

        let number = tag.number();
        let constructed = match number {
            TagNumber::N0 | TagNumber::N3 | TagNumber::N4 | TagNumber::N5 => true,
            TagNumber::N1 | TagNumber::N2 | TagNumber::N6 | TagNumber::N7 | TagNumber::N8 => false,
            _ => {
                return Err(ErrorKind::TagUnexpected {
                    expected: None,
                    actual: tag,
                }
                .into())
            }
        };
        let expected = Tag::ContextSpecific {
            constructed,
            number,
        };
        if tag != expected {
            return Err(ErrorKind::TagUnexpected {
                expected: Some(expected),
                actual: tag,
            }
            .into());
        }

        match number {
            TagNumber::N0 => {
                let bytes = reader.read_slice(header.length)?;
                validate_opaque_general_name(number, bytes, tag)?;
                owned_bytes(bytes).map(GeneralName::OtherName)
            }
            TagNumber::N1 => decode_ia5_string(reader, header).map(GeneralName::Rfc822Name),
            TagNumber::N2 => decode_ia5_string(reader, header).map(GeneralName::DnsName),
            TagNumber::N3 => {
                let bytes = reader.read_slice(header.length)?;
                validate_opaque_general_name(number, bytes, tag)?;
                owned_bytes(bytes).map(GeneralName::X400Address)
            }
            TagNumber::N4 => {
                let name = reader.read_nested(header.length, Name::decode)?;
                Ok(GeneralName::DirectoryName(name))
            }
            TagNumber::N5 => {
                let bytes = reader.read_slice(header.length)?;
                validate_opaque_general_name(number, bytes, tag)?;
                owned_bytes(bytes).map(GeneralName::EdiPartyName)
            }
            TagNumber::N6 => decode_ia5_string(reader, header).map(GeneralName::Uri),
            TagNumber::N7 => {
                let length = usize::try_from(header.length)?;
                if !matches!(length, 4 | 8 | 16 | 32) {
                    return Err(ErrorKind::Length { tag }.into());
                }
                let bytes = read_owned_bytes(reader, header.length)?;
                Ok(GeneralName::IpAddress(bytes))
            }
            TagNumber::N8 => {
                let bytes = reader.read_slice(header.length)?;
                if !oid_value_is_canonical(bytes) {
                    return Err(ErrorKind::OidMalformed.into());
                }
                let oid = ObjectIdentifier::from_bytes(bytes)?;
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
        self.validate_structure()?;
        match self {
            GeneralName::OtherName(bytes)
            | GeneralName::X400Address(bytes)
            | GeneralName::EdiPartyName(bytes) => bytes.len().try_into(),
            GeneralName::Rfc822Name(s) | GeneralName::DnsName(s) | GeneralName::Uri(s) => {
                s.len().try_into()
            }
            GeneralName::DirectoryName(name) => name.encoded_len(),
            GeneralName::IpAddress(bytes) => bytes.len().try_into(),
            GeneralName::RegisteredId(oid) => oid.as_bytes().len().try_into(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.validate_structure()?;
        match self {
            GeneralName::OtherName(bytes)
            | GeneralName::X400Address(bytes)
            | GeneralName::EdiPartyName(bytes) => writer.write(bytes),
            GeneralName::Rfc822Name(s) | GeneralName::DnsName(s) | GeneralName::Uri(s) => {
                writer.write(s.as_bytes())
            }
            GeneralName::DirectoryName(name) => name.encode(writer),
            GeneralName::IpAddress(bytes) => writer.write(bytes),
            GeneralName::RegisteredId(oid) => writer.write(oid.as_bytes()),
        }
    }
}

impl Tagged for GeneralName {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: matches!(
                self,
                GeneralName::OtherName(_)
                    | GeneralName::X400Address(_)
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

    fn validate_name(name: &GeneralName) -> der::Result<()> {
        name.validate_structure()?;
        if let GeneralName::IpAddress(bytes) = name {
            if !matches!(bytes.len(), 4 | 16) {
                return Err(ErrorKind::Length {
                    tag: Tag::ContextSpecific {
                        constructed: false,
                        number: TagNumber::N7,
                    },
                }
                .into());
            }
        }
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for SubjectAltName {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let mut names = Vec::new();
        reader.read_nested(header.length, |reader| {
            while !reader.is_finished() {
                names.try_reserve(1).map_err(|_| ErrorKind::Overlength)?;
                let name_header = Header::decode(reader)?;
                let name = GeneralName::decode_value(reader, name_header)?;
                Self::validate_name(&name)?;
                names.push(name);
            }
            Ok(())
        })?;
        if names.is_empty() {
            return Err(ErrorKind::Length { tag: Tag::Sequence }.into());
        }
        Ok(Self { names })
    }
}

impl EncodeValue for SubjectAltName {
    fn value_len(&self) -> der::Result<Length> {
        if self.names.is_empty() {
            return Err(ErrorKind::Length { tag: Tag::Sequence }.into());
        }
        let mut len = Length::ZERO;
        for name in &self.names {
            Self::validate_name(name)?;
            len = (len + name.encoded_len()?)?;
        }
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        if self.names.is_empty() {
            return Err(ErrorKind::Length { tag: Tag::Sequence }.into());
        }
        for name in &self.names {
            Self::validate_name(name)?;
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
    fn test_attribute_type_and_value_rejects_malformed_value_length() {
        let attr = AttributeTypeAndValue::new_utf8(CN, "Acme").unwrap();
        let mut encoded = attr.to_der().unwrap();
        let value_tag = encoded.iter().rposition(|byte| *byte == 0x0C).unwrap();
        encoded[value_tag + 1] = 3;

        assert!(AttributeTypeAndValue::from_der(&encoded).is_err());
    }

    #[test]
    fn test_attribute_type_and_value_requires_one_canonical_der_value() {
        fn attribute(value: &[u8]) -> Vec<u8> {
            let mut encoded = vec![0x30, (5 + value.len()) as u8, 0x06, 0x03, 0x55, 0x04, 0x03];
            encoded.extend_from_slice(value);
            encoded
        }

        for malformed in [
            &[0x0C, 0x01, b'a', 0x05, 0x00][..],
            &[0x0C, 0x81, 0x01, b'a'][..],
            &[0x10, 0x00][..],
            &[0x02, 0x02, 0x00, 0x01][..],
            &[0x1E, 0x01, 0x00][..],
            &[0x1E, 0x02, 0xD8, 0x00][..],
            &[0x1C, 0x04, 0x00, 0x11, 0x00, 0x00][..],
        ] {
            assert!(AttributeTypeAndValue::from_der(&attribute(malformed)).is_err());
        }

        for nonstandard in [
            &[0x13, 0x03, b'A', b'&', b'T'][..],
            &[0x13, 0x08, b'*', b'.', b'v', b'e', b'n', b'd', b'o', b'r'][..],
        ] {
            let encoded = attribute(nonstandard);
            let decoded = AttributeTypeAndValue::from_der(&encoded).unwrap();
            assert!(decoded.value_as_str().is_err());
            assert_eq!(decoded.to_der().unwrap(), encoded);
        }
    }

    #[test]
    fn test_directory_string_rejects_unprocessable_encodings() {
        assert!(DirectoryString::Utf8String(String::new()).to_der().is_err());
        assert!(DirectoryString::TeletexString(vec![0xC3, 0xA9])
            .as_str()
            .is_err());
        assert!(DirectoryString::BmpString(vec![0xD8, 0x00])
            .to_der()
            .is_err());
        assert!(
            DirectoryString::UniversalString(vec![0x00, 0x11, 0x00, 0x00])
                .to_der()
                .is_err()
        );
    }

    #[test]
    fn test_rdn_must_not_be_empty() {
        assert!(RelativeDistinguishedName::from_der(&[0x31, 0x00]).is_err());
        assert!(RelativeDistinguishedName::from_attributes(vec![]).is_err());
        assert!(RelativeDistinguishedName {
            attributes: SetOfVec::new(),
        }
        .to_der()
        .is_err());
    }

    #[test]
    fn test_rdn_requires_canonical_set_order() {
        let cn = [0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, b'a'];
        let organization = [0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x01, b'b'];
        let mut canonical = vec![0x31, 0x14];
        canonical.extend_from_slice(&cn);
        canonical.extend_from_slice(&organization);
        assert!(RelativeDistinguishedName::from_der(&canonical).is_ok());

        let mut noncanonical = vec![0x31, 0x14];
        noncanonical.extend_from_slice(&organization);
        noncanonical.extend_from_slice(&cn);
        assert!(RelativeDistinguishedName::from_der(&noncanonical).is_err());

        // SET OF ordering compares complete DER encodings, including the OID
        // length octet, rather than the semantic ordering of OID arcs.
        let short_oid = [
            0x30, 0x09, 0x06, 0x03, 0x55, 0x01, 0x01, 0x0C, 0x02, b'a', b'a',
        ];
        let long_oid = [
            0x30, 0x09, 0x06, 0x04, 0x2A, 0x03, 0x04, 0x05, 0x0C, 0x01, b'b',
        ];
        let mut canonical = vec![0x31, 0x16];
        canonical.extend_from_slice(&short_oid);
        canonical.extend_from_slice(&long_oid);
        assert!(RelativeDistinguishedName::from_der(&canonical).is_ok());

        let mut noncanonical = vec![0x31, 0x16];
        noncanonical.extend_from_slice(&long_oid);
        noncanonical.extend_from_slice(&short_oid);
        assert!(RelativeDistinguishedName::from_der(&noncanonical).is_err());
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
    fn test_registered_id_uses_implicit_general_name_encoding() {
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549");
        let san = SubjectAltName::new(vec![GeneralName::RegisteredId(oid)]);
        let der = san.to_der().unwrap();

        assert_eq!(&der[2..4], &[0x88, oid.as_bytes().len() as u8]);
        assert_eq!(&der[4..], oid.as_bytes());
        assert_eq!(SubjectAltName::from_der(&der).unwrap(), san);
    }

    #[test]
    fn test_registered_id_decode_is_scoped_to_implicit_field_length() {
        let oid = ObjectIdentifier::new_unwrap("1.2.840.113549");
        let mut content = vec![0x88, oid.as_bytes().len() as u8];
        content.extend_from_slice(oid.as_bytes());
        content.extend_from_slice(&[0x82, 0x01, b'a']);
        let mut der = vec![0x30, content.len() as u8];
        der.extend_from_slice(&content);

        assert_eq!(
            SubjectAltName::from_der(&der).unwrap(),
            SubjectAltName::new(vec![
                GeneralName::RegisteredId(oid),
                GeneralName::DnsName("a".to_string()),
            ])
        );
    }

    #[test]
    fn test_subject_alt_name_rejects_malformed_general_name_encodings() {
        for der in [
            &[0x30, 0x00][..],
            &[0x30, 0x03, 0xA2, 0x01, b'a'][..],
            &[0x30, 0x03, 0xA1, 0x01, b'a'][..],
            &[0x30, 0x03, 0xA6, 0x01, b'a'][..],
            &[0x30, 0x02, 0x84, 0x00][..],
            &[0x30, 0x03, 0x82, 0x01, 0xFF][..],
            &[0x30, 0x05, 0x88, 0x03, 0x2A, 0x80, 0x03][..],
            &[0x30, 0x07, 0x87, 0x05, 0, 0, 0, 0, 0][..],
        ] {
            assert!(SubjectAltName::from_der(der).is_err());
        }
        assert!(SubjectAltName::new(vec![]).to_der().is_err());
        assert!(GeneralName::IpAddress(vec![0; 5]).to_der().is_err());
        assert!(GeneralName::Rfc822Name("tést@example.com".to_string())
            .to_der()
            .is_err());
        assert!(GeneralName::DnsName("éxample.com".to_string())
            .to_der()
            .is_err());
        assert!(GeneralName::Uri("https://éxample.com".to_string())
            .to_der()
            .is_err());
    }

    #[test]
    fn test_opaque_general_name_structures_round_trip() {
        let valid = [
            GeneralName::OtherName(vec![0x06, 0x01, 0x2A, 0xA0, 0x02, 0x05, 0x00]),
            GeneralName::X400Address(vec![0x30, 0x00]),
            GeneralName::X400Address(vec![0x30, 0x06, 0x61, 0x04, 0x13, 0x02, b'U', b'S']),
            GeneralName::X400Address(vec![0x30, 0x03, 0x80, 0x01, b'1']),
            GeneralName::X400Address(vec![
                0x30, 0x00, 0x30, 0x08, 0x30, 0x06, 0x13, 0x01, b'a', 0x13, 0x01, b'b',
            ]),
            GeneralName::X400Address(vec![
                0x30, 0x00, 0x31, 0x09, 0x30, 0x07, 0x80, 0x01, 0x01, 0xA1, 0x02, 0x05, 0x00,
            ]),
            GeneralName::EdiPartyName(vec![0xA1, 0x07, 0x0C, 0x05, b'p', b'a', b'r', b't', b'y']),
            GeneralName::EdiPartyName(vec![
                0xA0, 0x03, 0x13, 0x01, b'a', 0xA1, 0x06, 0x1C, 0x04, 0, 0, 0, b'p',
            ]),
        ];

        for name in valid {
            let san = SubjectAltName::new(vec![name]);
            let encoded = san.to_der().unwrap();
            assert_eq!(SubjectAltName::from_der(&encoded).unwrap(), san);
        }
    }

    #[test]
    fn test_opaque_general_name_structural_der_is_enforced() {
        fn san_der(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut encoded = vec![0x30, (value.len() + 2) as u8, tag, value.len() as u8];
            encoded.extend_from_slice(value);
            encoded
        }

        let malformed = [
            (0xA0, &[][..]),
            (0xA0, &[0x06, 0x01, 0x2A][..]),
            (0xA0, &[0x06, 0x01, 0x2A, 0xA0, 0x00][..]),
            (
                0xA0,
                &[0x06, 0x01, 0x2A, 0xA0, 0x04, 0x05, 0x00, 0x05, 0x00][..],
            ),
            (0xA0, &[0x06, 0x01, 0x80, 0xA0, 0x02, 0x05, 0x00][..]),
            (0xA0, &[0x06, 0x01, 0x2A, 0xA0, 0x02, 0x10, 0x00][..]),
            (0xA0, &[0x06, 0x01, 0x2A, 0xA0, 0x02, 0x25, 0x00][..]),
            (0xA0, &[0x06, 0x01, 0x2A, 0xA0, 0x03, 0x05, 0x81, 0x00][..]),
            (0xA0, &[0x06, 0x01, 0x2A, 0xA0, 0x03, 0x1F, 0x1E, 0x00][..]),
            (0xA3, &[][..]),
            (0xA3, &[0x05, 0x00][..]),
            (0xA3, &[0x30, 0x00, 0x30, 0x00][..]),
            (0xA3, &[0x30, 0x00, 0x31, 0x00][..]),
            (0xA3, &[0x30, 0x01, 0x00][..]),
            (0xA3, &[0x30, 0x02, 0x05, 0x00][..]),
            (0xA3, &[0x30, 0x06, 0x81, 0x01, b'a', 0x80, 0x01, b'1'][..]),
            (0xA3, &[0x30, 0x02, 0xA5, 0x00][..]),
            (0xA3, &[0x30, 0x02, 0xA6, 0x00][..]),
            (
                0xA3,
                &[
                    0x30, 0x11, 0xA6, 0x0F, 0x13, 0x01, b'a', 0x13, 0x01, b'b', 0x13, 0x01, b'c',
                    0x13, 0x01, b'd', 0x13, 0x01, b'e',
                ][..],
            ),
            (
                0xA3,
                &[
                    0x30, 0x00, 0x31, 0x0A, 0x30, 0x08, 0x80, 0x02, 0x01, 0x01, 0xA1, 0x02, 0x05,
                    0x00,
                ][..],
            ),
            (0xA5, &[][..]),
            (0xA5, &[0xA0, 0x03, 0x0C, 0x01, b'a'][..]),
            (0xA5, &[0xA1, 0x00][..]),
            (0xA5, &[0x81, 0x01, b'a'][..]),
            (0xA5, &[0xA1, 0x03, 0x0C, 0x01, 0xFF][..]),
            (0xA5, &[0xA1, 0x03, 0x16, 0x01, b'a'][..]),
            (
                0xA5,
                &[0xA1, 0x03, 0x0C, 0x01, b'a', 0xA1, 0x03, 0x0C, 0x01, b'b'][..],
            ),
        ];

        for (tag, value) in malformed {
            assert!(SubjectAltName::from_der(&san_der(tag, value)).is_err());
        }

        let mut nested = vec![0x05, 0x00];
        for _ in 0..=MAX_OPAQUE_DER_DEPTH {
            let mut wrapper = vec![0xA0, nested.len() as u8];
            wrapper.extend_from_slice(&nested);
            nested = wrapper;
        }
        let mut deeply_nested_other = vec![0x06, 0x01, 0x2A, 0xA0, nested.len() as u8];
        deeply_nested_other.extend_from_slice(&nested);
        assert!(SubjectAltName::from_der(&san_der(0xA0, &deeply_nested_other)).is_err());

        for name in [
            GeneralName::OtherName(vec![]),
            GeneralName::X400Address(vec![]),
            GeneralName::EdiPartyName(vec![]),
        ] {
            assert!(name.to_der().is_err());
        }
    }

    #[test]
    fn test_subject_alt_name_rejects_name_constraint_ip_lengths() {
        for length in [8, 32] {
            let mut der = vec![0x30, (length + 2) as u8, 0x87, length as u8];
            der.resize(length + 4, 0);
            assert!(SubjectAltName::from_der(&der).is_err());
            assert!(
                SubjectAltName::new(vec![GeneralName::IpAddress(vec![0; length])])
                    .to_der()
                    .is_err()
            );
        }
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
