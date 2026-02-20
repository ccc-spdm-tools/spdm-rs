// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Time utilities for X.509 certificate validation.
//!
//! This module provides types and functions for handling certificate validity periods,
//! including support for both UTCTime and GeneralizedTime formats as defined in RFC 5280.
//!
//! # UTCTime Y2K Conversion
//!
//! UTCTime values are interpreted according to RFC 5280:
//! - Years 50-99 are interpreted as 1950-1999
//! - Years 00-49 are interpreted as 2000-2049

use core::cmp::Ordering;
use der::{
    asn1::{GeneralizedTime, UtcTime},
    Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Result, Tag, Writer,
};

/// A timestamp that can be either UTCTime or GeneralizedTime.
///
/// RFC 5280 mandates:
/// - UTCTime for dates through 2049
/// - GeneralizedTime for dates in 2050 or later
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Time {
    /// UTCTime format (YYMMDDHHMMSSZ)
    UtcTime(UtcTime),
    /// GeneralizedTime format (YYYYMMDDHHMMSSZ)
    GeneralizedTime(GeneralizedTime),
}

impl Time {
    /// Creates a new Time from a UtcTime.
    pub const fn new_utc(utc_time: UtcTime) -> Self {
        Time::UtcTime(utc_time)
    }

    /// Creates a new Time from a GeneralizedTime.
    pub const fn new_generalized(generalized_time: GeneralizedTime) -> Self {
        Time::GeneralizedTime(generalized_time)
    }

    /// Returns the DateTime representation.
    pub fn to_unix_duration(&self) -> der::DateTime {
        match self {
            Time::UtcTime(utc) => utc.to_date_time(),
            Time::GeneralizedTime(gen) => gen.to_date_time(),
        }
    }

    /// Checks if this time is before another time.
    pub fn is_before(&self, other: &Time) -> bool {
        let self_dt = self.to_unix_duration();
        let other_dt = other.to_unix_duration();
        self_dt.unix_duration() < other_dt.unix_duration()
    }

    /// Checks if this time is after another time.
    pub fn is_after(&self, other: &Time) -> bool {
        let self_dt = self.to_unix_duration();
        let other_dt = other.to_unix_duration();
        self_dt.unix_duration() > other_dt.unix_duration()
    }

    /// Checks if this time is before or equal to another time.
    pub fn is_before_or_equal(&self, other: &Time) -> bool {
        let self_dt = self.to_unix_duration();
        let other_dt = other.to_unix_duration();
        self_dt.unix_duration() <= other_dt.unix_duration()
    }

    /// Checks if this time is after or equal to another time.
    pub fn is_after_or_equal(&self, other: &Time) -> bool {
        let self_dt = self.to_unix_duration();
        let other_dt = other.to_unix_duration();
        self_dt.unix_duration() >= other_dt.unix_duration()
    }
}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Time {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_dt = self.to_unix_duration();
        let other_dt = other.to_unix_duration();
        self_dt.unix_duration().cmp(&other_dt.unix_duration())
    }
}

impl<'a> DecodeValue<'a> for Time {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        match header.tag {
            Tag::UtcTime => Ok(Time::UtcTime(UtcTime::decode_value(reader, header)?)),
            Tag::GeneralizedTime => Ok(Time::GeneralizedTime(GeneralizedTime::decode_value(
                reader, header,
            )?)),
            tag => Err(der::Error::from(der::ErrorKind::TagUnexpected {
                expected: Some(Tag::UtcTime),
                actual: tag,
            })),
        }
    }
}

impl EncodeValue for Time {
    fn value_len(&self) -> Result<Length> {
        match self {
            Time::UtcTime(utc) => utc.value_len(),
            Time::GeneralizedTime(gen) => gen.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Time::UtcTime(utc) => utc.encode_value(writer),
            Time::GeneralizedTime(gen) => gen.encode_value(writer),
        }
    }
}

impl Encode for Time {
    fn encoded_len(&self) -> Result<Length> {
        match self {
            Time::UtcTime(utc) => utc.encoded_len(),
            Time::GeneralizedTime(gen) => gen.encoded_len(),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Time::UtcTime(utc) => utc.encode(writer),
            Time::GeneralizedTime(gen) => gen.encode(writer),
        }
    }
}

impl<'a> Decode<'a> for Time {
    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self> {
        let header = Header::decode(reader)?;
        Self::decode_value(reader, header)
    }
}

/// Certificate validity period.
///
/// As defined in RFC 5280 Section 4.1.2.5:
/// ```text
/// Validity ::= SEQUENCE {
///     notBefore      Time,
///     notAfter       Time
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// The time before which the certificate is not valid.
    pub not_before: Time,
    /// The time after which the certificate is not valid.
    pub not_after: Time,
}

impl Validity {
    /// Creates a new Validity period.
    pub const fn new(not_before: Time, not_after: Time) -> Self {
        Validity {
            not_before,
            not_after,
        }
    }

    /// Checks if the certificate is valid at the given time.
    pub fn is_valid_at(&self, check_time: &Time) -> bool {
        self.not_before.is_before_or_equal(check_time)
            && self.not_after.is_after_or_equal(check_time)
    }

    /// Checks if the validity period is well-formed.
    pub fn is_well_formed(&self) -> bool {
        self.not_before.is_before_or_equal(&self.not_after)
    }
}

impl<'a> DecodeValue<'a> for Validity {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        header.tag.assert_eq(Tag::Sequence)?;
        reader.read_nested(header.length, |reader| {
            let not_before = Time::decode(reader)?;
            let not_after = Time::decode(reader)?;
            Ok(Validity {
                not_before,
                not_after,
            })
        })
    }
}

impl EncodeValue for Validity {
    fn value_len(&self) -> Result<Length> {
        self.not_before.encoded_len()? + self.not_after.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        self.not_before.encode(writer)?;
        self.not_after.encode(writer)?;
        Ok(())
    }
}

impl der::Sequence<'_> for Validity {}

/// Checks if a validity period is valid at the specified time.
pub fn is_valid_at(validity: &Validity, check_time: &Time) -> bool {
    validity.is_valid_at(check_time)
}

/// Gets current time as X.509 Time.
pub fn current_time() -> Result<Time> {
    #[cfg(feature = "std")]
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| der::Error::from(der::ErrorKind::DateTime))?;
        let now_dt = der::DateTime::from_unix_duration(now)?;
        let gen_time = GeneralizedTime::from_date_time(now_dt);
        Ok(Time::GeneralizedTime(gen_time))
    }

    // no_std firmware targets: use RTC-backed sys_time provider.
    #[cfg(any(target_os = "none", target_os = "uefi"))]
    {
        let unix_ts =
            sys_time::get_sys_time().ok_or_else(|| der::Error::from(der::ErrorKind::DateTime))?;
        if unix_ts < 0 {
            return Err(der::Error::from(der::ErrorKind::DateTime));
        }

        let now_dt =
            der::DateTime::from_unix_duration(core::time::Duration::from_secs(unix_ts as u64))?;
        let gen_time = GeneralizedTime::from_date_time(now_dt);
        Ok(Time::GeneralizedTime(gen_time))
    }

    #[cfg(all(not(feature = "std"), not(any(target_os = "none", target_os = "uefi"))))]
    {
        Err(der::Error::from(der::ErrorKind::DateTime))
    }
}

/// Checks if a validity period is currently valid.
pub fn is_currently_valid(validity: &Validity) -> Result<bool> {
    let now = current_time()?;
    Ok(validity.is_valid_at(&now))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_comparison() {
        use der::asn1::UtcTime;

        let earlier = Time::UtcTime(
            UtcTime::from_unix_duration(
                der::DateTime::from_unix_duration(core::time::Duration::from_secs(0))
                    .unwrap()
                    .unix_duration(),
            )
            .unwrap(),
        );
        let later = Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(86400)).unwrap(),
        );

        assert!(earlier.is_before(&later));
        assert!(later.is_after(&earlier));
        assert!(earlier.is_before_or_equal(&later));
        assert!(later.is_after_or_equal(&earlier));
    }

    #[test]
    fn test_validity_well_formed() {
        use der::asn1::UtcTime;

        let earlier =
            Time::UtcTime(UtcTime::from_unix_duration(core::time::Duration::from_secs(0)).unwrap());
        let later = Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(86400)).unwrap(),
        );

        let validity = Validity::new(earlier, later);
        assert!(validity.is_well_formed());

        let invalid_validity = Validity::new(later, earlier);
        assert!(!invalid_validity.is_well_formed());
    }

    #[test]
    fn test_validity_checking() {
        use der::asn1::UtcTime;

        let not_before = Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(1000)).unwrap(),
        );
        let not_after = Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(2000)).unwrap(),
        );
        let validity = Validity::new(not_before, not_after);

        let before = Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(500)).unwrap(),
        );
        assert!(!validity.is_valid_at(&before));

        let within = Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(1500)).unwrap(),
        );
        assert!(validity.is_valid_at(&within));

        let after = Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(2500)).unwrap(),
        );
        assert!(!validity.is_valid_at(&after));
    }

    #[test]
    fn test_time_ord() {
        use der::asn1::UtcTime;

        let time1 =
            Time::UtcTime(UtcTime::from_unix_duration(core::time::Duration::from_secs(0)).unwrap());
        let time2 = Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(100)).unwrap(),
        );

        assert_eq!(time1.cmp(&time2), Ordering::Less);
        assert_eq!(time2.cmp(&time1), Ordering::Greater);
        assert_eq!(time1.cmp(&time1), Ordering::Equal);
    }
}
