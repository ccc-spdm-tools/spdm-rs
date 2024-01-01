// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
    ops::{ControlFlow, FromResidual, Try},
};

/// Reference: https://github.com/DMTF/libspdm/blob/main/include/library/spdm_return_status.h

#[repr(u8)]
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatusSeverity {
    SUCCESS = 0,
    ERROR = 8,
}

impl Default for StatusSeverity {
    fn default() -> Self {
        Self::ERROR
    }
}

impl TryFrom<u8> for StatusSeverity {
    type Error = ();

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SUCCESS),
            8 => Ok(Self::ERROR),
            _ => Err(()),
        }
    }
}

#[repr(u16)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatusCodeCore {
    SUCCESS = 0,
    INVALID_PARAMETER = 1,
    UNSUPPORTED_CAP = 2,
    INVALID_STATE_LOCAL = 3,
    INVALID_STATE_PEER = 4,
    INVALID_MSG_FIELD = 5,
    INVALID_MSG_SIZE = 6,
    NEGOTIATION_FAIL = 7,
    BUSY_PEER = 8,
    NOT_READY_PEER = 9,
    ERROR_PEER = 10,
    RESYNCH_PEER = 11,
    BUFFER_FULL = 12,
    BUFFER_TOO_SMALL = 13,
    SESSION_NUMBER_EXCEED = 14,
    SESSION_MSG_ERROR = 15,
    ACQUIRE_FAIL = 16,
    SESSION_TRY_DISCARD_KEY_UPDATE = 17,

    // only in Rust-SPDM
    DECODE_AEAD_FAIL = 0xFE,
}

impl TryFrom<u16> for StatusCodeCore {
    type Error = ();

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SUCCESS),
            1 => Ok(Self::INVALID_PARAMETER),
            2 => Ok(Self::UNSUPPORTED_CAP),
            3 => Ok(Self::INVALID_STATE_LOCAL),
            4 => Ok(Self::INVALID_STATE_PEER),
            5 => Ok(Self::INVALID_MSG_FIELD),
            6 => Ok(Self::INVALID_MSG_SIZE),
            7 => Ok(Self::NEGOTIATION_FAIL),
            8 => Ok(Self::BUSY_PEER),
            9 => Ok(Self::NOT_READY_PEER),
            10 => Ok(Self::ERROR_PEER),
            11 => Ok(Self::RESYNCH_PEER),
            12 => Ok(Self::BUFFER_FULL),
            13 => Ok(Self::BUFFER_TOO_SMALL),
            14 => Ok(Self::SESSION_NUMBER_EXCEED),
            15 => Ok(Self::SESSION_MSG_ERROR),
            16 => Ok(Self::ACQUIRE_FAIL),
            17 => Ok(Self::SESSION_TRY_DISCARD_KEY_UPDATE),
            0xFE => Ok(Self::DECODE_AEAD_FAIL),
            _ => Err(()),
        }
    }
}

impl Default for StatusCodeCore {
    fn default() -> Self {
        Self::INVALID_PARAMETER
    }
}

#[repr(u16)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatusCodeCrypto {
    CRYPTO_ERROR = 0,
    VERIF_FAIL = 1,
    SEQUENCE_NUMBER_OVERFLOW = 2,
    VERIF_NO_AUTHORITY = 3,
}

impl TryFrom<u16> for StatusCodeCrypto {
    type Error = ();

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CRYPTO_ERROR),
            1 => Ok(Self::VERIF_FAIL),
            2 => Ok(Self::SEQUENCE_NUMBER_OVERFLOW),
            3 => Ok(Self::VERIF_NO_AUTHORITY),
            _ => Err(()),
        }
    }
}

impl Default for StatusCodeCrypto {
    fn default() -> Self {
        Self::CRYPTO_ERROR
    }
}

#[repr(u16)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatusCodeCertParse {
    INVALID_CERT = 0,
}

impl TryFrom<u16> for StatusCodeCertParse {
    type Error = ();

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::INVALID_CERT),
            _ => Err(()),
        }
    }
}

impl Default for StatusCodeCertParse {
    fn default() -> Self {
        Self::INVALID_CERT
    }
}

#[repr(u16)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatusCodeTransport {
    SEND_FAIL = 0,
    RECEIVE_FAIL = 1,

    // only in Rust-SPDM
    DECAP_FAIL = 0xFE,
    DECAP_APP_FAIL = 0xFD,
    ENCAP_FAIL = 0xFC,
    ENCAP_APP_FAIL = 0xFB,
}

impl TryFrom<u16> for StatusCodeTransport {
    type Error = ();

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SEND_FAIL),
            1 => Ok(Self::RECEIVE_FAIL),
            0xFE => Ok(Self::DECAP_FAIL),
            0xFD => Ok(Self::DECAP_APP_FAIL),
            0xFC => Ok(Self::ENCAP_FAIL),
            0xFB => Ok(Self::ENCAP_APP_FAIL),
            _ => Err(()),
        }
    }
}

impl Default for StatusCodeTransport {
    fn default() -> Self {
        Self::SEND_FAIL
    }
}

#[repr(u16)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatusCodeMeasCollect {
    MEAS_INVALID_INDEX = 0,
    MEAS_INTERNAL_ERROR = 1,
}

impl TryFrom<u16> for StatusCodeMeasCollect {
    type Error = ();

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MEAS_INVALID_INDEX),
            1 => Ok(Self::MEAS_INTERNAL_ERROR),
            _ => Err(()),
        }
    }
}

impl Default for StatusCodeMeasCollect {
    fn default() -> Self {
        Self::MEAS_INTERNAL_ERROR
    }
}

#[repr(u16)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatusCodeRNG {
    LOW_ENTROPY = 0,
}

impl TryFrom<u16> for StatusCodeRNG {
    type Error = ();

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LOW_ENTROPY),
            _ => Err(()),
        }
    }
}

impl Default for StatusCodeRNG {
    fn default() -> Self {
        Self::LOW_ENTROPY
    }
}

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatusCode {
    SUCCESS,
    CORE(StatusCodeCore),
    CRYPTO(StatusCodeCrypto),
    CERT_PARSE(StatusCodeCertParse),
    TRANSPORT(StatusCodeTransport),
    MEAS_COLLECT(StatusCodeMeasCollect),
    RNG(StatusCodeRNG),
}

impl Default for StatusCode {
    fn default() -> Self {
        Self::CORE(StatusCodeCore::default())
    }
}

impl TryFrom<u24> for StatusCode {
    type Error = ();

    fn try_from(value: u24) -> core::result::Result<Self, Self::Error> {
        let source: u8 = ((value.get() & 0xFF_00_00) >> 16) as u8;
        let code: u16 = (value.get() & 0x00_00_FF_FF) as u16;
        match source {
            0 => Ok(StatusCode::SUCCESS),
            1 => Ok(StatusCode::CORE(StatusCodeCore::try_from(code)?)),
            2 => Ok(StatusCode::CRYPTO(StatusCodeCrypto::try_from(code)?)),
            3 => Ok(StatusCode::CERT_PARSE(StatusCodeCertParse::try_from(code)?)),
            4 => Ok(StatusCode::TRANSPORT(StatusCodeTransport::try_from(code)?)),
            5 => Ok(StatusCode::MEAS_COLLECT(StatusCodeMeasCollect::try_from(
                code,
            )?)),
            6 => Ok(StatusCode::RNG(StatusCodeRNG::try_from(code)?)),
            _ => Err(()),
        }
    }
}

impl TryInto<u24> for StatusCode {
    type Error = ();

    fn try_into(self) -> Result<u24, Self::Error> {
        match self {
            StatusCode::SUCCESS => Ok(u24::new(0)),
            StatusCode::CORE(c) => Ok(u24::new((1 << 16) as u32 + (c as u16) as u32)),
            StatusCode::CRYPTO(c) => Ok(u24::new((2 << 16) as u32 + (c as u16) as u32)),
            StatusCode::CERT_PARSE(c) => Ok(u24::new((3 << 16) as u32 + (c as u16) as u32)),
            StatusCode::TRANSPORT(t) => Ok(u24::new((4 << 16) as u32 + (t as u16) as u32)),
            StatusCode::MEAS_COLLECT(m) => Ok(u24::new((5 << 16) as u32 + (m as u16) as u32)),
            StatusCode::RNG(r) => Ok(u24::new((6 << 16) as u32 + (r as u16) as u32)),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SpdmStatus {
    pub severity: StatusSeverity,
    pub status_code: StatusCode,
}

impl Codec for SpdmStatus {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut sc = 0u32;
        sc += (((self.severity as u8) & 0x0F) as u32) << 28;
        sc += <StatusCode as TryInto<u24>>::try_into(self.status_code)
            .unwrap() //due to the design of encode, panic is allowed
            .get();
        sc.encode(bytes)?;
        Ok(4)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let sc = u32::read(r)?;
        let severity = ((sc & 0xF0_00_00_00) >> 28) as u8;
        let severity = StatusSeverity::try_from(severity).ok()?;
        if (sc & 0x0F_00_00_00) != 0 {
            return None; //the reserve field
        }
        let status_code = u24::new(sc & 0x00_FF_FF_FF);
        let status_code = StatusCode::try_from(status_code).ok()?;

        Some(Self {
            severity,
            status_code,
        })
    }
}

impl SpdmStatus {
    /// return the u32 encoding
    pub fn get_u32(&self) -> u32 {
        let mut r = [0u8; 4];
        let _ = self.encode(&mut Writer::init(&mut r));
        u32::from_le_bytes(r)
    }

    /// get SpdmStatus structure from u32 value
    pub fn from_u32(status: u32) -> Option<Self> {
        Self::read_bytes(&status.to_le_bytes())
    }

    /// Returns true if severity is StatusSeverity::SUCCESS else it returns false.
    pub fn spdm_status_is_success(&self) -> bool {
        self.severity == StatusSeverity::SUCCESS
    }

    /// Returns true if severity is StatusSeverity::ERROR else it returns false.
    pub fn spdm_status_is_error(&self) -> bool {
        self.severity == StatusSeverity::ERROR
    }
}

impl fmt::Display for SpdmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Severity: {:?}, Status: {:?}, Code: {})",
            self.severity,
            self.status_code,
            self.get_u32()
        )
    }
}

impl FromResidual<SpdmStatus> for SpdmStatus {
    fn from_residual(residual: SpdmStatus) -> Self {
        residual
    }
}

impl Try for SpdmStatus {
    type Output = ();

    type Residual = Self;

    fn from_output(_output: Self::Output) -> Self {
        SPDM_STATUS_SUCCESS
    }

    fn branch(self) -> core::ops::ControlFlow<Self::Residual, Self::Output> {
        if self == SPDM_STATUS_SUCCESS {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(self)
        }
    }
}

#[macro_export]
macro_rules! spdm_return_status {
    ($severity:expr,  $status_code:expr) => {
        SpdmStatus {
            severity: $severity,
            status_code: $status_code,
        }
    };
}

use codec::{u24, Codec, Writer};
pub use spdm_return_status;

pub const SPDM_STATUS_SUCCESS: SpdmStatus =
    spdm_return_status!(StatusSeverity::SUCCESS, StatusCode::SUCCESS);

/* - Core Errors - */

/* The function input parameter is invalid. */
pub const SPDM_STATUS_INVALID_PARAMETER: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::INVALID_STATE_LOCAL)
);

/* Unable to complete operation due to unsupported capabilities by either the caller, the peer,
 * or both. */
pub const SPDM_STATUS_UNSUPPORTED_CAP: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::UNSUPPORTED_CAP)
);

/* Unable to complete operation due to caller's state. */
pub const SPDM_STATUS_INVALID_STATE_LOCAL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::INVALID_STATE_LOCAL)
);

/* Unable to complete operation due to peer's state. */
pub const SPDM_STATUS_INVALID_STATE_PEER: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::INVALID_STATE_PEER)
);

/* The received message contains one or more invalid message fields. */
pub const SPDM_STATUS_INVALID_MSG_FIELD: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::INVALID_MSG_FIELD)
);

/* The received message's size is invalid. */
pub const SPDM_STATUS_INVALID_MSG_SIZE: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::INVALID_MSG_SIZE)
);

/* Unable to derive a common set of versions, algorithms, etc. */
pub const SPDM_STATUS_NEGOTIATION_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::NEGOTIATION_FAIL)
);

/* Received a Busy error message. */
pub const SPDM_STATUS_BUSY_PEER: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::BUSY_PEER)
);

/* Received a NotReady error message. */
pub const SPDM_STATUS_NOT_READY_PEER: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::NOT_READY_PEER)
);

/* Received an unexpected error message. */
pub const SPDM_STATUS_ERROR_PEER: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::ERROR_PEER)
);

/* Received a RequestResynch error message. */
pub const SPDM_STATUS_RESYNCH_PEER: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::RESYNCH_PEER)
);

/* Unable to append new data to buffer due to resource exhaustion. */
pub const SPDM_STATUS_BUFFER_FULL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::BUFFER_FULL)
);

/* Unable to return data because caller does not provide big enough buffer. */
pub const SPDM_STATUS_BUFFER_TOO_SMALL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::BUFFER_TOO_SMALL)
);

/* Unable to allocate more session. */
pub const SPDM_STATUS_SESSION_NUMBER_EXCEED: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::SESSION_NUMBER_EXCEED)
);

/* Decrypt error from peer. */
pub const SPDM_STATUS_SESSION_MSG_ERROR: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::SESSION_MSG_ERROR)
);

/*  Unable to acquire resource. */
pub const SPDM_STATUS_ACQUIRE_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::ACQUIRE_FAIL)
);

/*  Re-triable decrypt error from peer - must rollback to backup keys. */
pub const SPDM_STATUS_SESSION_TRY_DISCARD_KEY_UPDATE: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::SESSION_TRY_DISCARD_KEY_UPDATE)
);

/*  Failed to decode AEAD. */
pub const SPDM_STATUS_DECODE_AEAD_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CORE(StatusCodeCore::DECODE_AEAD_FAIL)
);

/* - Cryptography Errors - */

/*  Generic failure originating from the cryptography module. */
pub const SPDM_STATUS_CRYPTO_ERROR: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CRYPTO(StatusCodeCrypto::CRYPTO_ERROR)
);

/*  Verification of the provided signature digest, signature, or AEAD tag failed. */
pub const SPDM_STATUS_VERIF_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CRYPTO(StatusCodeCrypto::VERIF_FAIL)
);

/*  AEAD sequence number overflow. */
pub const SPDM_STATUS_SEQUENCE_NUMBER_OVERFLOW: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CRYPTO(StatusCodeCrypto::SEQUENCE_NUMBER_OVERFLOW)
);

/*  Provided cert is valid but is not authoritative(mismatch the root cert). */
pub const SPDM_STATUS_VERIF_NO_AUTHORITY: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CRYPTO(StatusCodeCrypto::VERIF_NO_AUTHORITY)
);

/* - Certificate Parsing Errors - */

/*  Certificate is malformed or does not comply to x.509 standard. */
pub const SPDM_STATUS_INVALID_CERT: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::CERT_PARSE(StatusCodeCertParse::INVALID_CERT)
);

/* - Transport Errors - */

/*  Unable to send message to peer. */
pub const SPDM_STATUS_SEND_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::TRANSPORT(StatusCodeTransport::SEND_FAIL)
);

/*  Unable to receive message from peer. */
pub const SPDM_STATUS_RECEIVE_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::TRANSPORT(StatusCodeTransport::RECEIVE_FAIL)
);

/*  Unable to decap transport buffer. */
pub const SPDM_STATUS_DECAP_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::TRANSPORT(StatusCodeTransport::DECAP_FAIL)
);

/*  Unable to decap app buffer. */
pub const SPDM_STATUS_DECAP_APP_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::TRANSPORT(StatusCodeTransport::DECAP_APP_FAIL)
);

/*  Unable to encap transport buffer. */
pub const SPDM_STATUS_ENCAP_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::TRANSPORT(StatusCodeTransport::ENCAP_FAIL)
);

/*  Unable to encap app buffer. */
pub const SPDM_STATUS_ENCAP_APP_FAIL: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::TRANSPORT(StatusCodeTransport::ENCAP_APP_FAIL)
);

/* - Measurement Collection Errors - */

/*  Unable to collect measurement because of invalid index. */
pub const SPDM_STATUS_MEAS_INVALID_INDEX: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::MEAS_COLLECT(StatusCodeMeasCollect::MEAS_INVALID_INDEX)
);

/*  Unable to collect measurement because of internal error. */
pub const SPDM_STATUS_MEAS_INTERNAL_ERROR: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::MEAS_COLLECT(StatusCodeMeasCollect::MEAS_INTERNAL_ERROR)
);

/* - Random Number Generation Errors - */

/*  Unable to produce random number due to lack of entropy. */
pub const SPDM_STATUS_LOW_ENTROPY: SpdmStatus = spdm_return_status!(
    StatusSeverity::ERROR,
    StatusCode::RNG(StatusCodeRNG::LOW_ENTROPY)
);

pub type SpdmResult<T = ()> = core::result::Result<T, SpdmStatus>;
