// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{u24, Codec};
use core::convert::TryFrom;
use spdmlib::message::{
    RegistryOrStandardsBodyID, VendorIDStruct, MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE,
    MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN,
};

pub const TDISP_PROTOCOL_ID: u8 = 1;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct FunctionId {
    pub requester_id: u16,
    pub requester_segment: u8,
    pub requester_segment_valid: bool,
}

impl Codec for FunctionId {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut function_id = 0u32;
        function_id |= self.requester_id as u32;
        if self.requester_segment_valid {
            function_id |= (self.requester_segment as u32) << 16;
        }
        function_id |= (self.requester_segment_valid as u32) << 24;

        function_id.encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let function_id = u32::read(r)?;

        let requester_id = (function_id & 0x0000FFFF) as u16;
        let requester_segment = ((function_id & 0x00FF0000) >> 16) as u8;
        let requester_segment_valid = function_id & (1 << 24) != 0;

        if !requester_segment_valid && requester_segment != 0 {
            return None;
        }

        Some(Self {
            requester_id,
            requester_segment,
            requester_segment_valid,
        })
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct InterfaceId {
    pub function_id: FunctionId,
}

impl Codec for InterfaceId {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.function_id.encode(bytes)?;
        cnt += 0u64.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let function_id = FunctionId::read(r)?;
        let _ = u64::read(r)?;

        Some(Self { function_id })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TdiState {
    RUN,
    ERROR,
    CONFIG_LOCKED,
    CONFIG_UNLOCKED,
}

impl From<TdiState> for u8 {
    fn from(ts: TdiState) -> Self {
        match ts {
            TdiState::RUN => 2,
            TdiState::ERROR => 3,
            TdiState::CONFIG_LOCKED => 1,
            TdiState::CONFIG_UNLOCKED => 0,
        }
    }
}

impl From<&TdiState> for u8 {
    fn from(ts: &TdiState) -> Self {
        u8::from(*ts)
    }
}

impl TryFrom<u8> for TdiState {
    type Error = ();
    fn try_from(uts: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match uts {
            0 => Ok(Self::CONFIG_UNLOCKED),
            1 => Ok(Self::CONFIG_LOCKED),
            2 => Ok(Self::RUN),
            3 => Ok(Self::ERROR),
            4_u8..=u8::MAX => Err(()),
        }
    }
}

impl Default for TdiState {
    fn default() -> Self {
        Self::CONFIG_UNLOCKED
    }
}

impl Codec for TdiState {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        u8::from(self).encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let tdi_state = u8::read(r)?;
        Self::try_from(tdi_state).ok()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TdispRequestResponseCode {
    // Request
    GET_TDISP_VERSION,
    GET_TDISP_CAPABILITIES,
    LOCK_INTERFACE_REQUEST,
    GET_DEVICE_INTERFACE_REPORT,
    GET_DEVICE_INTERFACE_STATE,
    START_INTERFACE_REQUEST,
    STOP_INTERFACE_REQUEST,
    BIND_P2P_STREAM_REQUEST,
    UNBIND_P2P_STREAM_REQUEST,
    SET_MMIO_ATTRIBUTE_REQUEST,
    VDM_REQUEST,

    // Response
    TDISP_VERSION,
    TDISP_CAPABILITIES,
    LOCK_INTERFACE_RESPONSE,
    DEVICE_INTERFACE_REPORT,
    DEVICE_INTERFACE_STATE,
    START_INTERFACE_RESPONSE,
    STOP_INTERFACE_RESPONSE,
    BIND_P2P_STREAM_RESPONSE,
    UNBIND_P2P_STREAM_RESPONSE,
    SET_MMIO_ATTRIBUTE_RESPONSE,
    VDM_RESPONSE,
    TDISP_ERROR,
}

impl From<TdispRequestResponseCode> for u8 {
    fn from(trrc: TdispRequestResponseCode) -> Self {
        match trrc {
            TdispRequestResponseCode::GET_TDISP_VERSION => 0x81,
            TdispRequestResponseCode::GET_TDISP_CAPABILITIES => 0x82,
            TdispRequestResponseCode::LOCK_INTERFACE_REQUEST => 0x83,
            TdispRequestResponseCode::GET_DEVICE_INTERFACE_REPORT => 0x84,
            TdispRequestResponseCode::GET_DEVICE_INTERFACE_STATE => 0x85,
            TdispRequestResponseCode::START_INTERFACE_REQUEST => 0x86,
            TdispRequestResponseCode::STOP_INTERFACE_REQUEST => 0x87,
            TdispRequestResponseCode::BIND_P2P_STREAM_REQUEST => 0x88,
            TdispRequestResponseCode::UNBIND_P2P_STREAM_REQUEST => 0x89,
            TdispRequestResponseCode::SET_MMIO_ATTRIBUTE_REQUEST => 0x8A,
            TdispRequestResponseCode::VDM_REQUEST => 0x8B,
            TdispRequestResponseCode::TDISP_VERSION => 0x01,
            TdispRequestResponseCode::TDISP_CAPABILITIES => 0x02,
            TdispRequestResponseCode::LOCK_INTERFACE_RESPONSE => 0x03,
            TdispRequestResponseCode::DEVICE_INTERFACE_REPORT => 0x04,
            TdispRequestResponseCode::DEVICE_INTERFACE_STATE => 0x05,
            TdispRequestResponseCode::START_INTERFACE_RESPONSE => 0x06,
            TdispRequestResponseCode::STOP_INTERFACE_RESPONSE => 0x07,
            TdispRequestResponseCode::BIND_P2P_STREAM_RESPONSE => 0x08,
            TdispRequestResponseCode::UNBIND_P2P_STREAM_RESPONSE => 0x09,
            TdispRequestResponseCode::SET_MMIO_ATTRIBUTE_RESPONSE => 0x0A,
            TdispRequestResponseCode::VDM_RESPONSE => 0x0B,
            TdispRequestResponseCode::TDISP_ERROR => 0x7F,
        }
    }
}

impl From<&TdispRequestResponseCode> for u8 {
    fn from(trrc: &TdispRequestResponseCode) -> Self {
        u8::from(*trrc)
    }
}

impl TryFrom<u8> for TdispRequestResponseCode {
    type Error = ();
    fn try_from(utrrc: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match utrrc {
            0x81 => Ok(TdispRequestResponseCode::GET_TDISP_VERSION),
            0x82 => Ok(TdispRequestResponseCode::GET_TDISP_CAPABILITIES),
            0x83 => Ok(TdispRequestResponseCode::LOCK_INTERFACE_REQUEST),
            0x84 => Ok(TdispRequestResponseCode::GET_DEVICE_INTERFACE_REPORT),
            0x85 => Ok(TdispRequestResponseCode::GET_DEVICE_INTERFACE_STATE),
            0x86 => Ok(TdispRequestResponseCode::START_INTERFACE_REQUEST),
            0x87 => Ok(TdispRequestResponseCode::STOP_INTERFACE_REQUEST),
            0x88 => Ok(TdispRequestResponseCode::BIND_P2P_STREAM_REQUEST),
            0x89 => Ok(TdispRequestResponseCode::UNBIND_P2P_STREAM_REQUEST),
            0x8A => Ok(TdispRequestResponseCode::SET_MMIO_ATTRIBUTE_REQUEST),
            0x8B => Ok(TdispRequestResponseCode::VDM_REQUEST),
            0x01 => Ok(TdispRequestResponseCode::TDISP_VERSION),
            0x02 => Ok(TdispRequestResponseCode::TDISP_CAPABILITIES),
            0x03 => Ok(TdispRequestResponseCode::LOCK_INTERFACE_RESPONSE),
            0x04 => Ok(TdispRequestResponseCode::DEVICE_INTERFACE_REPORT),
            0x05 => Ok(TdispRequestResponseCode::DEVICE_INTERFACE_STATE),
            0x06 => Ok(TdispRequestResponseCode::START_INTERFACE_RESPONSE),
            0x07 => Ok(TdispRequestResponseCode::STOP_INTERFACE_RESPONSE),
            0x08 => Ok(TdispRequestResponseCode::BIND_P2P_STREAM_RESPONSE),
            0x09 => Ok(TdispRequestResponseCode::UNBIND_P2P_STREAM_RESPONSE),
            0x0A => Ok(TdispRequestResponseCode::SET_MMIO_ATTRIBUTE_RESPONSE),
            0x0B => Ok(TdispRequestResponseCode::VDM_RESPONSE),
            0x7F => Ok(TdispRequestResponseCode::TDISP_ERROR),
            _ => Err(()),
        }
    }
}

impl Codec for TdispRequestResponseCode {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        u8::from(self).encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let req_rsp_code = u8::read(r)?;
        Self::try_from(req_rsp_code).ok()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TdispVersion {
    pub major_version: u8,
    pub minor_version: u8,
}

impl Default for TdispVersion {
    fn default() -> Self {
        Self {
            major_version: 1,
            minor_version: 0,
        }
    }
}

impl PartialOrd for TdispVersion {
    fn partial_cmp(&self, tv: &TdispVersion) -> Option<core::cmp::Ordering> {
        if self.major_version > tv.major_version {
            Some(core::cmp::Ordering::Greater)
        } else if self.major_version < tv.major_version {
            Some(core::cmp::Ordering::Less)
        } else if self.minor_version > tv.minor_version {
            Some(core::cmp::Ordering::Greater)
        } else if self.minor_version < tv.minor_version {
            Some(core::cmp::Ordering::Less)
        } else {
            Some(core::cmp::Ordering::Equal)
        }
    }
}

impl Codec for TdispVersion {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        (self.major_version << 4 | self.minor_version).encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let tdisp_version = u8::read(r)?;

        let major_version = (tdisp_version & 0xF0) >> 4;
        let minor_version = tdisp_version & 0x0F;

        Some(Self {
            major_version,
            minor_version,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TdispMessageHeader {
    pub tdisp_version: TdispVersion,
    pub message_type: TdispRequestResponseCode,
    pub interface_id: InterfaceId,
}

impl Codec for TdispMessageHeader {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += TDISP_PROTOCOL_ID.encode(bytes)?;
        cnt += self.tdisp_version.encode(bytes)?;
        cnt += self.message_type.encode(bytes)?;
        cnt += 0u16.encode(bytes)?; // reserved
        cnt += self.interface_id.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let protocol_id = u8::read(r)?;
        if protocol_id != TDISP_PROTOCOL_ID {
            return None;
        }
        let tdisp_version = TdispVersion::read(r)?;
        let message_type = TdispRequestResponseCode::read(r)?;
        u16::read(r)?; // reserved
        let interface_id = InterfaceId::read(r)?;

        Some(Self {
            tdisp_version,
            message_type,
            interface_id,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TdispErrorCode {
    INVALID_REQUEST,
    BUSY,
    INVALID_INTERFACE_STATE,
    UNSPECIFIED,
    UNSUPPORTED_REQUEST,
    VERSION_MISMATCH,
    VENDOR_SPECIFIC_ERROR,
    INVALID_INTERFACE,
    INVALID_NONCE,
    INSUFFICIENT_ENTROPY,
    INVALID_DEVICE_CONFIGURATION,
}

impl From<TdispErrorCode> for u32 {
    fn from(ec: TdispErrorCode) -> Self {
        match ec {
            TdispErrorCode::INVALID_REQUEST => 0x0001,
            TdispErrorCode::BUSY => 0x0003,
            TdispErrorCode::INVALID_INTERFACE_STATE => 0x0004,
            TdispErrorCode::UNSPECIFIED => 0x0005,
            TdispErrorCode::UNSUPPORTED_REQUEST => 0x0007,
            TdispErrorCode::VERSION_MISMATCH => 0x0041,
            TdispErrorCode::VENDOR_SPECIFIC_ERROR => 0x00FF,
            TdispErrorCode::INVALID_INTERFACE => 0x0101,
            TdispErrorCode::INVALID_NONCE => 0x0102,
            TdispErrorCode::INSUFFICIENT_ENTROPY => 0x0103,
            TdispErrorCode::INVALID_DEVICE_CONFIGURATION => 0x0104,
        }
    }
}

impl From<&TdispErrorCode> for u32 {
    fn from(ec: &TdispErrorCode) -> Self {
        u32::from(*ec)
    }
}

impl TryFrom<u32> for TdispErrorCode {
    type Error = ();
    fn try_from(uec: u32) -> Result<Self, <Self as TryFrom<u32>>::Error> {
        match uec {
            0x0001 => Ok(Self::INVALID_REQUEST),
            0x0003 => Ok(Self::BUSY),
            0x0004 => Ok(Self::INVALID_INTERFACE_STATE),
            0x0005 => Ok(Self::UNSPECIFIED),
            0x0007 => Ok(Self::UNSUPPORTED_REQUEST),
            0x0041 => Ok(Self::VERSION_MISMATCH),
            0x00FF => Ok(Self::VENDOR_SPECIFIC_ERROR),
            0x0101 => Ok(Self::INVALID_INTERFACE),
            0x0102 => Ok(Self::INVALID_NONCE),
            0x0103 => Ok(Self::INSUFFICIENT_ENTROPY),
            0x0104 => Ok(Self::INVALID_DEVICE_CONFIGURATION),
            _ => Err(()),
        }
    }
}

impl Codec for TdispErrorCode {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        u32::from(self).encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let errcode = u32::read(r)?;
        Self::try_from(errcode).ok()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqGetTdispVersion {
    pub interface_id: InterfaceId,
}

impl Codec for ReqGetTdispVersion {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        TdispMessageHeader {
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
            message_type: TdispRequestResponseCode::GET_TDISP_VERSION,
            interface_id: self.interface_id,
        }
        .encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        if message_header.tdisp_version.major_version != 1 {
            return None;
        }

        if message_header.message_type != TdispRequestResponseCode::GET_TDISP_VERSION {
            return None;
        }

        Some(Self {
            interface_id: message_header.interface_id,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RspTdispVersion {
    pub interface_id: InterfaceId,
    pub version_num_count: u8,
    pub version_num_entry: [TdispVersion; u8::MAX as usize],
}

impl Codec for RspTdispVersion {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += TdispMessageHeader {
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
            message_type: TdispRequestResponseCode::TDISP_VERSION,
            interface_id: self.interface_id,
        }
        .encode(bytes)?;
        cnt += self.version_num_count.encode(bytes)?;
        for version in self
            .version_num_entry
            .iter()
            .take(self.version_num_count as usize)
        {
            cnt += version.encode(bytes)?;
        }

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        if message_header.tdisp_version.major_version != 1 {
            return None;
        }

        if message_header.message_type != TdispRequestResponseCode::TDISP_VERSION {
            return None;
        }

        let version_num_count = u8::read(r)?;
        let mut version_num_entry = [TdispVersion::default(); u8::MAX as usize];
        for version in version_num_entry
            .iter_mut()
            .take(version_num_count as usize)
        {
            *version = TdispVersion::read(r)?;
        }

        Some(Self {
            interface_id: message_header.interface_id,
            version_num_count,
            version_num_entry,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqGetTdispCapabilities {
    pub message_header: TdispMessageHeader,
    pub tsm_caps: u32,
}

impl Codec for ReqGetTdispCapabilities {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.tsm_caps.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let tsm_caps = u32::read(r)?;

        Some(Self {
            message_header,
            tsm_caps,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct LockInterfaceFlag: u16 {
        const NO_FW_UPDATE = 0b0000_0000_0000_0001;
        const SYSTEM_CACHE_LINE_SIZE = 0b0000_0000_0000_0010;
        const LOCK_MSIX = 0b0000_0000_0000_0100;
        const BIND_P2P = 0b0000_0000_0000_1000;
        const ALL_REQUEST_REDIRECT = 0b0000_0000_0001_0000;
    }
}

impl Codec for LockInterfaceFlag {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let bits = u16::read(r)?;
        Some(Self { bits })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RspTdispCapabilities {
    pub message_header: TdispMessageHeader,
    pub dsm_caps: u32,
    pub req_msgs_supported: [u8; 16],
    pub lock_interface_flags_supported: LockInterfaceFlag,
    pub dev_addr_width: u8,
    pub num_req_this: u8,
    pub num_req_all: u8,
}

impl Codec for RspTdispCapabilities {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.dsm_caps.encode(bytes)?;
        cnt += self.req_msgs_supported.encode(bytes)?;
        cnt += self.lock_interface_flags_supported.encode(bytes)?;
        cnt += u24::new(0).encode(bytes)?; // reserved
        cnt += self.dev_addr_width.encode(bytes)?;
        cnt += self.num_req_this.encode(bytes)?;
        cnt += self.num_req_all.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let dsm_caps = u32::read(r)?;
        let req_msgs_supported = <[u8; 16]>::read(r)?;
        let lock_interface_flags_supported = LockInterfaceFlag::read(r)?;
        u24::read(r)?; // reserved
        let dev_addr_width = u8::read(r)?;
        let num_req_this = u8::read(r)?;
        let num_req_all = u8::read(r)?;

        Some(Self {
            message_header,
            dsm_caps,
            req_msgs_supported,
            lock_interface_flags_supported,
            dev_addr_width,
            num_req_this,
            num_req_all,
        })
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct ReqLockInterfaceRequest {
    pub message_header: TdispMessageHeader,
    pub flags: LockInterfaceFlag,
    pub default_stream_id: u8,
    pub mmio_reporting_offset: u64,
    pub bind_p2p_address_mask: u64,
}

impl Codec for ReqLockInterfaceRequest {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.flags.encode(bytes)?;
        cnt += self.default_stream_id.encode(bytes)?;
        cnt += 0u8.encode(bytes)?; //reserved
        cnt += self.mmio_reporting_offset.encode(bytes)?;
        cnt += self.bind_p2p_address_mask.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let flags = LockInterfaceFlag::read(r)?;
        let default_stream_id = u8::read(r)?;
        u8::read(r)?; // reserved
        let mmio_reporting_offset = u64::read(r)?;
        let bind_p2p_address_mask = u64::read(r)?;

        Some(Self {
            message_header,
            flags,
            default_stream_id,
            mmio_reporting_offset,
            bind_p2p_address_mask,
        })
    }
}

pub const START_INTERFACE_NONCE_LEN: usize = 32;

#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct RspLockInterfaceResponse {
    pub message_header: TdispMessageHeader,
    pub start_interface_nonce: [u8; START_INTERFACE_NONCE_LEN],
}

impl Codec for RspLockInterfaceResponse {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.start_interface_nonce.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let start_interface_nonce = <[u8; START_INTERFACE_NONCE_LEN]>::read(r)?;

        Some(Self {
            message_header,
            start_interface_nonce,
        })
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct ReqGetDeviceInterfaceReport {
    pub message_header: TdispMessageHeader,
    pub offset: u16,
    pub length: u16,
}

impl Codec for ReqGetDeviceInterfaceReport {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.offset.encode(bytes)?;
        cnt += self.length.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let offset = u16::read(r)?;
        let length = u16::read(r)?;

        Some(Self {
            message_header,
            offset,
            length,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct InterfaceInfo: u16 {
        const DEVICE_FIRMWARE_UPDATES_NOT_PERMITTED = 0b0000_0000_0000_0001;
        const DMA_REQUESTS_WITHOUT_PASID = 0b0000_0000_0000_0010;
        const DMA_REQUESTS_WITH_PASID = 0b0000_0000_0000_0100;
        const ATS_SUPPORTED_ENABLED = 0b0000_0000_0000_1000;
        const PRS_SUPPORTED_ENABLED = 0b0000_0000_0001_0000;
    }
}

impl Codec for InterfaceInfo {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let bits = u16::read(r)?;
        Some(Self { bits })
    }
}

pub const MAX_DEVICE_REPORT_BUFFER: usize =
    MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE - 1/*Protocol ID*/ - 16/*Header size*/ - 4;
pub const MAX_PORTION_LENGTH: usize = MAX_DEVICE_REPORT_BUFFER;

#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct RspDeviceInterfaceReport {
    pub message_header: TdispMessageHeader,
    pub portion_length: u16,
    pub remainder_length: u16,
    pub report: [u8; MAX_PORTION_LENGTH],
}

impl Codec for RspDeviceInterfaceReport {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.portion_length.encode(bytes)?;
        cnt += self.remainder_length.encode(bytes)?;
        for b in self.report.iter().take(self.portion_length as usize) {
            cnt += b.encode(bytes)?;
        }

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let portion_length = u16::read(r)?;
        let remainder_length = u16::read(r)?;
        let mut report = [0u8; MAX_PORTION_LENGTH];
        if portion_length as usize > MAX_PORTION_LENGTH {
            return None;
        }
        for rp in report.iter_mut().take(portion_length as usize) {
            *rp = u8::read(r)?;
        }

        Some(Self {
            message_header,
            portion_length,
            remainder_length,
            report,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqGetDeviceInterfaceState {
    pub message_header: TdispMessageHeader,
}

impl Codec for ReqGetDeviceInterfaceState {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.message_header.encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        Some(Self { message_header })
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct RspDeviceInterfaceState {
    pub message_header: TdispMessageHeader,
    pub tdi_state: TdiState,
}

impl Codec for RspDeviceInterfaceState {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.tdi_state.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let tdi_state = TdiState::read(r)?;

        Some(Self {
            message_header,
            tdi_state,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqStartInterfaceRequest {
    pub message_header: TdispMessageHeader,
    pub start_interface_nonce: [u8; START_INTERFACE_NONCE_LEN],
}

impl Codec for ReqStartInterfaceRequest {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.start_interface_nonce.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let start_interface_nonce = <[u8; START_INTERFACE_NONCE_LEN]>::read(r)?;

        Some(Self {
            message_header,
            start_interface_nonce,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RspStartInterfaceResponse {
    pub message_header: TdispMessageHeader,
}

impl Codec for RspStartInterfaceResponse {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.message_header.encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        Some(Self { message_header })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqStopInterfaceRequest {
    pub message_header: TdispMessageHeader,
}

impl Codec for ReqStopInterfaceRequest {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.message_header.encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        Some(Self { message_header })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RspStopInterfaceResponse {
    pub message_header: TdispMessageHeader,
}

impl Codec for RspStopInterfaceResponse {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.message_header.encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        Some(Self { message_header })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqBindP2PStreamRequest {
    pub message_header: TdispMessageHeader,
    pub p2p_stream_id: u8,
}

impl Codec for ReqBindP2PStreamRequest {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.p2p_stream_id.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let p2p_stream_id = u8::read(r)?;

        Some(Self {
            message_header,
            p2p_stream_id,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RspBindP2PStreamResponse {
    pub message_header: TdispMessageHeader,
}

impl Codec for RspBindP2PStreamResponse {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.message_header.encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        Some(Self { message_header })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqUnBindP2PStreamRequest {
    pub message_header: TdispMessageHeader,
    pub p2p_stream_id: u8,
}

impl Codec for ReqUnBindP2PStreamRequest {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.p2p_stream_id.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let p2p_stream_id = u8::read(r)?;

        Some(Self {
            message_header,
            p2p_stream_id,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RspUnBindP2PStreamResponse {
    pub message_header: TdispMessageHeader,
}

impl Codec for RspUnBindP2PStreamResponse {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.message_header.encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        Some(Self { message_header })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct MMIORangeAttribute: u16 {
        const MSI_X_TABLE = 0b0000_0000_0000_0001;
        const MSI_X_PBA = 0b0000_0000_0000_0010;
        const IS_NON_TEE_MEM = 0b0000_0000_0000_0100;
        const IS_MEM_ATTR_UPDATABLE = 0b0000_0000_0000_1000;
        const PRS_SUPPORTED_ENABLED = 0b0000_0000_0001_0000;
    }
}

impl Codec for MMIORangeAttribute {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let bits = u16::read(r)?;
        Some(Self { bits })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TdispMmioRange {
    pub first_page_with_offset_added: u64,
    pub number_of_pages: u32,
    pub range_attributes: MMIORangeAttribute,
}

impl Default for TdispMmioRange {
    fn default() -> Self {
        Self {
            first_page_with_offset_added: 0,
            number_of_pages: 0,
            range_attributes: MMIORangeAttribute::empty(),
        }
    }
}

impl Codec for TdispMmioRange {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.first_page_with_offset_added.encode(bytes)?;
        cnt += self.number_of_pages.encode(bytes)?;
        cnt += self.range_attributes.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let first_page_with_offset_added = u64::read(r)?;
        let number_of_pages = u32::read(r)?;
        let range_attributes = MMIORangeAttribute::read(r)?;

        Some(Self {
            first_page_with_offset_added,
            number_of_pages,
            range_attributes,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqSetMmioAttributeRequest {
    pub message_header: TdispMessageHeader,
    pub mmio_range: TdispMmioRange,
}

impl Codec for ReqSetMmioAttributeRequest {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.mmio_range.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        let mmio_range = TdispMmioRange::read(r)?;

        Some(Self {
            message_header,
            mmio_range,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RspSetMmioAttributeResponse {
    pub message_header: TdispMessageHeader,
}

impl Codec for RspSetMmioAttributeResponse {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        self.message_header.encode(bytes)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;

        Some(Self { message_header })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RspTdispError {
    pub message_header: TdispMessageHeader,
    pub error_code: TdispErrorCode,
    pub error_data: u32,
}

impl Codec for RspTdispError {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.message_header.encode(bytes)?;
        cnt += self.error_code.encode(bytes)?;
        cnt += self.error_data.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let message_header = TdispMessageHeader::read(r)?;
        if message_header.message_type != TdispRequestResponseCode::TDISP_ERROR {
            return None;
        }
        let error_code = TdispErrorCode::read(r)?;
        let error_data = u32::read(r)?;

        Some(Self {
            message_header,
            error_code,
            error_data,
        })
    }
}

pub const STANDARD_ID: RegistryOrStandardsBodyID = RegistryOrStandardsBodyID::PCISIG;

#[inline]
pub const fn vendor_id() -> VendorIDStruct {
    let mut vendor_idstruct = VendorIDStruct {
        len: 2,
        vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
    };

    vendor_idstruct.vendor_id[0] = 0x01;

    vendor_idstruct
}
