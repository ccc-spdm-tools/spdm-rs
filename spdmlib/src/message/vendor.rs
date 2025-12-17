// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::config;
use crate::error::{
    SpdmResult, SpdmStatus, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_STATE_LOCAL,
};
use crate::message::SpdmErrorCode;
use crate::protocol::{SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion};
use crate::responder::ResponderContext;
use codec::{enum_builder, Codec, Reader, Writer};
use conquer_once::spin::OnceCell;
use zeroize::ZeroizeOnDrop;

// config::MAX_SPDM_MSG_SIZE - 7 - 6
// SPDM0274 1.4: VENDOR_DEFINED_RESPONSE message format
pub const MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE: usize = config::MAX_SPDM_MSG_SIZE - 7 - 6;

pub const MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN: usize = 0xFF;

enum_builder! {
    @U16
    EnumName: RegistryOrStandardsBodyID;
    EnumVal{
        DMTF => 0x00,
        TCG => 0x01,
        USB => 0x02,
        PCISIG => 0x03,
        IANA => 0x04,
        HDBASET => 0x05,
        MIPI => 0x06,
        CXL => 0x07,
        JEDEC => 0x08,
        VESA => 0x09,
        IANACBOR => 0x0A,
        DMTFDSP => 0x0B
    }
}

impl RegistryOrStandardsBodyID {
    pub fn get_default_vendor_id_len(&self) -> u16 {
        match self {
            RegistryOrStandardsBodyID::DMTF => 0,
            RegistryOrStandardsBodyID::TCG => 2,
            RegistryOrStandardsBodyID::USB => 2,
            RegistryOrStandardsBodyID::PCISIG => 2,
            RegistryOrStandardsBodyID::IANA => 4,
            RegistryOrStandardsBodyID::HDBASET => 4,
            RegistryOrStandardsBodyID::MIPI => 2,
            RegistryOrStandardsBodyID::CXL => 2,
            RegistryOrStandardsBodyID::JEDEC => 2,
            RegistryOrStandardsBodyID::VESA => 0,
            RegistryOrStandardsBodyID::IANACBOR => MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN as u16,
            RegistryOrStandardsBodyID::DMTFDSP => 2,
            RegistryOrStandardsBodyID::Unknown(_) => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VendorIDStruct {
    pub len: u8,
    pub vendor_id: [u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
}

impl Codec for VendorIDStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.len.encode(bytes)?;
        for d in self.vendor_id.iter().take(self.len as usize) {
            cnt += d.encode(bytes)?;
        }
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<VendorIDStruct> {
        let len = u8::read(r)?;
        let mut vendor_id = [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN];
        for d in vendor_id.iter_mut().take(len as usize) {
            *d = u8::read(r)?;
        }
        Some(VendorIDStruct { len, vendor_id })
    }

    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read(&mut rd)
    }
}

impl PartialEq for VendorIDStruct {
    fn eq(&self, vid: &VendorIDStruct) -> bool {
        if self.len != vid.len {
            false
        } else {
            self.vendor_id[..self.len as usize] == vid.vendor_id[..vid.len as usize]
        }
    }
}

impl Eq for VendorIDStruct {}

impl Default for VendorIDStruct {
    fn default() -> Self {
        Self {
            len: 0,
            vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
        }
    }
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct VendorDefinedReqPayloadStruct {
    pub req_length: u32,
    pub vendor_defined_req_payload: [u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
}
impl Codec for VendorDefinedReqPayloadStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        assert!(MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE <= u16::MAX as usize);
        let mut cnt = 0usize;
        cnt += (self.req_length as u16).encode(bytes)?;
        for d in self
            .vendor_defined_req_payload
            .iter()
            .take(self.req_length as usize)
        {
            cnt += d.encode(bytes)?;
        }
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<VendorDefinedReqPayloadStruct> {
        assert!(MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE <= u16::MAX as usize);
        let req_length = u16::read(r)? as u32;
        if req_length as usize > MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE {
            log::error!("invalid req length!!!\n");
            None
        } else {
            let mut vendor_defined_req_payload = [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
            for d in vendor_defined_req_payload
                .iter_mut()
                .take(req_length as usize)
            {
                *d = u8::read(r)?;
            }
            Some(VendorDefinedReqPayloadStruct {
                req_length,
                vendor_defined_req_payload,
            })
        }
    }
}

impl VendorDefinedReqPayloadStruct {
    fn encode_large(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += 0u16.encode(bytes)?; // req_length
        cnt += self.req_length.encode(bytes)?;
        for d in self
            .vendor_defined_req_payload
            .iter()
            .take(self.req_length as usize)
        {
            cnt += d.encode(bytes)?;
        }
        Ok(cnt)
    }

    fn read_large(r: &mut Reader) -> Option<VendorDefinedReqPayloadStruct> {
        u16::read(r)?; // req_length
        let req_length = u32::read(r)?;
        if req_length as usize > MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE {
            log::error!("invalid req length!!!\n");
            None
        } else {
            let mut vendor_defined_req_payload = [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
            for d in vendor_defined_req_payload
                .iter_mut()
                .take(req_length as usize)
            {
                *d = u8::read(r)?;
            }
            Some(VendorDefinedReqPayloadStruct {
                req_length,
                vendor_defined_req_payload,
            })
        }
    }
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct VendorDefinedRspPayloadStruct {
    pub rsp_length: u32,
    pub vendor_defined_rsp_payload: [u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
}

impl Codec for VendorDefinedRspPayloadStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        assert!(MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE <= u16::MAX as usize);
        let mut cnt = 0usize;
        cnt += (self.rsp_length as u16).encode(bytes)?;
        for d in self
            .vendor_defined_rsp_payload
            .iter()
            .take(self.rsp_length as usize)
        {
            cnt += d.encode(bytes)?;
        }
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<VendorDefinedRspPayloadStruct> {
        assert!(MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE <= u16::MAX as usize);
        let rsp_length = u16::read(r)? as u32;
        if rsp_length as usize > MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE {
            log::error!("invalid rsp length!!!\n");
            None
        } else {
            let mut vendor_defined_rsp_payload = [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
            for d in vendor_defined_rsp_payload
                .iter_mut()
                .take(rsp_length as usize)
            {
                *d = u8::read(r)?;
            }
            Some(VendorDefinedRspPayloadStruct {
                rsp_length,
                vendor_defined_rsp_payload,
            })
        }
    }
}

impl VendorDefinedRspPayloadStruct {
    fn encode_large(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += 0u16.encode(bytes)?; // rsp_length
        cnt += self.rsp_length.encode(bytes)?;
        for d in self
            .vendor_defined_rsp_payload
            .iter()
            .take(self.rsp_length as usize)
        {
            cnt += d.encode(bytes)?;
        }
        Ok(cnt)
    }

    fn read_large(r: &mut Reader) -> Option<VendorDefinedRspPayloadStruct> {
        u16::read(r)?; // rsp_length
        let rsp_length = u32::read(r)?;
        if rsp_length as usize > MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE {
            log::error!("invalid rsp length!!!\n");
            None
        } else {
            let mut vendor_defined_rsp_payload = [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
            for d in vendor_defined_rsp_payload
                .iter_mut()
                .take(rsp_length as usize)
            {
                *d = u8::read(r)?;
            }
            Some(VendorDefinedRspPayloadStruct {
                rsp_length,
                vendor_defined_rsp_payload,
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpdmVendorDefinedRequestPayload {
    pub standard_id: RegistryOrStandardsBodyID,
    pub vendor_id: VendorIDStruct,
    pub req_payload: VendorDefinedReqPayloadStruct,
}

impl SpdmCodec for SpdmVendorDefinedRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let large_payload = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
            && context
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP);
        let mut cnt = 0usize;
        let param1 = if large_payload { 0x80u8 } else { 0u8 };
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .standard_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; //Standard ID
        cnt += self
            .vendor_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        if large_payload {
            cnt += self
                .req_payload
                .encode_large(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += self
                .req_payload
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVendorDefinedRequestPayload> {
        let param1 = u8::read(r)?; // param1
        u8::read(r)?; // param2
        let large_payload = (param1 & 0x80) != 0;
        if large_payload
            && !(context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
                && context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP))
        {
            return None;
        }
        let standard_id = RegistryOrStandardsBodyID::read(r)?; // Standard ID
        let vendor_id = VendorIDStruct::read(r)?;
        let req_payload = if large_payload {
            VendorDefinedReqPayloadStruct::read_large(r)?
        } else {
            VendorDefinedReqPayloadStruct::read(r)?
        };

        Some(SpdmVendorDefinedRequestPayload {
            standard_id,
            vendor_id,
            req_payload,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SpdmVendorDefinedResponsePayload {
    pub standard_id: RegistryOrStandardsBodyID,
    pub vendor_id: VendorIDStruct,
    pub rsp_payload: VendorDefinedRspPayloadStruct,
}

impl SpdmCodec for SpdmVendorDefinedResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let large_payload = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
            && context
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP);
        let mut cnt = 0usize;
        let param1 = if large_payload { 0x80u8 } else { 0u8 };
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .standard_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; //Standard ID
        cnt += self
            .vendor_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        if large_payload {
            cnt += self
                .rsp_payload
                .encode_large(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += self
                .rsp_payload
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVendorDefinedResponsePayload> {
        let param1 = u8::read(r)?; // param1
        u8::read(r)?; // param2
        let large_payload = (param1 & 0x80) != 0;
        if large_payload
            && !(context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
                && context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP))
        {
            return None;
        }
        let standard_id = RegistryOrStandardsBodyID::read(r)?; // Standard ID
        let vendor_id = VendorIDStruct::read(r)?;
        let rsp_payload = if large_payload {
            VendorDefinedRspPayloadStruct::read_large(r)?
        } else {
            VendorDefinedRspPayloadStruct::read(r)?
        };

        Some(SpdmVendorDefinedResponsePayload {
            standard_id,
            vendor_id,
            rsp_payload,
        })
    }
}

#[derive(Clone, Copy)]
pub struct VendorDefinedStruct {
    pub vendor_defined_request_handler: fn(
        usize,
        &VendorIDStruct,
        &VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct>,
    pub vdm_handle: usize, // interpreted/managed by User
}

static VENDOR_DEFNIED: OnceCell<VendorDefinedStruct> = OnceCell::uninit();

static VENDOR_DEFNIED_DEFAULT: VendorDefinedStruct = VendorDefinedStruct {
    vendor_defined_request_handler:
        |_vdm_handle: usize,
         _vendor_id_struct: &VendorIDStruct,
         _vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct|
         -> SpdmResult<VendorDefinedRspPayloadStruct> {
            log::info!("not implement vendor defined struct!!!\n");
            Err(SPDM_STATUS_INVALID_STATE_LOCAL)
        },
    vdm_handle: 0,
};

pub fn register_vendor_defined_struct(context: VendorDefinedStruct) -> bool {
    VENDOR_DEFNIED.try_init_once(|| context).is_ok()
}

pub fn vendor_defined_request_handler(
    vendor_id_struct: &VendorIDStruct,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    if let Ok(vds) = VENDOR_DEFNIED.try_get_or_init(|| VENDOR_DEFNIED_DEFAULT) {
        (vds.vendor_defined_request_handler)(
            vds.vdm_handle,
            vendor_id_struct,
            vendor_defined_req_payload_struct,
        )
    } else {
        Err(SPDM_STATUS_INVALID_STATE_LOCAL)
    }
}

#[derive(Clone, Copy)]
#[allow(clippy::type_complexity)]
pub struct VendorDefinedStructEx {
    pub vendor_defined_request_handler_ex: for<'a> fn(
        &mut ResponderContext,
        Option<u32>,
        &[u8],
        &'a mut [u8],
    ) -> (SpdmResult, Option<&'a [u8]>),
    pub vdm_handle: usize, // interpreted/managed by User
}

pub static VENDOR_DEFNIED_EX: OnceCell<VendorDefinedStructEx> = OnceCell::uninit();

static VENDOR_DEFNIED_DEFAULT_EX: VendorDefinedStructEx = VendorDefinedStructEx {
    vendor_defined_request_handler_ex: |responder_context: &mut ResponderContext,
                                        _session_id: Option<u32>,
                                        _req_bytes: &[u8],
                                        rsp_bytes: &mut [u8]|
     -> (SpdmResult, Option<&[u8]>) {
        log::info!("not implement vendor defined struct!!!\n");
        let mut writer = Writer::init(rsp_bytes);
        responder_context.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, &mut writer);
        let used = writer.used();
        (Err(SPDM_STATUS_INVALID_MSG_FIELD), Some(&rsp_bytes[..used]))
    },
    vdm_handle: 0,
};

pub fn register_vendor_defined_struct_ex(context: VendorDefinedStructEx) -> bool {
    VENDOR_DEFNIED_EX.try_init_once(|| context).is_ok()
}

pub fn vendor_defined_request_handler_ex<'a>(
    responder_context: &mut ResponderContext,
    session_id: Option<u32>,
    req_bytes: &[u8],
    rsp_bytes: &'a mut [u8],
) -> (SpdmResult, Option<&'a [u8]>) {
    if let Ok(vds) = VENDOR_DEFNIED_EX.try_get_or_init(|| VENDOR_DEFNIED_DEFAULT_EX) {
        (vds.vendor_defined_request_handler_ex)(responder_context, session_id, req_bytes, rsp_bytes)
    } else {
        (Err(SPDM_STATUS_INVALID_STATE_LOCAL), None)
    }
}
