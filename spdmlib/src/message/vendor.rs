// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::config;
use crate::error::{
    SpdmResult, SpdmStatus, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_STATE_LOCAL,
};
use codec::{enum_builder, Codec, Reader, Writer};
use conquer_once::spin::OnceCell;
use zeroize::ZeroizeOnDrop;

// config::MAX_SPDM_MSG_SIZE - 7 - 2
// SPDM0274 1.2.1: Table 56, table 57 VENDOR_DEFINED_RESPONSE message format
pub const MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE: usize = config::MAX_SPDM_MSG_SIZE - 7 - 2;

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
        JEDEC => 0x08
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
    pub req_length: u16,
    pub vendor_defined_req_payload: [u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
}
impl Codec for VendorDefinedReqPayloadStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
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

    fn read(r: &mut Reader) -> Option<VendorDefinedReqPayloadStruct> {
        let req_length = u16::read(r)?;
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

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct VendorDefinedRspPayloadStruct {
    pub rsp_length: u16,
    pub vendor_defined_rsp_payload: [u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
}

impl Codec for VendorDefinedRspPayloadStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
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

    fn read(r: &mut Reader) -> Option<VendorDefinedRspPayloadStruct> {
        let rsp_length = u16::read(r)?;
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

#[derive(Debug, Clone)]
pub struct SpdmVendorDefinedRequestPayload {
    pub standard_id: RegistryOrStandardsBodyID,
    pub vendor_id: VendorIDStruct,
    pub req_payload: VendorDefinedReqPayloadStruct,
}

impl SpdmCodec for SpdmVendorDefinedRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .standard_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; //Standard ID
        cnt += self
            .vendor_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .req_payload
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVendorDefinedRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2
        let standard_id = RegistryOrStandardsBodyID::read(r)?; // Standard ID
        let vendor_id = VendorIDStruct::read(r)?;
        let req_payload = VendorDefinedReqPayloadStruct::read(r)?;

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
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .standard_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; //Standard ID
        cnt += self
            .vendor_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .rsp_payload
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVendorDefinedResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2
        let standard_id = RegistryOrStandardsBodyID::read(r)?; // Standard ID
        let vendor_id = VendorIDStruct::read(r)?;
        let rsp_payload = VendorDefinedRspPayloadStruct::read(r)?;

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
            unimplemented!()
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
