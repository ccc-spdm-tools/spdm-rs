// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::SpdmVersion;
use codec::{enum_builder, u24, Codec, Reader, Writer};

pub const ENCAPSULATED_RESPONSE_ACK_HEADER_SIZE: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct SpdmGetEncapsulatedRequestPayload {}

impl SpdmCodec for SpdmGetEncapsulatedRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetEncapsulatedRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmGetEncapsulatedRequestPayload {})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmEncapsulatedRequestPayload {
    pub request_id: u8,
}

impl SpdmCodec for SpdmEncapsulatedRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .request_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmEncapsulatedRequestPayload> {
        let request_id = u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmEncapsulatedRequestPayload { request_id })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmDeliverEncapsulatedResponsePayload {
    pub request_id: u8,
}

impl SpdmCodec for SpdmDeliverEncapsulatedResponsePayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .request_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmDeliverEncapsulatedResponsePayload> {
        let request_id = u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmDeliverEncapsulatedResponsePayload { request_id })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmEncapsulatedResponseAckPayload {
    pub request_id: u8,
    pub payload_type: SpdmEncapsulatedResponseAckPayloadType,
    pub ack_request_id: u8,
}

impl SpdmCodec for SpdmEncapsulatedResponseAckPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .request_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += self
            .payload_type
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            cnt += self
                .ack_request_id
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += u24::new(0)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved
        }

        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmEncapsulatedResponseAckPayload> {
        let request_id = u8::read(r)?; // param1
        let payload_type = SpdmEncapsulatedResponseAckPayloadType::read(r)?; // param2
        let mut ack_request_id = 0;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            ack_request_id = u8::read(r)?;
            let _ = u24::read(r)?; // reserved
        }

        Some(SpdmEncapsulatedResponseAckPayload {
            request_id,
            payload_type,
            ack_request_id,
        })
    }
}

enum_builder! {
    @U8
    EnumName: SpdmEncapsulatedResponseAckPayloadType;
    EnumVal{
        Absent => 0,
        Present => 1,
        ReqSlotNumber => 2
    }
}
impl Default for SpdmEncapsulatedResponseAckPayloadType {
    fn default() -> SpdmEncapsulatedResponseAckPayloadType {
        SpdmEncapsulatedResponseAckPayloadType::Absent
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
#[path = "encapsulated_test.rs"]
mod encapsulated_test;
