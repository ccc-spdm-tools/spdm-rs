// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::spdm_codec::SpdmCodec;
use crate::common::{self};
use crate::config;
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
pub struct SpdmRespondIfReadyRequestPayload {}

impl SpdmCodec for SpdmRespondIfReadyRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(2)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmRespondIfReadyRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmRespondIfReadyRequestPayload {})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmRespondIfReadyRespondPayload {}

impl SpdmCodec for SpdmRespondIfReadyRespondPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(2)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmRespondIfReadyRespondPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmRespondIfReadyRespondPayload {})
    }
}

#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub receive_buffer: [u8; config::MAX_SPDM_MSG_SIZE],
    pub used: usize,
}
