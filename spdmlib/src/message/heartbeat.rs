// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::spdm_codec::SpdmCodec;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::{common, error::SpdmStatus};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
pub struct SpdmHeartbeatRequestPayload {}

impl SpdmCodec for SpdmHeartbeatRequestPayload {
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
    ) -> Option<SpdmHeartbeatRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmHeartbeatRequestPayload {})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmHeartbeatResponsePayload {}

impl SpdmCodec for SpdmHeartbeatResponsePayload {
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
    ) -> Option<SpdmHeartbeatResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmHeartbeatResponsePayload {})
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};
    extern crate alloc;

    #[test]
    fn test_case0_spdm_heartbeat_response_payload() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmHeartbeatResponsePayload {};

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        SpdmHeartbeatResponsePayload::spdm_read(&mut context, &mut reader);
    }
    #[test]
    fn test_case0_spdm_heartbeat_request_payload() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmHeartbeatRequestPayload {};

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        SpdmHeartbeatRequestPayload::spdm_read(&mut context, &mut reader);
    }
}

#[cfg(test)]
#[path = "heartbeat_test.rs"]
mod heartbeat_test;
