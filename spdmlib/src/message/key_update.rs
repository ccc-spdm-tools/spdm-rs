// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use codec::enum_builder;
use codec::{Codec, Reader, Writer};

enum_builder! {
    @U8
    EnumName: SpdmKeyUpdateOperation;
    EnumVal{
        SpdmUpdateSingleKey => 0x1,
        SpdmUpdateAllKeys => 0x2,
        SpdmVerifyNewKey => 0x3
    }
}
impl Default for SpdmKeyUpdateOperation {
    fn default() -> SpdmKeyUpdateOperation {
        SpdmKeyUpdateOperation::Unknown(0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmKeyUpdateRequestPayload {
    pub key_update_operation: SpdmKeyUpdateOperation,
    pub tag: u8,
}

impl SpdmCodec for SpdmKeyUpdateRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .key_update_operation
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += self
            .tag
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmKeyUpdateRequestPayload> {
        let key_update_operation = SpdmKeyUpdateOperation::read(r)?; // param1
        let tag = u8::read(r)?; // param2

        match key_update_operation {
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey
            | SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            | SpdmKeyUpdateOperation::SpdmVerifyNewKey => {}
            _ => return None,
        }

        Some(SpdmKeyUpdateRequestPayload {
            key_update_operation,
            tag,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmKeyUpdateResponsePayload {
    pub key_update_operation: SpdmKeyUpdateOperation,
    pub tag: u8,
}

impl SpdmCodec for SpdmKeyUpdateResponsePayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .key_update_operation
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += self
            .tag
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmKeyUpdateResponsePayload> {
        let key_update_operation = SpdmKeyUpdateOperation::read(r)?; // param1
        let tag = u8::read(r)?; // param2

        match key_update_operation {
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey
            | SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            | SpdmKeyUpdateOperation::SpdmVerifyNewKey => {}
            _ => return None,
        }

        Some(SpdmKeyUpdateResponsePayload {
            key_update_operation,
            tag,
        })
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
    fn test_case0_spdm_key_update_request_payload() {
        let u8_slice = &mut [0u8; 2];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyUpdateRequestPayload {
            key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
            tag: 100u8,
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(2, reader.left());
        let key_request_payload =
            SpdmKeyUpdateRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            key_request_payload.key_update_operation,
            SpdmKeyUpdateOperation::SpdmUpdateAllKeys
        );
        assert_eq!(key_request_payload.tag, 100);
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_key_update_response_payload() {
        let u8_slice = &mut [0u8; 2];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyUpdateResponsePayload {
            key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
            tag: 100u8,
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(2, reader.left());
        let key_response_payload =
            SpdmKeyUpdateResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            key_response_payload.key_update_operation,
            SpdmKeyUpdateOperation::SpdmUpdateAllKeys
        );
        assert_eq!(key_response_payload.tag, 100);
        assert_eq!(0, reader.left());
    }
}

#[cfg(test)]
#[path = "key_update_test.rs"]
mod key_update_test;
