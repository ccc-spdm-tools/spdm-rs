// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::spdm_codec::SpdmCodec;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::{common, error::SpdmStatus};
use codec::{Codec, Reader, Writer};

bitflags! {
    #[derive(Default)]
    pub struct SpdmEndSessionRequestAttributes: u8 {
        const PRESERVE_NEGOTIATED_STATE = 0b00000001;
    }
}

impl Codec for SpdmEndSessionRequestAttributes {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmEndSessionRequestAttributes> {
        let bits = u8::read(r)?;

        SpdmEndSessionRequestAttributes::from_bits(bits)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpdmEndSessionRequestPayload {
    pub end_session_request_attributes: SpdmEndSessionRequestAttributes,
}

impl SpdmCodec for SpdmEndSessionRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .end_session_request_attributes
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmEndSessionRequestPayload> {
        let end_session_request_attributes = SpdmEndSessionRequestAttributes::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmEndSessionRequestPayload {
            end_session_request_attributes,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmEndSessionResponsePayload {}

impl SpdmCodec for SpdmEndSessionResponsePayload {
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
    ) -> Option<SpdmEndSessionResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmEndSessionResponsePayload {})
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
    fn test_case0_spdm_end_session_request_attributes() {
        let u8_slice = &mut [0u8; 1];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmEndSessionRequestAttributes::all();
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(
            SpdmEndSessionRequestAttributes::read(&mut reader).unwrap(),
            SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_end_session_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmEndSessionRequestPayload {
            end_session_request_attributes:
                SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE,
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_end_session_request_payload =
            SpdmEndSessionRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            spdm_end_session_request_payload.end_session_request_attributes,
            SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE
        );
        assert_eq!(10, reader.left());
    }
    #[test]
    fn test_case0_spdm_end_session_response_payload() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmEndSessionResponsePayload {};

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        SpdmEndSessionResponsePayload::spdm_read(&mut context, &mut reader);
    }
}

#[cfg(test)]
#[path = "end_session_test.rs"]
mod end_session_test;
