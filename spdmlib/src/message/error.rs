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
    EnumName: SpdmErrorCode;
    EnumVal{
        SpdmErrorInvalidRequest => 0x1,
        SpdmErrorBusy => 0x3,
        SpdmErrorUnexpectedRequest => 0x4,
        SpdmErrorUnspecified => 0x5,
        SpdmErrorDecryptError => 0x6,
        SpdmErrorUnsupportedRequest => 0x7,
        SpdmErrorRequestInFlight => 0x8,
        SpdmErrorInvalidResponseCode => 0x9,
        SpdmErrorSessionLimitExceeded => 0xA,
        SpdmErrorSessionRequired => 0xB,
        SpdmErrorResetRequired => 0xC,
        SpdmErrorResponseTooLarge => 0xD,
        SpdmErrorRequestTooLarge => 0xE,
        SpdmErrorLargeResponse => 0xF,
        SpdmErrorMessageLost => 0x10,
        SpdmErrorVersionMismatch => 0x41,
        SpdmErrorResponseNotReady => 0x42,
        SpdmErrorRequestResynch => 0x43,
        SpdmErrorVendorDefined => 0xFF
    }
}
impl Default for SpdmErrorCode {
    fn default() -> SpdmErrorCode {
        SpdmErrorCode::Unknown(0)
    }
}

pub const SPDM_ERROR_VENDOR_EXT_DATA_SIZE: usize = 32;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpdmErrorResponseNoneExtData {}

impl SpdmCodec for SpdmErrorResponseNoneExtData {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        _bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        Ok(0)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        _r: &mut Reader,
    ) -> Option<SpdmErrorResponseNoneExtData> {
        Some(SpdmErrorResponseNoneExtData {})
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpdmErrorResponseNotReadyExtData {
    pub rdt_exponent: u8,
    pub request_code: u8,
    pub token: u8,
    pub rdtm: u8,
}

impl Codec for SpdmErrorResponseNotReadyExtData {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.rdt_exponent.encode(bytes)?;
        cnt += self.request_code.encode(bytes)?;
        cnt += self.token.encode(bytes)?;
        cnt += self.rdtm.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<SpdmErrorResponseNotReadyExtData> {
        let rdt_exponent = u8::read(r)?;
        let request_code = u8::read(r)?;
        let token = u8::read(r)?;
        let rdtm = u8::read(r)?;
        Some(SpdmErrorResponseNotReadyExtData {
            rdt_exponent,
            request_code,
            token,
            rdtm,
        })
    }
}

impl SpdmCodec for SpdmErrorResponseNotReadyExtData {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .rdt_exponent
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .request_code
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .token
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .rdtm
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmErrorResponseNotReadyExtData> {
        let rdt_exponent = u8::read(r)?;
        let request_code = u8::read(r)?;
        let token = u8::read(r)?;
        let rdtm = u8::read(r)?;

        Some(SpdmErrorResponseNotReadyExtData {
            rdt_exponent,
            request_code,
            token,
            rdtm,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpdmErrorResponseVendorExtData {
    pub data_size: u8,
    pub data: [u8; 32],
}

impl SpdmCodec for SpdmErrorResponseVendorExtData {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(self.data_size as usize)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmErrorResponseVendorExtData> {
        let mut data_size = 0;
        let mut data = [0u8; 32];

        for d in &mut data {
            let result = u8::read(r);
            match result {
                Some(v) => {
                    *d = v;
                    data_size += 1;
                }
                None => {
                    break;
                }
            }
        }

        Some(SpdmErrorResponseVendorExtData { data_size, data })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpdmErrorResponseExtData {
    SpdmErrorExtDataNone(SpdmErrorResponseNoneExtData),
    SpdmErrorExtDataNotReady(SpdmErrorResponseNotReadyExtData),
    SpdmErrorExtDataVendorDefined(SpdmErrorResponseVendorExtData),
}
impl Default for SpdmErrorResponseExtData {
    fn default() -> SpdmErrorResponseExtData {
        SpdmErrorResponseExtData::SpdmErrorExtDataNone(SpdmErrorResponseNoneExtData {})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmErrorResponsePayload {
    pub error_code: SpdmErrorCode,
    pub error_data: u8,
    pub extended_data: SpdmErrorResponseExtData,
}

impl SpdmCodec for SpdmErrorResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .error_code
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += self
            .error_data
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        match &self.extended_data {
            SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(extended_data) => {
                cnt += extended_data.spdm_encode(context, bytes)?;
            }
            SpdmErrorResponseExtData::SpdmErrorExtDataVendorDefined(extended_data) => {
                cnt += extended_data.spdm_encode(context, bytes)?;
            }
            SpdmErrorResponseExtData::SpdmErrorExtDataNone(extended_data) => {
                cnt += extended_data.spdm_encode(context, bytes)?;
            }
        }

        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmErrorResponsePayload> {
        let error_code = SpdmErrorCode::read(r)?; // param1
        let error_data = u8::read(r)?; // param2

        let extended_data = match error_code {
            SpdmErrorCode::SpdmErrorResponseNotReady => {
                Some(SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(
                    SpdmErrorResponseNotReadyExtData::spdm_read(context, r)?,
                ))
            }
            SpdmErrorCode::SpdmErrorVendorDefined => {
                Some(SpdmErrorResponseExtData::SpdmErrorExtDataVendorDefined(
                    SpdmErrorResponseVendorExtData::spdm_read(context, r)?,
                ))
            }
            _ => Some(SpdmErrorResponseExtData::SpdmErrorExtDataNone(
                SpdmErrorResponseNoneExtData::spdm_read(context, r)?,
            )),
        };

        let extended_data = extended_data?;

        Some(SpdmErrorResponsePayload {
            error_code,
            error_data,
            extended_data,
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
    fn test_case0_spdm_error_response_not_ready_ext_data() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);

        let value = SpdmErrorResponseNotReadyExtData {
            rdt_exponent: 0xaa,
            request_code: 0xaa,
            token: 0x55,
            rdtm: 0x55,
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let spdm_error_response_not_ready_ext_data =
            SpdmErrorResponseNotReadyExtData::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_error_response_not_ready_ext_data.rdt_exponent, 0xaa);
        assert_eq!(spdm_error_response_not_ready_ext_data.request_code, 0xaa);
        assert_eq!(spdm_error_response_not_ready_ext_data.token, 0x55);
        assert_eq!(spdm_error_response_not_ready_ext_data.rdtm, 0x55);
        assert_eq!(4, reader.left());
    }
    #[test]
    fn test_case0_spdm_error_response_vendor_ext_data() {
        let u8_slice = &mut [0u8; SPDM_ERROR_VENDOR_EXT_DATA_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmErrorResponseVendorExtData {
            data_size: SPDM_ERROR_VENDOR_EXT_DATA_SIZE as u8,
            data: [100u8; SPDM_ERROR_VENDOR_EXT_DATA_SIZE],
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(SPDM_ERROR_VENDOR_EXT_DATA_SIZE, reader.left());
        let response_vendor_ext_data =
            SpdmErrorResponseVendorExtData::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(response_vendor_ext_data.data_size, 32);
        for i in 0..SPDM_ERROR_VENDOR_EXT_DATA_SIZE {
            assert_eq!(response_vendor_ext_data.data[i], 100u8);
        }
    }
    #[test]
    fn test_case1_spdm_error_response_vendor_ext_data() {
        let u8_slice = &mut [0u8; SPDM_ERROR_VENDOR_EXT_DATA_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmErrorResponseVendorExtData::default();

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(SPDM_ERROR_VENDOR_EXT_DATA_SIZE, reader.left());
        let response_vendor_ext_data =
            SpdmErrorResponseVendorExtData::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            response_vendor_ext_data.data_size,
            SPDM_ERROR_VENDOR_EXT_DATA_SIZE as u8
        );
        for i in 0..SPDM_ERROR_VENDOR_EXT_DATA_SIZE {
            assert_eq!(response_vendor_ext_data.data[i], 0);
        }
    }
    #[test]
    fn test_case0_spdm_error_response_payload() {
        let value = SpdmErrorResponsePayload {
            error_code: SpdmErrorCode::SpdmErrorResponseNotReady,
            error_data: 100,
            extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(
                SpdmErrorResponseNotReadyExtData {
                    rdt_exponent: 0x11,
                    request_code: 0x22,
                    token: 0x33,
                    rdtm: 0x44,
                },
            ),
        };

        create_spdm_context!(context);

        let mut spdm_error_response_payload = new_spdm_response(value, &mut context);

        assert_eq!(
            spdm_error_response_payload.error_code,
            SpdmErrorCode::SpdmErrorResponseNotReady
        );
        assert_eq!(spdm_error_response_payload.error_data, 100);
        if let SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(extended_data) =
            &spdm_error_response_payload.extended_data
        {
            assert_eq!(extended_data.rdt_exponent, 0x11);
            assert_eq!(extended_data.request_code, 0x22);
            assert_eq!(extended_data.token, 0x33);
            assert_eq!(extended_data.rdtm, 0x44);
        }

        let mut value = SpdmErrorResponsePayload {
            error_code: SpdmErrorCode::SpdmErrorVendorDefined,
            error_data: 100,
            extended_data: SpdmErrorResponseExtData::default(),
        };
        value.extended_data = SpdmErrorResponseExtData::SpdmErrorExtDataVendorDefined(
            SpdmErrorResponseVendorExtData {
                data_size: 32,
                data: [100u8; 32],
            },
        );
        spdm_error_response_payload = new_spdm_response(value, &mut context);

        if let SpdmErrorResponseExtData::SpdmErrorExtDataVendorDefined(extended_data) =
            &spdm_error_response_payload.extended_data
        {
            assert_eq!(
                extended_data.data_size,
                SPDM_ERROR_VENDOR_EXT_DATA_SIZE as u8
            );
            for i in 0..SPDM_ERROR_VENDOR_EXT_DATA_SIZE {
                assert_eq!(extended_data.data[i], 100u8);
            }
        }

        let mut value = SpdmErrorResponsePayload {
            error_code: SpdmErrorCode::SpdmErrorInvalidRequest,
            error_data: 100,
            extended_data: SpdmErrorResponseExtData::default(),
        };
        value.extended_data =
            SpdmErrorResponseExtData::SpdmErrorExtDataNone(SpdmErrorResponseNoneExtData {});
        new_spdm_response(value, &mut context);
    }

    fn new_spdm_response(
        value: SpdmErrorResponsePayload,
        context: &mut common::SpdmContext,
    ) -> SpdmErrorResponsePayload {
        let u8_slice = &mut [0u8; 4 + SPDM_ERROR_VENDOR_EXT_DATA_SIZE];
        let mut writer = Writer::init(u8_slice);
        assert!(value.spdm_encode(context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);

        SpdmErrorResponsePayload::spdm_read(context, &mut reader).unwrap()
    }
}
