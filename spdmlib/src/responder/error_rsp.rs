// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::SpdmCodec;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::message::*;
use crate::responder::*;

impl ResponderContext {
    pub fn write_spdm_error(
        &mut self,
        error_code: SpdmErrorCode,
        error_data: u8,
        writer: &mut Writer,
    ) {
        let error = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseError,
            },
            payload: SpdmMessagePayload::SpdmErrorResponse(SpdmErrorResponsePayload {
                error_code,
                error_data,
                extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNone(
                    SpdmErrorResponseNoneExtData {},
                ),
            }),
        };
        writer.clear();
        let _ = error.spdm_encode(&mut self.common, writer);
    }
}

impl ResponderContext {
    pub fn handle_error_request<'a>(
        &mut self,
        error_code: SpdmErrorCode,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (_, rsp_slice) = self.write_error_response(error_code, bytes, writer);
        (Ok(()), rsp_slice)
    }

    pub fn write_error_response<'a>(
        &mut self,
        error_code: SpdmErrorCode,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            let error_data = if error_code == SpdmErrorCode::SpdmErrorUnsupportedRequest {
                message_header.request_response_code.get_u8()
            } else {
                0u8
            };
            self.write_spdm_error(error_code, error_data, writer);
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }
}
