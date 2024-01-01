// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Writer;

use crate::{
    common::SpdmCodec,
    message::{
        SpdmErrorCode, SpdmErrorResponseExtData, SpdmErrorResponseNoneExtData,
        SpdmErrorResponsePayload, SpdmMessage, SpdmMessageHeader, SpdmMessagePayload,
        SpdmRequestResponseCode,
    },
};

use super::RequesterContext;

impl RequesterContext {
    pub fn encode_encap_error_response(
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
        let _ = error.spdm_encode(&mut self.common, writer);
    }
}
