// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::SpdmCodec;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::message::*;
use crate::responder::*;

impl ResponderContext {
    pub fn handle_spdm_vendor_defined_request<'a>(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (_, rsp_slice) = self.write_spdm_vendor_defined_response(session_id, bytes, writer);
        (Ok(()), rsp_slice)
    }

    pub fn write_spdm_vendor_defined_response<'a>(
        &mut self,
        session_id: Option<u32>,
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
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
            session_id,
        );

        let vendor_defined_request_payload =
            SpdmVendorDefinedRequestPayload::spdm_read(&mut self.common, &mut reader);
        if vendor_defined_request_payload.is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }
        let vendor_defined_request_payload = vendor_defined_request_payload.unwrap();

        let standard_id = vendor_defined_request_payload.standard_id;
        let vendor_id = vendor_defined_request_payload.vendor_id;
        let req_payload = vendor_defined_request_payload.req_payload;
        let rsp_payload = self.respond_to_vendor_defined_request(
            &req_payload,
            &vendor_id,
            vendor_defined_request_handler,
        );
        if let Err(e) = rsp_payload {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (Err(e), Some(writer.used_slice()));
        }

        let rsp_payload = rsp_payload.unwrap();
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse,
            },
            payload: SpdmMessagePayload::SpdmVendorDefinedResponse(
                SpdmVendorDefinedResponsePayload {
                    standard_id,
                    vendor_id,
                    rsp_payload,
                },
            ),
        };

        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }

    pub fn respond_to_vendor_defined_request<F>(
        &mut self,
        req: &VendorDefinedReqPayloadStruct,
        vendor_id_struct: &VendorIDStruct,
        verdor_defined_func: F,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct>
    where
        F: Fn(
            &VendorIDStruct,
            &VendorDefinedReqPayloadStruct,
        ) -> SpdmResult<VendorDefinedRspPayloadStruct>,
    {
        verdor_defined_func(vendor_id_struct, req)
    }
}
