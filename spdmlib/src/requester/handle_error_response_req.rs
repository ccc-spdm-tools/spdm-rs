// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader};

use crate::common::session::SpdmSessionState;
use crate::error::{
    SpdmResult, SPDM_STATUS_BUSY_PEER, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_NOT_READY_PEER, SPDM_STATUS_SESSION_MSG_ERROR,
};
use crate::message::*;
use crate::requester::RequesterContext;

impl RequesterContext {
    fn spdm_handle_simple_error_response(
        &mut self,
        session_id: Option<u32>,
        error_code: u8,
    ) -> SpdmResult {
        /* NOT_READY is treated as error here.
         * Use spdm_handle_error_response_main to handle NOT_READY message in long latency command.*/
        if error_code == SpdmErrorCode::SpdmErrorResponseNotReady.get_u8() {
            Err(SPDM_STATUS_NOT_READY_PEER)
        } else if error_code == SpdmErrorCode::SpdmErrorBusy.get_u8() {
            Err(SPDM_STATUS_BUSY_PEER)
        } else if error_code == SpdmErrorCode::SpdmErrorRequestResynch.get_u8() {
            if let Some(sid) = session_id {
                let session = if let Some(s) = self.common.get_session_via_id(sid) {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                };
                session.set_session_state(SpdmSessionState::SpdmSessionNotStarted);
            }
            Err(SPDM_STATUS_INVALID_PARAMETER)
        } else {
            Err(SPDM_STATUS_ERROR_PEER)
        }
    }

    pub fn spdm_handle_error_response_main(
        &mut self,
        session_id: Option<u32>,
        response: &[u8],
        _original_request_code: SpdmRequestResponseCode,
        _expected_response_code: SpdmRequestResponseCode,
    ) -> SpdmResult {
        let mut spdm_message_header_reader = Reader::init(response);
        let spdm_message_header =
            if let Some(smh) = SpdmMessageHeader::read(&mut spdm_message_header_reader) {
                smh
            } else {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            };
        let header_size = spdm_message_header_reader.used();

        if spdm_message_header.version != self.common.negotiate_info.spdm_version_sel {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        if spdm_message_header.request_response_code != SpdmRequestResponseCode::SpdmResponseError {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        let mut spdm_message_payload_reader = Reader::init(&response[header_size..]);
        let spdm_message_general_payload =
            if let Some(smgp) = SpdmMessageGeneralPayload::read(&mut spdm_message_payload_reader) {
                smgp
            } else {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            };

        if spdm_message_general_payload.param1 == SpdmErrorCode::SpdmErrorDecryptError.get_u8() {
            if let Some(sid) = session_id {
                let session = if let Some(s) = self.common.get_session_via_id(sid) {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                };
                session.teardown();
            }
            Err(SPDM_STATUS_SESSION_MSG_ERROR)
        } else {
            self.spdm_handle_simple_error_response(session_id, spdm_message_general_payload.param1)
        }
    }
}
