// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::config;
use crate::error::{
    SpdmResult, SpdmStatus, SPDM_STATUS_BUSY_PEER, SPDM_STATUS_ERROR_PEER,
    SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_INVALID_STATE_PEER,
    SPDM_STATUS_NOT_READY_PEER, SPDM_STATUS_SESSION_MSG_ERROR,
};
use crate::message::*;
use crate::requester::RequesterContext;

/// Maximum number of RESPOND_IF_READY retries before giving up.
pub const MAX_RESPOND_IF_READY_RETRY_COUNT: usize = 3;

impl RequesterContext {
    fn spdm_handle_simple_error_response(
        &mut self,
        session_id: Option<u32>,
        error_code: u8,
    ) -> SpdmResult {
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
                session.teardown();
            }
            Err(SPDM_STATUS_INVALID_STATE_PEER)
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

        let mut spdm_status: SpdmStatus;
        if spdm_message_general_payload.param1 == SpdmErrorCode::SpdmErrorDecryptError.get_u8() {
            if let Some(sid) = session_id {
                let session = if let Some(s) = self.common.get_session_via_id(sid) {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                };
                session.teardown();
            }
            spdm_status = SPDM_STATUS_SESSION_MSG_ERROR;
        } else {
            spdm_status = match self
                .spdm_handle_simple_error_response(session_id, spdm_message_general_payload.param1)
            {
                Err(e) => e,
                _ => SPDM_STATUS_ERROR_PEER,
            }
        }

        spdm_status.spdm_status_set_error_data(response);
        Err(spdm_status)
    }

    /// Parse the `ResponseNotReady` extended data from an error response.
    /// Returns `Some(ext_data)` if the response is a valid ResponseNotReady error,
    /// `None` otherwise.
    pub fn parse_response_not_ready_ext_data(
        &self,
        response: &[u8],
    ) -> Option<SpdmErrorResponseNotReadyExtData> {
        let mut reader = Reader::init(response);
        let header = SpdmMessageHeader::read(&mut reader)?;
        if header.request_response_code != SpdmRequestResponseCode::SpdmResponseError {
            return None;
        }
        let general = SpdmMessageGeneralPayload::read(&mut reader)?;
        if general.param1 != SpdmErrorCode::SpdmErrorResponseNotReady.get_u8() {
            return None;
        }
        SpdmErrorResponseNotReadyExtData::read(&mut reader)
    }

    /// Send a `RESPOND_IF_READY` request and receive the response.
    /// This implements the retry mechanism per SPDM spec section 10.13.
    ///
    /// On success, writes the new response into `receive_buffer` and returns
    /// the number of bytes written.
    #[maybe_async::maybe_async]
    pub async fn send_receive_respond_if_ready(
        &mut self,
        session_id: Option<u32>,
        original_request_code: SpdmRequestResponseCode,
        token: u8,
        receive_buffer: &mut [u8],
        crypto_request: bool,
    ) -> Result<usize, SpdmStatus> {
        let mut send_buf = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buf);

        let header = SpdmMessageHeader {
            version: self.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmRequestResponseIfReady,
        };
        header
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_INVALID_MSG_FIELD)?;
        // param1 = original request code
        original_request_code
            .get_u8()
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_INVALID_MSG_FIELD)?;
        // param2 = token from ResponseNotReady
        token
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_INVALID_MSG_FIELD)?;

        let send_used = writer.used();
        self.send_message(session_id, &send_buf[..send_used], false)
            .await?;

        let used = self
            .receive_message(session_id, receive_buffer, crypto_request)
            .await?;
        Ok(used)
    }
}
