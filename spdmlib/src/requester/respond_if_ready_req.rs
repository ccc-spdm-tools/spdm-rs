// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::common::SpdmRespondIfReadyContext;
use crate::error::{
    SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_MSG_SIZE, SPDM_STATUS_NOT_READY_PEER,
};
use crate::message::*;
use crate::requester::RequesterContext;

/// Maximum number of RESPOND_IF_READY requests sent for one original request.
pub const MAX_RESPOND_IF_READY_RETRY_COUNT: usize = 3;
/// Largest accepted RDTExponent; RDT = 2^31 us is about 36 minutes.
pub const MAX_RDT_EXPONENT: u8 = 31;

impl RequesterContext {
    /// If `receive_buffer[..used]` is ERROR(ResponseNotReady), wait RDT and fetch the
    /// response with RESPOND_IF_READY. Returns the size of the response to the original
    /// request, which is left in `receive_buffer`.
    #[maybe_async::maybe_async]
    pub async fn spdm_handle_response_not_ready(
        &mut self,
        session_id: Option<u32>,
        original_request_code: SpdmRequestResponseCode,
        receive_buffer: &mut [u8],
        mut used: usize,
        crypto_request: bool,
    ) -> SpdmResult<usize> {
        // A RESPOND_IF_READY sent before a checkpoint restore is answered in receive_buffer.
        let mut pending = match self.common.respond_if_ready.take() {
            Some(pending)
                if pending.request_code == original_request_code.get_u8()
                    && pending.session_id == session_id =>
            {
                Some(pending)
            }
            _ => None,
        };
        loop {
            let ext_data = match self.read_response_not_ready(&receive_buffer[..used])? {
                Some(ext_data) => ext_data,
                None => return Ok(used),
            };
            if ext_data.request_code != original_request_code.get_u8()
                || matches!(pending, Some(p) if p.token != ext_data.token)
                || ext_data.rdtm <= 1
                || ext_data.rdt_exponent > MAX_RDT_EXPONENT
            {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            let retry_count = pending.map_or(0, |p| p.retry_count);
            if retry_count as usize >= MAX_RESPOND_IF_READY_RETRY_COUNT {
                let mut status = SPDM_STATUS_NOT_READY_PEER;
                status.spdm_status_set_error_data(&receive_buffer[..used]);
                return Err(status);
            }

            // WT counts from the reception of the error, so this waits at least RDT.
            crate::time::sleep(1usize << ext_data.rdt_exponent);

            // Set before sending, so that a checkpoint taken on send can resume here.
            self.common.respond_if_ready = Some(SpdmRespondIfReadyContext {
                request_code: ext_data.request_code,
                token: ext_data.token,
                retry_count: retry_count + 1,
                session_id,
            });
            if let Err(e) = self
                .send_respond_if_ready(session_id, ext_data.request_code, ext_data.token)
                .await
            {
                self.common.respond_if_ready = None;
                return Err(e);
            }
            // On failure the state stays, so that receiving again can resume.
            used = self
                .receive_message(session_id, receive_buffer, crypto_request)
                .await?;
            pending = self.common.respond_if_ready.take();
        }
    }

    fn read_response_not_ready(
        &self,
        response: &[u8],
    ) -> SpdmResult<Option<SpdmErrorResponseNotReadyExtData>> {
        let mut reader = Reader::init(response);
        let header = match SpdmMessageHeader::read(&mut reader) {
            Some(header) => header,
            None => return Ok(None),
        };
        if header.request_response_code != SpdmRequestResponseCode::SpdmResponseError {
            return Ok(None);
        }
        match SpdmMessageGeneralPayload::read(&mut reader) {
            Some(payload)
                if payload.param1 == SpdmErrorCode::SpdmErrorResponseNotReady.get_u8() => {}
            _ => return Ok(None),
        }
        if header.version != self.common.negotiate_info.spdm_version_sel {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        SpdmErrorResponseNotReadyExtData::read(&mut reader)
            .map(Some)
            .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)
    }

    #[maybe_async::maybe_async]
    async fn send_respond_if_ready(
        &mut self,
        session_id: Option<u32>,
        request_code: u8,
        token: u8,
    ) -> SpdmResult {
        let mut send_buffer = [0u8; 4];
        let mut writer = Writer::init(&mut send_buffer);
        SpdmMessageHeader {
            version: self.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmRequestResponseIfReady,
        }
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        SpdmMessageGeneralPayload {
            param1: request_code,
            param2: token,
        }
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        let send_used = writer.used();

        // send_message() would drop the state of this RESPOND_IF_READY.
        self.send_single_message(session_id, &send_buffer[..send_used], false)
            .await
    }
}
