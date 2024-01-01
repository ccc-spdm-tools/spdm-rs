// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER,
};
use crate::message::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_end_session(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm end_session\n");

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestEndSession,
            Some(session_id),
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self.encode_spdm_end_session(&mut send_buffer)?;
        self.send_message(Some(session_id), &send_buffer[..used], false)
            .await?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(Some(session_id), &mut receive_buffer, false)
            .await?;
        self.handle_spdm_end_session_response(session_id, &receive_buffer[..used])
    }

    pub fn encode_spdm_end_session(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestEndSession,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(SpdmEndSessionRequestPayload {
                end_session_request_attributes: SpdmEndSessionRequestAttributes::empty(),
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_end_session_response(
        &mut self,
        session_id: u32,
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseEndSessionAck => {
                        let end_session_rsp =
                            SpdmEndSessionResponsePayload::spdm_read(&mut self.common, &mut reader);
                        if let Some(end_session_rsp) = end_session_rsp {
                            debug!("!!! end_session rsp : {:02x?}\n", end_session_rsp);

                            let session =
                                if let Some(s) = self.common.get_session_via_id(session_id) {
                                    s
                                } else {
                                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                                };
                            session.teardown();

                            Ok(())
                        } else {
                            error!("!!! end_session : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestEndSession,
                            SpdmRequestResponseCode::SpdmResponseEndSessionAck,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
