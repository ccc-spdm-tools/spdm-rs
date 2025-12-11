// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_STATE_LOCAL,
};
use crate::message::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_heartbeat(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm heartbeat\n");

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestHeartbeat,
            Some(session_id),
        );

        let send_buffer_arc = self.send_buffer.clone();
        let mut send_buffer = send_buffer_arc
            .try_lock()
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        let used = self.encode_spdm_heartbeat(&mut send_buffer[..])?;
        self.send_message(Some(session_id), &send_buffer[..used], false)
            .await?;

        // Receive
        let receive_buffer_arc = self.receive_buffer.clone();
        let mut receive_buffer = receive_buffer_arc
            .try_lock()
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        let used = self
            .receive_message(Some(session_id), &mut receive_buffer[..], false)
            .await?;
        self.handle_spdm_heartbeat_response(session_id, &receive_buffer[..used])
    }

    pub fn encode_spdm_heartbeat(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestHeartbeat,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatRequest(SpdmHeartbeatRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_heartbeat_response(
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
                    SpdmRequestResponseCode::SpdmResponseHeartbeatAck => {
                        let heartbeat_rsp =
                            SpdmHeartbeatResponsePayload::spdm_read(&mut self.common, &mut reader);
                        if let Some(heartbeat_rsp) = heartbeat_rsp {
                            debug!("!!! heartbeat rsp : {:02x?}\n", heartbeat_rsp);
                            Ok(())
                        } else {
                            error!("!!! heartbeat : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestHeartbeat,
                            SpdmRequestResponseCode::SpdmResponseHeartbeatAck,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
