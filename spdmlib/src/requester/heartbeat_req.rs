// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD};
use crate::message::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_heartbeat(&mut self, session_id: u32) -> SpdmResult {
        use crate::requester::context::{HeartbeatSubstate, SpdmCommandState};

        info!("send spdm heartbeat\n");

        if self.exec_state.command_state == SpdmCommandState::Idle {
            self.exec_state.command_state = SpdmCommandState::Heartbeating(HeartbeatSubstate::Init);
        }

        if self.exec_state.command_state == SpdmCommandState::Heartbeating(HeartbeatSubstate::Init)
        {
            self.common.reset_buffer_via_request_code(
                SpdmRequestResponseCode::SpdmRequestHeartbeat,
                Some(session_id),
            );

            let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
            let used = self.encode_spdm_heartbeat(&mut send_buffer)?;

            {
                let mut guard = self.exec_state.send_buffer.lock();
                guard.0[..used].copy_from_slice(&send_buffer[..used]);
                guard.1 = used;
            }

            self.exec_state.command_state = SpdmCommandState::Heartbeating(HeartbeatSubstate::Send);
        }

        if self.exec_state.command_state == SpdmCommandState::Heartbeating(HeartbeatSubstate::Send)
        {
            let (send_data, send_len) = self.get_send_buffer_copy();
            self.exec_state.command_state =
                SpdmCommandState::Heartbeating(HeartbeatSubstate::Receive);
            self.send_message(Some(session_id), &send_data[..send_len], false)
                .await?;
        }

        if self.exec_state.command_state
            == SpdmCommandState::Heartbeating(HeartbeatSubstate::Receive)
        {
            let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
            let used = self
                .receive_message(Some(session_id), &mut receive_buffer, false)
                .await?;

            let result = self.handle_spdm_heartbeat_response(session_id, &receive_buffer[..used]);
            self.exec_state.command_state = SpdmCommandState::Idle;

            return result;
        }

        Err(crate::error::SPDM_STATUS_INVALID_STATE_LOCAL)
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
