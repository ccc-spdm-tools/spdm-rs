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
    async fn send_receive_spdm_key_update_op(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
        tag: u8,
    ) -> SpdmResult {
        info!("send spdm key_update\n");

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            Some(session_id),
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self.encode_spdm_key_update_op(key_update_operation, tag, &mut send_buffer)?;
        self.send_message(Some(session_id), &send_buffer[..used], false)
            .await?;

        // update key
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
            s
        } else {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        };
        let update_requester = key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateSingleKey
            || key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateAllKeys;
        let update_responder = key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateAllKeys;
        session.create_data_secret_update(spdm_version_sel, update_requester, update_responder)?;
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(Some(session_id), &mut receive_buffer, false)
            .await?;

        self.handle_spdm_key_update_op_response(
            session_id,
            update_requester,
            update_responder,
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_key_update_op(
        &mut self,
        key_update_operation: SpdmKeyUpdateOperation,
        tag: u8,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
                key_update_operation,
                tag,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_key_update_op_response(
        &mut self,
        session_id: u32,
        update_requester: bool,
        update_responder: bool,
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseKeyUpdateAck => {
                        let key_update_rsp =
                            SpdmKeyUpdateResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                            s
                        } else {
                            return Err(SPDM_STATUS_INVALID_PARAMETER);
                        };
                        if let Some(key_update_rsp) = key_update_rsp {
                            debug!("!!! key_update rsp : {:02x?}\n", key_update_rsp);
                            session.activate_data_secret_update(
                                spdm_version_sel,
                                update_requester,
                                update_responder,
                                true,
                            )?;
                            Ok(())
                        } else {
                            error!("!!! key_update : fail !!!\n");
                            session.activate_data_secret_update(
                                spdm_version_sel,
                                update_requester,
                                update_responder,
                                false,
                            )?;
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
                            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_key_update(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
    ) -> SpdmResult {
        if key_update_operation != SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            && key_update_operation != SpdmKeyUpdateOperation::SpdmUpdateSingleKey
        {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        self.send_receive_spdm_key_update_op(session_id, key_update_operation, 1)
            .await?;
        self.send_receive_spdm_key_update_op(
            session_id,
            SpdmKeyUpdateOperation::SpdmVerifyNewKey,
            2,
        )
        .await
    }
}
