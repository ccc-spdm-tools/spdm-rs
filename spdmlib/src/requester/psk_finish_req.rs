// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;
extern crate alloc;
use alloc::boxed::Box;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_psk_finish(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm psk_finish\n");

        if let Err(e) = self.delegate_send_receive_spdm_psk_finish(session_id).await {
            if let Some(session) = self.common.get_session_via_id(session_id) {
                session.teardown();
            }

            Err(e)
        } else {
            Ok(())
        }
    }

    #[maybe_async::maybe_async]
    pub async fn delegate_send_receive_spdm_psk_finish(&mut self, session_id: u32) -> SpdmResult {
        if self.common.get_session_via_id(session_id).is_none() {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestPskFinish,
            Some(session_id),
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let res = self.encode_spdm_psk_finish(session_id, &mut send_buffer);
        if res.is_err() {
            self.common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown();
            return Err(res.err().unwrap());
        }
        let send_used = res.unwrap();
        let res = self
            .send_message(Some(session_id), &send_buffer[..send_used], false)
            .await;
        if res.is_err() {
            self.common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown();
            return res;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let res = self
            .receive_message(Some(session_id), &mut receive_buffer, false)
            .await;
        if res.is_err() {
            self.common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown();
            return Err(res.err().unwrap());
        }
        let receive_used = res.unwrap();
        let res = self.handle_spdm_psk_finish_response(session_id, &receive_buffer[..receive_used]);
        if res.is_err() {
            if let Some(session) = self.common.get_session_via_id(session_id) {
                session.teardown();
            }
        }
        res
    }

    pub fn encode_spdm_psk_finish(&mut self, session_id: u32, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskFinish,
            },
            payload: SpdmMessagePayload::SpdmPskFinishRequest(SpdmPskFinishRequestPayload {
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        let send_used = request.spdm_encode(&mut self.common, &mut writer)?;

        // generate HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = send_used - base_hash_size;

        self.common
            .append_message_f(true, session_id, &buf[..temp_used])?;

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();
        let transcript_hash =
            self.common
                .calc_req_transcript_hash(true, INVALID_SLOT, false, session)?;

        let session = self.common.get_session_via_id(session_id).unwrap();
        let hmac = session.generate_hmac_with_request_finished_key(transcript_hash.as_ref())?;

        self.common
            .append_message_f(true, session_id, hmac.as_ref())?;

        // patch the message before send
        buf[(send_used - base_hash_size)..send_used].copy_from_slice(hmac.as_ref());
        Ok(send_used)
    }

    pub fn handle_spdm_psk_finish_response(
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
                    SpdmRequestResponseCode::SpdmResponsePskFinishRsp => {
                        let psk_finish_rsp =
                            SpdmPskFinishResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let receive_used = reader.used();
                        if let Some(psk_finish_rsp) = psk_finish_rsp {
                            debug!("!!! psk_finish rsp : {:02x?}\n", psk_finish_rsp);
                            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;

                            self.common.append_message_f(
                                true,
                                session_id,
                                &receive_buffer[..receive_used],
                            )?;

                            let session = self
                                .common
                                .get_immutable_session_via_id(session_id)
                                .unwrap();

                            let th2 = self.common.calc_req_transcript_hash(
                                true,
                                INVALID_SLOT,
                                false,
                                session,
                            )?;

                            debug!("!!! th2 : {:02x?}\n", th2.as_ref());

                            let session = self.common.get_session_via_id(session_id).unwrap();
                            session.generate_data_secret(spdm_version_sel, &th2)?;
                            session.set_session_state(
                                crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                            );

                            Ok(())
                        } else {
                            error!("!!! psk_finish : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestPskFinish,
                            SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
