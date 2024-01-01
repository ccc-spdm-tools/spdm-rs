// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::session::SpdmSession;
use crate::error::*;
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;
extern crate alloc;
use alloc::boxed::Box;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_finish(
        &mut self,
        req_slot_id: Option<u8>,
        session_id: u32,
    ) -> SpdmResult {
        info!("send spdm finish\n");

        if let Err(e) = self
            .delegate_send_receive_spdm_finish(req_slot_id, session_id)
            .await
        {
            if let Some(session) = self.common.get_session_via_id(session_id) {
                session.teardown();
            }

            Err(e)
        } else {
            Ok(())
        }
    }

    #[maybe_async::maybe_async]
    pub async fn delegate_send_receive_spdm_finish(
        &mut self,
        req_slot_id: Option<u8>,
        session_id: u32,
    ) -> SpdmResult {
        let in_clear_text = self
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            && self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);
        info!("in_clear_text {:?}\n", in_clear_text);

        let req_slot_id = if let Some(req_slot_id) = req_slot_id {
            if req_slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }
            if self.common.provision_info.my_cert_chain[req_slot_id as usize].is_none() {
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }
            req_slot_id
        } else {
            0
        };

        if self.common.get_session_via_id(session_id).is_none() {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestFinish,
            Some(session_id),
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let res = self.encode_spdm_finish(session_id, req_slot_id, &mut send_buffer);
        if res.is_err() {
            self.common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown();
            return Err(res.err().unwrap());
        }
        let send_used = res.unwrap();
        let res = if in_clear_text {
            self.send_message(None, &send_buffer[..send_used], false)
                .await
        } else {
            self.send_message(Some(session_id), &send_buffer[..send_used], false)
                .await
        };
        if res.is_err() {
            self.common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown();
            return res;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let res = if in_clear_text {
            self.receive_message(None, &mut receive_buffer, false).await
        } else {
            self.receive_message(Some(session_id), &mut receive_buffer, false)
                .await
        };
        if res.is_err() {
            self.common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown();
            return Err(res.err().unwrap());
        }
        let receive_used = res.unwrap();
        let res = self.handle_spdm_finish_response(
            session_id,
            req_slot_id,
            &receive_buffer[..receive_used],
        );
        if res.is_err() {
            if let Some(session) = self.common.get_session_via_id(session_id) {
                session.teardown();
            }
        }
        res
    }

    pub fn encode_spdm_finish(
        &mut self,
        session_id: u32,
        req_slot_id: u8,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut finish_request_attributes = SpdmFinishRequestAttributes::empty();
        let mut signature = SpdmSignatureStruct::default();
        let mut is_mut_auth = false;

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        if !session.get_mut_auth_requested().is_empty() {
            finish_request_attributes = SpdmFinishRequestAttributes::SIGNATURE_INCLUDED;
            signature.data_size = self.common.negotiate_info.req_asym_sel.get_size();
            is_mut_auth = true;
        }

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestFinish,
            },
            payload: SpdmMessagePayload::SpdmFinishRequest(SpdmFinishRequestPayload {
                finish_request_attributes,
                req_slot_id,
                signature,
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };

        let mut writer = Writer::init(buf);
        let send_used = request.spdm_encode(&mut self.common, &mut writer)?;

        // Record the header of finish request
        self.common.append_message_f(true, session_id, &buf[..4])?;

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        if !session.get_mut_auth_requested().is_empty() {
            signature = self.generate_finish_req_signature(session.get_slot_id(), session)?;
            // patch the signature
            buf[4..4 + signature.data_size as usize].copy_from_slice(signature.as_ref());

            self.common
                .append_message_f(true, session_id, signature.as_ref())?;
        }

        // generate HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();

        let transcript_hash =
            self.common
                .calc_req_transcript_hash(false, req_slot_id, is_mut_auth, session)?;

        let session = self.common.get_session_via_id(session_id).unwrap();

        let hmac = session.generate_hmac_with_request_finished_key(transcript_hash.as_ref())?;

        self.common
            .append_message_f(true, session_id, hmac.as_ref())?;

        // patch the message before send
        buf[(send_used - base_hash_size)..send_used].copy_from_slice(hmac.as_ref());
        Ok(send_used)
    }

    pub fn handle_spdm_finish_response(
        &mut self,
        session_id: u32,
        req_slot_id: u8,
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let in_clear_text = self
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            && self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);

        let is_mut_auth = !self
            .common
            .get_immutable_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
            .get_mut_auth_requested()
            .is_empty();

        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseFinishRsp => {
                    let finish_rsp =
                        SpdmFinishResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let receive_used = reader.used();
                    if let Some(finish_rsp) = finish_rsp {
                        debug!("!!! finish rsp : {:02x?}\n", finish_rsp);

                        let base_hash_size =
                            self.common.negotiate_info.base_hash_sel.get_size() as usize;

                        if in_clear_text {
                            // verify HMAC with finished_key
                            let temp_used = receive_used - base_hash_size;
                            self.common.append_message_f(
                                true,
                                session_id,
                                &receive_buffer[..temp_used],
                            )?;

                            let session = self
                                .common
                                .get_immutable_session_via_id(session_id)
                                .unwrap();

                            let transcript_hash = self.common.calc_req_transcript_hash(
                                false,
                                req_slot_id,
                                is_mut_auth,
                                session,
                            )?;

                            if session
                                .verify_hmac_with_response_finished_key(
                                    transcript_hash.as_ref(),
                                    &finish_rsp.verify_data,
                                )
                                .is_err()
                            {
                                error!("verify_hmac_with_response_finished_key fail");
                                return Err(SPDM_STATUS_VERIF_FAIL);
                            } else {
                                info!("verify_hmac_with_response_finished_key pass");
                            }

                            self.common.append_message_f(
                                true,
                                session_id,
                                finish_rsp.verify_data.as_ref(),
                            )?;
                        } else {
                            self.common.append_message_f(
                                true,
                                session_id,
                                &receive_buffer[..receive_used],
                            )?;
                        }

                        let session = self
                            .common
                            .get_immutable_session_via_id(session_id)
                            .unwrap();

                        // generate the data secret
                        let th2 = self.common.calc_req_transcript_hash(
                            false,
                            req_slot_id,
                            is_mut_auth,
                            session,
                        )?;

                        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
                        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                        let session = self.common.get_session_via_id(session_id).unwrap();
                        match session.generate_data_secret(spdm_version_sel, &th2) {
                            Ok(_) => {}
                            Err(e) => {
                                return Err(e);
                            }
                        }
                        session.set_session_state(
                            crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                        );

                        self.common.runtime_info.set_last_session_id(None);

                        Ok(())
                    } else {
                        error!("!!! finish : fail !!!\n");
                        Err(SPDM_STATUS_INVALID_MSG_FIELD)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => self.spdm_handle_error_response_main(
                    Some(session_id),
                    receive_buffer,
                    SpdmRequestResponseCode::SpdmRequestFinish,
                    SpdmRequestResponseCode::SpdmResponseFinishRsp,
                ),
                _ => Err(SPDM_STATUS_ERROR_PEER),
            },
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    fn generate_finish_req_signature(
        &self,
        slot_id: u8,
        session: &SpdmSession,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let transcript_data_hash = self
            .common
            .calc_req_transcript_hash(false, slot_id, true, session)?;

        let mut transcript_sign = ManagedBuffer12Sign::default();
        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            transcript_sign.reset_message();
            transcript_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_12)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_sign
                .append_message(&SPDM_FINISH_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_sign
                .append_message(transcript_data_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        crate::secret::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            transcript_sign.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(feature = "hashed-transcript-data")]
    fn generate_finish_req_signature(
        &self,
        _slot_id: u8,
        session: &SpdmSession,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let transcript_hash =
            self.common
                .calc_req_transcript_hash(false, INVALID_SLOT, true, session)?;

        debug!("transcript_hash - {:02x?}", transcript_hash.as_ref());

        let mut transcript_sign = ManagedBuffer12Sign::default();
        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            transcript_sign.reset_message();
            transcript_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_12)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_sign
                .append_message(&SPDM_FINISH_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_sign
                .append_message(transcript_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        } else {
            error!("hashed-transcript-data is unsupported in SPDM 1.0/1.1 signing!\n");
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        let signature = crate::secret::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            transcript_sign.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;

        let peer_slot_id = self.common.runtime_info.get_local_used_cert_chain_slot_id();
        let peer_cert = &self.common.provision_info.my_cert_chain[peer_slot_id as usize]
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[peer_slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];

        crate::crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            peer_cert,
            transcript_sign.as_ref(),
            &signature,
        )
        .unwrap();

        Ok(signature)
    }
}
