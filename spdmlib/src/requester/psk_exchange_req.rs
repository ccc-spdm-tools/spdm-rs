// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use config::MAX_SPDM_PSK_CONTEXT_SIZE;

use crate::crypto;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_SESSION_NUMBER_EXCEED, SPDM_STATUS_VERIF_FAIL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;
extern crate alloc;
use core::ops::DerefMut;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_psk_exchange(
        &mut self,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        psk_hint: Option<&SpdmPskHintStruct>,
    ) -> SpdmResult<u32> {
        info!("send spdm psk exchange\n");

        let psk_hint = if let Some(hint) = psk_hint {
            hint.clone()
        } else {
            SpdmPskHintStruct::default()
        };

        self.common
            .reset_buffer_via_request_code(SpdmRequestResponseCode::SpdmRequestPskExchange, None);

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let half_session_id = self.common.get_next_half_session_id(true)?;
        let send_used = self.encode_spdm_psk_exchange(
            half_session_id,
            measurement_summary_hash_type,
            &psk_hint,
            &mut send_buffer,
        )?;

        self.send_message(None, &send_buffer[..send_used], false)
            .await?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let receive_used = self
            .receive_message(None, &mut receive_buffer, false)
            .await?;

        let mut target_session_id = None;
        if let Err(e) = self.handle_spdm_psk_exchange_response(
            half_session_id,
            measurement_summary_hash_type,
            &psk_hint,
            &send_buffer[..send_used],
            &receive_buffer[..receive_used],
            &mut target_session_id,
        ) {
            if let Some(session_id) = target_session_id {
                if let Some(session) = self.common.get_session_via_id(session_id) {
                    session.teardown();
                }
            }

            Err(e)
        } else {
            Ok(target_session_id.unwrap())
        }
    }

    pub fn encode_spdm_psk_exchange(
        &mut self,
        half_session_id: u16,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        psk_hint: &SpdmPskHintStruct,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let mut psk_context = [0u8; MAX_SPDM_PSK_CONTEXT_SIZE];
        crypto::rand::get_random(&mut psk_context)?;

        let mut secured_message_version_list = SecuredMessageVersionList {
            version_count: 0,
            versions_list: [SecuredMessageVersion::default(); MAX_SECURE_SPDM_VERSION_COUNT],
        };

        for local_version in self.common.config_info.secure_spdm_version.iter().flatten() {
            secured_message_version_list.versions_list
                [secured_message_version_list.version_count as usize] = *local_version;
            secured_message_version_list.version_count += 1;
        }

        let opaque = SpdmOpaqueStruct::from_sm_supported_ver_list_opaque(
            &mut self.common,
            &SMSupportedVerListOpaque {
                secured_message_version_list,
            },
        )?;

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskExchange,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeRequest(SpdmPskExchangeRequestPayload {
                measurement_summary_hash_type,
                req_session_id: half_session_id,
                psk_hint: psk_hint.clone(),
                psk_context: SpdmPskContextStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: psk_context,
                },
                opaque,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_psk_exchange_response(
        &mut self,
        half_session_id: u16,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        psk_hint: &SpdmPskHintStruct,
        send_buffer: &[u8],
        receive_buffer: &[u8],
        target_session_id: &mut Option<u32>,
    ) -> SpdmResult<u32> {
        self.common.runtime_info.need_measurement_summary_hash = (measurement_summary_hash_type
            == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
            || (measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll);

        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponsePskExchangeRsp => {
                        let psk_exchange_rsp = SpdmPskExchangeResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let receive_used = reader.used();
                        if let Some(psk_exchange_rsp) = psk_exchange_rsp {
                            debug!("!!! psk_exchange rsp : {:02x?}\n", psk_exchange_rsp);

                            // create session structure
                            let base_hash_algo = self.common.negotiate_info.base_hash_sel;
                            let dhe_algo = self.common.negotiate_info.dhe_sel;
                            let aead_algo = self.common.negotiate_info.aead_sel;
                            let key_schedule_algo = self.common.negotiate_info.key_schedule_sel;
                            let sequence_number_count = {
                                let mut transport_encap = self.common.transport_encap.lock();
                                let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
                                    transport_encap.deref_mut();
                                transport_encap.get_sequence_number_count()
                            };
                            let max_random_count = {
                                let mut transport_encap = self.common.transport_encap.lock();
                                let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
                                    transport_encap.deref_mut();
                                transport_encap.get_max_random_count()
                            };

                            let secure_spdm_version_sel = psk_exchange_rsp
                                .opaque
                                .req_get_dmtf_secure_spdm_version_selection(&mut self.common)
                                .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

                            let session_id = ((psk_exchange_rsp.rsp_session_id as u32) << 16)
                                + half_session_id as u32;
                            *target_session_id = Some(session_id);
                            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                            let message_a = self.common.runtime_info.message_a.clone();

                            let session = self
                                .common
                                .get_next_avaiable_session()
                                .ok_or(SPDM_STATUS_SESSION_NUMBER_EXCEED)?;

                            session.setup(session_id)?;

                            session.set_use_psk(true);

                            session.set_crypto_param(
                                base_hash_algo,
                                dhe_algo,
                                aead_algo,
                                key_schedule_algo,
                            );
                            session.set_transport_param(sequence_number_count, max_random_count);

                            session.runtime_info.psk_hint = Some(psk_hint.clone());
                            session.runtime_info.message_a = message_a;
                            session.runtime_info.rsp_cert_hash = None;
                            session.runtime_info.req_cert_hash = None;

                            // create transcript
                            let base_hash_size =
                                self.common.negotiate_info.base_hash_sel.get_size() as usize;
                            let temp_receive_used = receive_used - base_hash_size;

                            self.common.append_message_k(session_id, send_buffer)?;
                            self.common.append_message_k(
                                session_id,
                                &receive_buffer[..temp_receive_used],
                            )?;

                            let session = self
                                .common
                                .get_immutable_session_via_id(session_id)
                                .unwrap();

                            // generate the handshake secret (including finished_key) before verify HMAC
                            let th1 = self.common.calc_req_transcript_hash(
                                true,
                                INVALID_SLOT,
                                false,
                                session,
                            )?;
                            debug!("!!! th1 : {:02x?}\n", th1.as_ref());

                            let session = self.common.get_session_via_id(session_id).unwrap();
                            session.generate_handshake_secret(spdm_version_sel, &th1)?;

                            let session = self
                                .common
                                .get_immutable_session_via_id(session_id)
                                .unwrap();

                            // verify HMAC with finished_key
                            let transcript_hash = self.common.calc_req_transcript_hash(
                                true,
                                INVALID_SLOT,
                                false,
                                session,
                            )?;

                            let session = self
                                .common
                                .get_immutable_session_via_id(session_id)
                                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

                            if session
                                .verify_hmac_with_response_finished_key(
                                    transcript_hash.as_ref(),
                                    &psk_exchange_rsp.verify_data,
                                )
                                .is_err()
                            {
                                error!("verify_hmac_with_response_finished_key fail");
                                let session = self.common.get_session_via_id(session_id).unwrap();
                                session.teardown();
                                return Err(SPDM_STATUS_VERIF_FAIL);
                            } else {
                                info!("verify_hmac_with_response_finished_key pass");
                            }

                            // append verify_data after TH1
                            if self
                                .common
                                .append_message_k(session_id, psk_exchange_rsp.verify_data.as_ref())
                                .is_err()
                            {
                                let session = self
                                    .common
                                    .get_session_via_id(session_id)
                                    .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
                                session.teardown();
                                return Err(SPDM_STATUS_BUFFER_FULL);
                            }

                            let session = self
                                .common
                                .get_session_via_id(session_id)
                                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
                            session.set_session_state(
                                crate::common::session::SpdmSessionState::SpdmSessionHandshaking,
                            );

                            let session = self
                                .common
                                .get_immutable_session_via_id(session_id)
                                .unwrap();
                            let psk_without_context = self
                                .common
                                .negotiate_info
                                .rsp_capabilities_sel
                                .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT);
                            if psk_without_context {
                                // generate the data secret directly to skip PSK_FINISH
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
                            }

                            let session = self.common.get_session_via_id(session_id).unwrap();
                            session.secure_spdm_version_sel = secure_spdm_version_sel;
                            session.heartbeat_period = psk_exchange_rsp.heartbeat_period;

                            Ok(session_id)
                        } else {
                            error!("!!! psk_exchange : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let status = self.spdm_handle_error_response_main(
                            None,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestPskExchange,
                            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
                        );
                        match status {
                            Err(status) => Err(status),
                            Ok(()) => Err(SPDM_STATUS_ERROR_PEER),
                        }
                    }
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
