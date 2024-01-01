// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::opaque::SpdmOpaqueStruct;
use crate::common::SMVersionSelOpaque;
use crate::common::SecuredMessageVersion;
use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::common::SpdmTransportEncap;
use crate::common::INVALID_SLOT;
use crate::crypto;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::SPDM_STATUS_INVALID_STATE_PEER;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
use crate::watchdog::start_watchdog;
use config::MAX_SPDM_PSK_CONTEXT_SIZE;
extern crate alloc;
use crate::secret;
use alloc::boxed::Box;
use core::convert::TryFrom;
use core::ops::DerefMut;

impl ResponderContext {
    pub fn handle_spdm_psk_exchange<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let mut target_session_id = None;
        let (result, rsp_slice) =
            self.write_spdm_psk_exchange_response(bytes, writer, &mut target_session_id);
        if result.is_err() {
            if let Some(session_id) = target_session_id {
                if let Some(session) = self.common.get_session_via_id(session_id) {
                    session.teardown();
                }
            }
        }

        (Ok(()), rsp_slice)
    }

    pub fn write_spdm_psk_exchange_response<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
        target_session_id: &mut Option<u32>,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if self.common.runtime_info.get_connection_state().get_u8()
            < SpdmConnectionState::SpdmConnectionNegotiated.get_u8()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            if message_header.version < SpdmVersion::SpdmVersion11 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnsupportedRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        self.common
            .reset_buffer_via_request_code(SpdmRequestResponseCode::SpdmRequestPskExchange, None);

        let psk_exchange_req =
            SpdmPskExchangeRequestPayload::spdm_read(&mut self.common, &mut reader);

        let mut return_opaque = SpdmOpaqueStruct::default();

        let measurement_summary_hash;
        let psk_hint;
        if let Some(psk_exchange_req) = &psk_exchange_req {
            debug!("!!! psk_exchange req : {:02x?}\n", psk_exchange_req);

            if (psk_exchange_req.measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
                || (psk_exchange_req.measurement_summary_hash_type
                    == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
            {
                self.common.runtime_info.need_measurement_summary_hash = true;
                let measurement_summary_hash_res =
                    secret::measurement::generate_measurement_summary_hash(
                        self.common.negotiate_info.spdm_version_sel,
                        self.common.negotiate_info.base_hash_sel,
                        self.common.negotiate_info.measurement_specification_sel,
                        self.common.negotiate_info.measurement_hash_sel,
                        psk_exchange_req.measurement_summary_hash_type,
                    );
                if measurement_summary_hash_res.is_none() {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
                }
                measurement_summary_hash = measurement_summary_hash_res.unwrap();
                if measurement_summary_hash.data_size == 0 {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
                }
            } else {
                self.common.runtime_info.need_measurement_summary_hash = false;
                measurement_summary_hash = SpdmDigestStruct::default();
            }

            psk_hint = psk_exchange_req.psk_hint.clone();

            if let Some(secured_message_version_list) = psk_exchange_req
                .opaque
                .rsp_get_dmtf_supported_secure_spdm_version_list(&mut self.common)
            {
                if secured_message_version_list.version_count
                    > crate::common::opaque::MAX_SECURE_SPDM_VERSION_COUNT as u8
                {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_MSG_FIELD),
                        Some(writer.used_slice()),
                    );
                }

                let mut selected_version: Option<SecuredMessageVersion> = None;
                for index in 0..secured_message_version_list.version_count as usize {
                    for (_, local_version) in self
                        .common
                        .config_info
                        .secure_spdm_version
                        .iter()
                        .flatten()
                        .enumerate()
                    {
                        if secured_message_version_list.versions_list[index] == *local_version {
                            selected_version = Some(*local_version);
                        }
                    }
                }

                if let Some(selected_version) = selected_version {
                    if let Ok(opaque) = SpdmOpaqueStruct::from_sm_version_sel_opaque(
                        &mut self.common,
                        &SMVersionSelOpaque {
                            secured_message_version: selected_version,
                        },
                    ) {
                        return_opaque = opaque;
                    } else {
                        self.write_spdm_error(
                            SpdmErrorCode::SpdmErrorUnsupportedRequest,
                            0,
                            writer,
                        );
                        return (
                            Err(SPDM_STATUS_INVALID_MSG_FIELD),
                            Some(writer.used_slice()),
                        );
                    }
                } else {
                    error!("secure message version not selected!");
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_MSG_FIELD),
                        Some(writer.used_slice()),
                    );
                }
            }
        } else {
            error!("!!! psk_exchange req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        let psk_without_context = self
            .common
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT);
        let psk_context_size = if psk_without_context {
            0u16
        } else {
            MAX_SPDM_PSK_CONTEXT_SIZE as u16
        };
        let mut psk_context = [0u8; MAX_SPDM_PSK_CONTEXT_SIZE];
        if psk_without_context {
            let res = crypto::rand::get_random(&mut psk_context);
            if res.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
            }
        }

        let rsp_session_id = self.common.get_next_half_session_id(false);
        if rsp_session_id.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorSessionLimitExceeded, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }
        let rsp_session_id = rsp_session_id.unwrap();

        // create session structure
        let hash_algo = self.common.negotiate_info.base_hash_sel;
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

        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let message_a = self.common.runtime_info.message_a.clone();

        let session = self.common.get_next_avaiable_session();
        if session.is_none() {
            error!("!!! too many sessions : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorSessionLimitExceeded, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        let session = session.unwrap();
        let session_id =
            ((rsp_session_id as u32) << 16) + psk_exchange_req.unwrap().req_session_id as u32;
        *target_session_id = Some(session_id);
        session.setup(session_id).unwrap();
        session.set_use_psk(true);

        session.set_crypto_param(hash_algo, dhe_algo, aead_algo, key_schedule_algo);
        session.set_transport_param(sequence_number_count, max_random_count);

        session.runtime_info.psk_hint = Some(psk_hint);
        session.runtime_info.message_a = message_a;
        session.runtime_info.rsp_cert_hash = None;
        session.runtime_info.req_cert_hash = None;

        info!("send spdm psk_exchange rsp\n");

        // prepare response
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeResponse(SpdmPskExchangeResponsePayload {
                heartbeat_period: self.common.config_info.heartbeat_period,
                rsp_session_id,
                measurement_summary_hash,
                psk_context: SpdmPskContextStruct {
                    data_size: psk_context_size,
                    data: psk_context,
                },
                opaque: return_opaque,
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };

        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }
        let used = writer.used();

        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = used - base_hash_size;

        if self
            .common
            .append_message_k(session_id, &bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }
        if self
            .common
            .append_message_k(session_id, &writer.used_slice()[..temp_used])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();

        // create session - generate the handshake secret (including finished_key)
        let th1 = self
            .common
            .calc_rsp_transcript_hash(true, INVALID_SLOT, false, session);
        if th1.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
        }
        let th1 = th1.unwrap();
        debug!("!!! th1 : {:02x?}\n", th1.as_ref());

        let session = self.common.get_session_via_id(session_id).unwrap();
        if let Err(e) = session.generate_handshake_secret(spdm_version_sel, &th1) {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (Err(e), Some(writer.used_slice()));
        }

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();
        // generate HMAC with finished_key
        let transcript_hash =
            self.common
                .calc_rsp_transcript_hash(true, INVALID_SLOT, false, session);
        if transcript_hash.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
        }
        let transcript_hash = transcript_hash.unwrap();

        let hmac = session.generate_hmac_with_response_finished_key(transcript_hash.as_ref());
        if hmac.is_err() {
            let session = self.common.get_session_via_id(session_id).unwrap();
            session.teardown();
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
        }
        let hmac = hmac.unwrap();

        // append verify_data after TH1
        if self
            .common
            .append_message_k(session_id, hmac.as_ref())
            .is_err()
        {
            let session = self.common.get_session_via_id(session_id).unwrap();
            session.teardown();
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        // patch the message before send
        writer.mut_used_slice()[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref());
        let heartbeat_period = self.common.config_info.heartbeat_period;
        let session = self.common.get_session_via_id(session_id).unwrap();
        session.set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();

        if psk_without_context {
            // generate the data secret directly to skip PSK_FINISH
            let th2 = self
                .common
                .calc_rsp_transcript_hash(true, 0, false, session);
            if th2.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
            }
            let th2 = th2.unwrap();
            debug!("!!! th2 : {:02x?}\n", th2.as_ref());
            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
            let heartbeat_period = {
                let session = self.common.get_session_via_id(session_id).unwrap();
                session
                    .generate_data_secret(spdm_version_sel, &th2)
                    .unwrap();
                session.set_session_state(
                    crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                );

                session.heartbeat_period
            };
            if self
                .common
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::HBEAT_CAP)
                && self
                    .common
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::HBEAT_CAP)
            {
                start_watchdog(session_id, heartbeat_period as u16 * 2);
            }
        }

        let session = self.common.get_session_via_id(session_id).unwrap();
        session.heartbeat_period = heartbeat_period;
        if return_opaque.data_size != 0 {
            session.secure_spdm_version_sel = SecuredMessageVersion::try_from(
                return_opaque.data[return_opaque.data_size as usize - 1],
            )
            .unwrap();
        }

        (Ok(()), Some(writer.used_slice()))
    }
}
