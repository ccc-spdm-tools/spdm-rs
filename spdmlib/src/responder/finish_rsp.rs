// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::session::SpdmSession;
use crate::common::{ManagedBuffer12Sign, SpdmCodec};
use crate::crypto;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::*;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
extern crate alloc;
use alloc::boxed::Box;

impl ResponderContext {
    pub fn handle_spdm_finish<'a>(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        #[cfg(feature = "mandatory-mut-auth")]
        if !self.common.mut_auth_done {
            if let Some(session) = self.common.get_session_via_id(session_id) {
                session.teardown();
            }
            return (Ok(()), None);
        }

        let (result, rsp_slice) = self.write_spdm_finish_response(session_id, bytes, writer);
        if result.is_err() {
            if let Some(session) = self.common.get_session_via_id(session_id) {
                session.teardown();
            }
        }

        (Ok(()), rsp_slice)
    }

    // Return true on success, false otherwise.
    pub fn write_spdm_finish_response<'a>(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
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
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestFinish,
            Some(session_id),
        );

        let finish_req = SpdmFinishRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(finish_req) = &finish_req {
            debug!("!!! finish req : {:02x?}\n", finish_req);
        } else {
            error!("!!! finish req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }
        let finish_req = finish_req.unwrap();

        if self
            .common
            .append_message_f(false, session_id, &bytes[..4])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        let mut_auth_attributes = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap()
            .get_mut_auth_requested();
        let finish_request_attributes = finish_req.finish_request_attributes;

        if (!mut_auth_attributes.is_empty()
            && !finish_request_attributes.contains(SpdmFinishRequestAttributes::SIGNATURE_INCLUDED))
            || (mut_auth_attributes.is_empty()
                && finish_request_attributes
                    .contains(SpdmFinishRequestAttributes::SIGNATURE_INCLUDED))
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        let is_mut_auth = !mut_auth_attributes.is_empty();
        if is_mut_auth {
            let session = self
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();

            if self
                .verify_finish_req_signature(&finish_req.signature, session)
                .is_err()
            {
                error!("verify finish request signature error");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorDecryptError, 0, writer);
                return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
            }
            info!("verify_finish_req_signature pass");

            if self
                .common
                .append_message_f(false, session_id, finish_req.signature.as_ref())
                .is_err()
            {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                    Some(writer.used_slice()),
                );
            }
        }

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;

        {
            let session = self.common.get_session_via_id(session_id).unwrap();

            if session.get_use_psk() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }

            let session = self
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();

            let slot_id = session.get_slot_id();

            let transcript_hash =
                self.common
                    .calc_rsp_transcript_hash(false, slot_id, is_mut_auth, session);
            if transcript_hash.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
            }
            let transcript_hash = transcript_hash.as_ref().unwrap();

            if session
                .verify_hmac_with_request_finished_key(
                    transcript_hash.as_ref(),
                    &finish_req.verify_data,
                )
                .is_err()
            {
                error!("verify_hmac_with_request_finished_key fail");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorDecryptError, 0, writer);
                return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
            } else {
                info!("verify_hmac_with_request_finished_key pass");
            }

            if self
                .common
                .append_message_f(false, session_id, finish_req.verify_data.as_ref())
                .is_err()
            {
                error!("message_f add the message error");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                    Some(writer.used_slice()),
                );
            }
        }

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

        info!("send spdm finish rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmFinishResponse(SpdmFinishResponsePayload {
                verify_data: SpdmDigestStruct {
                    data_size: (self as &ResponderContext)
                        .common
                        .negotiate_info
                        .base_hash_sel
                        .get_size(),
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

        if in_clear_text {
            // generate HMAC with finished_key
            let temp_used = used - base_hash_size;

            if self
                .common
                .append_message_f(false, session_id, &writer.used_slice()[..temp_used])
                .is_err()
            {
                error!("message_f add the message error");
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

            let slot_id = session.get_slot_id();

            let transcript_hash =
                self.common
                    .calc_rsp_transcript_hash(false, slot_id, is_mut_auth, session);
            if transcript_hash.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
            }
            let transcript_hash = transcript_hash.unwrap();

            let hmac = session.generate_hmac_with_response_finished_key(transcript_hash.as_ref());
            if hmac.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
            }
            let hmac = hmac.unwrap();

            if self
                .common
                .append_message_f(false, session_id, hmac.as_ref())
                .is_err()
            {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                    Some(writer.used_slice()),
                );
            }

            // patch the message before send
            writer.mut_used_slice()[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref());
        } else if self
            .common
            .append_message_f(false, session_id, &writer.used_slice()[..4])
            .is_err()
        {
            error!("message_f add the message error");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        // generate the data secret
        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();
        let slot_id = session.get_slot_id();
        let th2 = self
            .common
            .calc_rsp_transcript_hash(false, slot_id, is_mut_auth, session);

        if th2.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
        }
        let th2 = th2.unwrap();
        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self.common.get_session_via_id(session_id).unwrap();
        if let Err(e) = session.generate_data_secret(spdm_version_sel, &th2) {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (Err(e), Some(writer.used_slice()));
        } else {
            (Ok(()), Some(writer.used_slice()))
        }
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    fn verify_finish_req_signature(
        &self,
        signature: &SpdmSignatureStruct,
        session: &SpdmSession,
    ) -> SpdmResult {
        let transcript_data_hash =
            self.common
                .calc_rsp_transcript_hash(false, session.get_slot_id(), true, session)?;

        let peer_slot_id = self.common.runtime_info.get_peer_used_cert_chain_slot_id();
        let peer_cert = &self.common.peer_info.peer_cert_chain[peer_slot_id as usize]
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[peer_slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];
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

        crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            peer_cert,
            transcript_sign.as_ref(),
            signature,
        )
    }

    #[cfg(feature = "hashed-transcript-data")]
    fn verify_finish_req_signature(
        &self,
        signature: &SpdmSignatureStruct,
        session: &SpdmSession,
    ) -> SpdmResult {
        let transcript_hash =
            self.common
                .calc_rsp_transcript_hash(false, session.get_slot_id(), true, session)?;

        let peer_slot_id = self.common.runtime_info.get_peer_used_cert_chain_slot_id();
        let peer_cert = &self.common.peer_info.peer_cert_chain[peer_slot_id as usize]
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[peer_slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];

        let mut transcript_hash_sign = ManagedBuffer12Sign::default();
        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            transcript_hash_sign.reset_message();
            transcript_hash_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_hash_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_12)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_hash_sign
                .append_message(&SPDM_FINISH_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            transcript_hash_sign
                .append_message(transcript_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        } else {
            error!("hashed-transcript-data is unsupported in SPDM 1.0/1.1 signing!\n");
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        let res = crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            peer_cert,
            transcript_hash_sign.as_ref(),
            signature,
        );

        res
    }
}
