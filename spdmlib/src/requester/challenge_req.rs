// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto;
#[cfg(feature = "hashed-transcript-data")]
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::{
    SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_ERROR_PEER,
    SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_VERIF_FAIL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_challenge(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult {
        info!("send spdm challenge\n");

        if slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        self.common
            .reset_buffer_via_request_code(SpdmRequestResponseCode::SpdmRequestChallenge, None);

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used =
            self.encode_spdm_challenge(slot_id, measurement_summary_hash_type, &mut send_buffer)?;
        self.send_message(None, &send_buffer[..send_used], false)
            .await?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(None, &mut receive_buffer, true)
            .await?;
        self.handle_spdm_challenge_response(
            0, // NULL
            slot_id,
            measurement_summary_hash_type,
            &send_buffer[..send_used],
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_challenge(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        crypto::rand::get_random(&mut nonce)?;

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
            },
            payload: SpdmMessagePayload::SpdmChallengeRequest(SpdmChallengeRequestPayload {
                slot_id,
                measurement_summary_hash_type,
                nonce: SpdmNonceStruct { data: nonce },
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_challenge_response(
        &mut self,
        session_id: u32,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
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
                    SpdmRequestResponseCode::SpdmResponseChallengeAuth => {
                        let challenge_auth = SpdmChallengeAuthResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let used = reader.used();
                        if let Some(challenge_auth) = challenge_auth {
                            debug!("!!! challenge_auth : {:02x?}\n", challenge_auth);

                            // verify signature
                            let base_asym_size =
                                self.common.negotiate_info.base_asym_sel.get_size() as usize;
                            let temp_used = used - base_asym_size;

                            self.common.append_message_c(send_buffer)?;
                            self.common.append_message_c(&receive_buffer[..temp_used])?;

                            if self
                                .verify_challenge_auth_signature(slot_id, &challenge_auth.signature)
                                .is_err()
                            {
                                error!("verify_challenge_auth_signature fail");
                                self.common.reset_message_b();
                                self.common.reset_message_c();
                                return Err(SPDM_STATUS_VERIF_FAIL);
                            } else {
                                self.common.reset_message_b();
                                self.common.reset_message_c();
                                info!("verify_challenge_auth_signature pass");
                            }

                            Ok(())
                        } else {
                            error!("!!! challenge_auth : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestChallenge,
                            SpdmRequestResponseCode::SpdmResponseChallengeAuth,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn verify_challenge_auth_signature(
        &self,
        slot_id: u8,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let message_m1m2_hash = crypto::hash::hash_ctx_finalize(
            self.common
                .runtime_info
                .digest_context_m1m2
                .as_ref()
                .cloned()
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        debug!("message_m1m2_hash - {:02x?}", message_m1m2_hash.as_ref());

        if self.common.peer_info.peer_cert_chain[slot_id as usize].is_none() {
            error!("peer_cert_chain is not populated!\n");
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        let cert_chain_data = &self.common.peer_info.peer_cert_chain[slot_id as usize]
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];

        let mut message_sign = ManagedBuffer12Sign::default();

        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            message_sign.reset_message();
            message_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_4)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(&SPDM_CHALLENGE_AUTH_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(message_m1m2_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        } else {
            error!("hashed-transcript-data is unsupported in SPDM 1.0/1.1 signing verification!\n");
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            cert_chain_data,
            message_sign.as_ref(),
            signature,
        )
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn verify_challenge_auth_signature(
        &self,
        slot_id: u8,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let mut message_m1m2 = ManagedBufferM1M2::default();
        message_m1m2
            .append_message(self.common.runtime_info.message_a.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        message_m1m2
            .append_message(self.common.runtime_info.message_b.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        message_m1m2
            .append_message(self.common.runtime_info.message_c.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;

        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_m1m2_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            message_m1m2.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        debug!("message_m1m2_hash - {:02x?}", message_m1m2_hash.as_ref());

        if self.common.peer_info.peer_cert_chain[slot_id as usize].is_none() {
            error!("peer_cert_chain is not populated!\n");
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        let cert_chain_data = &self.common.peer_info.peer_cert_chain[slot_id as usize]
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];

        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            message_m1m2.reset_message();
            message_m1m2
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_m1m2
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_4)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_m1m2
                .append_message(&SPDM_CHALLENGE_AUTH_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_m1m2
                .append_message(message_m1m2_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            cert_chain_data,
            message_m1m2.as_ref(),
            signature,
        )
    }
}
