// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::opaque::{SpdmOpaqueStruct, MAX_SPDM_OPAQUE_SIZE};
#[cfg(feature = "hashed-transcript-data")]
use crate::common::ManagedBuffer12Sign;
#[cfg(not(feature = "hashed-transcript-data"))]
use crate::common::ManagedBufferM1M2;
use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::crypto;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::SPDM_STATUS_INVALID_STATE_PEER;
use crate::error::{SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR};
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
use crate::secret;

impl ResponderContext {
    pub fn handle_spdm_challenge<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (_, rsp_slice) = self.write_spdm_challenge_response(bytes, writer);
        (Ok(()), rsp_slice)
    }

    pub fn write_spdm_challenge_response<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
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
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        self.common
            .reset_buffer_via_request_code(SpdmRequestResponseCode::SpdmRequestChallenge, None);

        let measurement_summary_hash;
        let challenge = SpdmChallengeRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(challenge) = &challenge {
            debug!("!!! challenge : {:02x?}\n", challenge);

            if (challenge.measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
                || (challenge.measurement_summary_hash_type
                    == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
            {
                self.common.runtime_info.need_measurement_summary_hash = true;
                let measurement_summary_hash_res =
                    secret::measurement::generate_measurement_summary_hash(
                        self.common.negotiate_info.spdm_version_sel,
                        self.common.negotiate_info.base_hash_sel,
                        self.common.negotiate_info.measurement_specification_sel,
                        self.common.negotiate_info.measurement_hash_sel,
                        challenge.measurement_summary_hash_type,
                    );
                if measurement_summary_hash_res.is_none() {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                        Some(writer.used_slice()),
                    );
                }
                measurement_summary_hash = measurement_summary_hash_res.unwrap();
                if measurement_summary_hash.data_size == 0 {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                        Some(writer.used_slice()),
                    );
                }
            } else {
                self.common.runtime_info.need_measurement_summary_hash = false;
                measurement_summary_hash = SpdmDigestStruct::default();
            }
        } else {
            error!("!!! challenge : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        let challenge = challenge.unwrap();
        let slot_id = challenge.slot_id as usize;
        if slot_id >= SPDM_MAX_SLOT_NUMBER {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }
        if self.common.provision_info.my_cert_chain[slot_id].is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        if self
            .common
            .append_message_c(&bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        let my_cert_chain = self.common.provision_info.my_cert_chain[slot_id]
            .as_ref()
            .unwrap();
        let cert_chain_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            my_cert_chain.as_ref(),
        )
        .unwrap();

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        let res = crypto::rand::get_random(&mut nonce);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        info!("send spdm challenge_auth\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseChallengeAuth,
            },
            payload: SpdmMessagePayload::SpdmChallengeAuthResponse(
                SpdmChallengeAuthResponsePayload {
                    slot_id: slot_id as u8,
                    slot_mask: 0x1,
                    challenge_auth_attribute: SpdmChallengeAuthAttribute::empty(),
                    cert_chain_hash,
                    nonce: SpdmNonceStruct { data: nonce },
                    measurement_summary_hash,
                    opaque: SpdmOpaqueStruct {
                        data_size: 0,
                        data: [0u8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: self.common.negotiate_info.base_asym_sel.get_size(),
                        data: [0xbb; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
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

        // generat signature
        let base_asym_size = self.common.negotiate_info.base_asym_sel.get_size() as usize;
        let temp_used = used - base_asym_size;

        if self
            .common
            .append_message_c(&writer.used_slice()[..temp_used])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        let signature = self.generate_challenge_auth_signature();
        if signature.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }
        let signature = signature.unwrap();
        // patch the message before send
        writer.mut_used_slice()[(used - base_asym_size)..used].copy_from_slice(signature.as_ref());

        self.common.reset_message_b();
        self.common.reset_message_c();

        (Ok(()), Some(writer.used_slice()))
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn generate_challenge_auth_signature(&self) -> SpdmResult<SpdmSignatureStruct> {
        let message_m1m2_hash = crypto::hash::hash_ctx_finalize(
            self.common
                .runtime_info
                .digest_context_m1m2
                .as_ref()
                .cloned()
                .unwrap(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;

        debug!("message_m1m2_hash - {:02x?}", message_m1m2_hash.as_ref());

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
            error!("hashed-transcript-data is unsupported in SPDM 1.0/1.1 signing!\n");
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        crate::secret::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message_sign.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn generate_challenge_auth_signature(&self) -> SpdmResult<SpdmSignatureStruct> {
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

        crate::secret::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message_m1m2.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }
}
