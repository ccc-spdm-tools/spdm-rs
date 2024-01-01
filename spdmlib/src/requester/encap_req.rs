// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::{
    common::SpdmCodec,
    config,
    error::{
        SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_MSG_SIZE,
        SPDM_STATUS_UNSUPPORTED_CAP,
    },
    message::{
        SpdmDeliverEncapsulatedResponsePayload, SpdmEncapsulatedRequestPayload,
        SpdmEncapsulatedResponseAckPayload, SpdmEncapsulatedResponseAckPayloadType, SpdmErrorCode,
        SpdmGetDigestsRequestPayload, SpdmGetEncapsulatedRequestPayload,
        SpdmKeyExchangeMutAuthAttributes, SpdmMessage, SpdmMessageHeader, SpdmMessagePayload,
        SpdmRequestResponseCode, ENCAPSULATED_RESPONSE_ACK_HEADER_SIZE,
    },
    protocol::{
        SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion, SPDM_MAX_SLOT_NUMBER,
    },
};

use super::RequesterContext;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn get_encapsulated_request_response(
        &mut self,
        session_id: u32,
        mut_auth_requested: SpdmKeyExchangeMutAuthAttributes,
    ) -> SpdmResult {
        if self.common.negotiate_info.spdm_version_sel < SpdmVersion::SpdmVersion11 {
            return Err(SPDM_STATUS_UNSUPPORTED_CAP);
        }

        if !self
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::ENCAP_CAP)
            || !self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::ENCAP_CAP)
        {
            return Err(SPDM_STATUS_UNSUPPORTED_CAP);
        }

        match mut_auth_requested {
            // Optimized session-based mutual authentication
            // When the Requester successfully receives a Session-Secrets-Exchange response with an included encapsulated
            // request (GET_DIGEST), the Requester shall send a DELIVER_ENCAPSULATED_RESPONSE after processing the encapsulated request.
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS => {
                let mut encapsulated_request = [0u8; 4];
                let mut writer = Writer::init(&mut encapsulated_request);
                let get_digest_request = SpdmMessage {
                    header: SpdmMessageHeader {
                        version: self.common.negotiate_info.spdm_version_sel,
                        request_response_code: SpdmRequestResponseCode::SpdmRequestGetDigests,
                    },
                    payload: SpdmMessagePayload::SpdmGetDigestsRequest(
                        SpdmGetDigestsRequestPayload {},
                    ),
                };
                let _ = get_digest_request.spdm_encode(&mut self.common, &mut writer)?;
                self.process_encapsulated_request(session_id, 0, &encapsulated_request)
                    .await?;
            }
            _ => {
                self.send_get_encapsulated_request(session_id).await?;
                self.receive_encapsulated_request(session_id).await?;
            }
        }

        while self.receive_encapsulated_response_ack(session_id).await? {}
        Ok(())
    }

    #[maybe_async::maybe_async]
    pub async fn send_get_encapsulated_request(&mut self, session_id: u32) -> SpdmResult {
        let mut send_buffer = [0u8; 4];
        let mut writer = Writer::init(&mut send_buffer);
        let get_encap_request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest,
            },
            payload: SpdmMessagePayload::SpdmGetEncapsulatedRequestPayload(
                SpdmGetEncapsulatedRequestPayload {},
            ),
        };
        let _ = get_encap_request.spdm_encode(&mut self.common, &mut writer)?;

        self.send_message(Some(session_id), writer.mut_used_slice(), false)
            .await
    }

    #[maybe_async::maybe_async]
    pub async fn receive_encapsulated_request(&mut self, session_id: u32) -> SpdmResult {
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let _ = self
            .receive_message(Some(session_id), &mut receive_buffer, false)
            .await?;
        let mut reader = Reader::init(&receive_buffer);

        let header = SpdmMessageHeader::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

        if self.common.negotiate_info.spdm_version_sel != header.version
            || header.request_response_code
                != SpdmRequestResponseCode::SpdmResponseEncapsulatedRequest
        {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        let encapsulated_request =
            SpdmEncapsulatedRequestPayload::spdm_read(&mut self.common, &mut reader)
                .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

        self.process_encapsulated_request(
            session_id,
            encapsulated_request.request_id,
            &receive_buffer[reader.used()..],
        )
        .await
    }

    #[maybe_async::maybe_async]
    pub async fn receive_encapsulated_response_ack(&mut self, session_id: u32) -> SpdmResult<bool> {
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let size = self
            .receive_message(Some(session_id), &mut receive_buffer, false)
            .await?;
        let mut reader = Reader::init(&receive_buffer);

        let header = SpdmMessageHeader::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

        if self.common.negotiate_info.spdm_version_sel != header.version
            || header.request_response_code
                != SpdmRequestResponseCode::SpdmResponseEncapsulatedResponseAck
        {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        let ack_header =
            SpdmEncapsulatedResponseAckPayload::spdm_read(&mut self.common, &mut reader)
                .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;

        match ack_header.payload_type {
            SpdmEncapsulatedResponseAckPayloadType::Absent => {
                if size == ENCAPSULATED_RESPONSE_ACK_HEADER_SIZE {
                    return Ok(false);
                } else {
                    return Err(SPDM_STATUS_INVALID_MSG_SIZE);
                }
            }
            SpdmEncapsulatedResponseAckPayloadType::Present => {}
            SpdmEncapsulatedResponseAckPayloadType::ReqSlotNumber => {
                if size == ENCAPSULATED_RESPONSE_ACK_HEADER_SIZE + 1 {
                    let req_slot_id = u8::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
                    if req_slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
                        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                    }
                    self.common
                        .runtime_info
                        .set_local_used_cert_chain_slot_id(req_slot_id);
                    return Ok(false);
                } else {
                    return Err(SPDM_STATUS_INVALID_MSG_SIZE);
                }
            }
            _ => {}
        }

        self.process_encapsulated_request(
            session_id,
            ack_header.request_id,
            &receive_buffer[reader.used()..],
        )
        .await?;

        Ok(true)
    }

    #[maybe_async::maybe_async]
    async fn process_encapsulated_request(
        &mut self,
        session_id: u32,
        request_id: u8,
        encap_request: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(encap_request);
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let message = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code:
                    SpdmRequestResponseCode::SpdmRequestDeliverEncapsulatedResponse,
            },
            payload: SpdmMessagePayload::SpdmDeliverEncapsulatedResponsePayload(
                SpdmDeliverEncapsulatedResponsePayload { request_id },
            ),
        };

        let _ = message.spdm_encode(&mut self.common, &mut writer)?;

        let encap_header =
            SpdmMessageHeader::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;
        match encap_header.request_response_code {
            crate::message::SpdmRequestResponseCode::SpdmRequestGetDigests => {
                self.encap_handle_get_digest(encap_request, &mut writer)
            }
            crate::message::SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                self.encap_handle_get_certificate(encap_request, &mut writer)
            }
            _ => self.encode_encap_error_response(
                SpdmErrorCode::SpdmErrorUnexpectedRequest,
                0,
                &mut writer,
            ),
        }

        self.send_message(Some(session_id), writer.used_slice(), false)
            .await
    }
}
