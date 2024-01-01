// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::{
    common::{SpdmCodec, SpdmConnectionState},
    error::{
        SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_MSG_FIELD,
        SPDM_STATUS_INVALID_MSG_SIZE, SPDM_STATUS_INVALID_STATE_LOCAL, SPDM_STATUS_NOT_READY_PEER,
        SPDM_STATUS_UNSUPPORTED_CAP,
    },
    message::{
        SpdmDeliverEncapsulatedResponsePayload, SpdmEncapsulatedRequestPayload,
        SpdmEncapsulatedResponseAckPayload, SpdmEncapsulatedResponseAckPayloadType, SpdmErrorCode,
        SpdmMessage, SpdmMessageHeader, SpdmMessagePayload, SpdmRequestResponseCode,
    },
    protocol::{SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion},
};

use super::ResponderContext;

impl ResponderContext {
    pub fn handle_get_encapsulated_request<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if self
            .encap_check_version_cap_state(
                SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest.get_u8(),
                writer,
            )
            .is_err()
        {
            (Ok(()), Some(writer.used_slice()))
        } else {
            let (_, rsp_slice) = self.write_encap_request_response(bytes, writer);
            (Ok(()), rsp_slice)
        }
    }

    fn write_encap_request_response<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let mut reader = Reader::init(bytes);
        if let Some(request_header) = SpdmMessageHeader::read(&mut reader) {
            if request_header.version != self.common.negotiate_info.spdm_version_sel {
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
        };

        let encapsulated_request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseEncapsulatedRequest,
            },
            payload: SpdmMessagePayload::SpdmEncapsulatedRequestPayload(
                SpdmEncapsulatedRequestPayload {
                    request_id: self.common.encap_context.request_id,
                },
            ),
        };

        if encapsulated_request
            .spdm_encode(&mut self.common, writer)
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        if self.encode_encap_request_get_digest(writer).is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidResponseCode, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }

    pub fn handle_deliver_encapsulated_reponse<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if let Err(err) = self.encap_check_version_cap_state(
            SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest.get_u8(),
            writer,
        ) {
            (Err(err), Some(writer.used_slice()))
        } else {
            self.write_encap_response_ack_response(bytes, writer)
        }
    }

    fn write_encap_response_ack_response<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let mut reader = Reader::init(bytes);
        if let Some(request_header) = SpdmMessageHeader::read(&mut reader) {
            if request_header.version != self.common.negotiate_info.spdm_version_sel {
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
        };

        let encap_response_payload = if let Some(encap_response_payload) =
            SpdmDeliverEncapsulatedResponsePayload::spdm_read(&mut self.common, &mut reader)
        {
            encap_response_payload
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        };

        if self
            .process_encapsulated_response(&encap_response_payload, &bytes[reader.used()..], writer)
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidResponseCode, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }

    fn encap_check_version_cap_state(
        &mut self,
        request_response_code: u8,
        writer: &mut Writer<'_>,
    ) -> SpdmResult {
        if self.common.negotiate_info.spdm_version_sel < SpdmVersion::SpdmVersion11 {
            self.write_spdm_error(
                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                request_response_code,
                writer,
            );
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
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
            self.write_spdm_error(
                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                request_response_code,
                writer,
            );
            return Err(SPDM_STATUS_UNSUPPORTED_CAP);
        }

        if self.common.runtime_info.get_connection_state().get_u8()
            < SpdmConnectionState::SpdmConnectionAfterCertificate.get_u8()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        Ok(())
    }

    fn process_encapsulated_response(
        &mut self,
        encap_response_payload: &SpdmDeliverEncapsulatedResponsePayload,
        encap_response: &[u8],
        encap_response_ack: &mut Writer,
    ) -> SpdmResult {
        let mut reader = Reader::init(encap_response);
        let deliver_encap_response = if let Some(header) = SpdmMessageHeader::read(&mut reader) {
            if header.version != self.common.negotiate_info.spdm_version_sel {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            header
        } else {
            return Err(SPDM_STATUS_INVALID_MSG_SIZE);
        };

        let header = SpdmMessageHeader {
            version: self.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmResponseEncapsulatedResponseAck,
        };
        let _ = header.encode(encap_response_ack);

        let mut ack_params = SpdmEncapsulatedResponseAckPayload {
            request_id: self.common.encap_context.request_id,
            payload_type: SpdmEncapsulatedResponseAckPayloadType::Present,
            ack_request_id: encap_response_payload.request_id,
        };

        match deliver_encap_response.request_response_code {
            SpdmRequestResponseCode::SpdmResponseDigests => {
                self.handle_encap_response_digest(encap_response)?;

                let _ = ack_params.spdm_encode(&mut self.common, encap_response_ack);
                self.encode_encap_requst_get_certificate(encap_response_ack)
            }
            SpdmRequestResponseCode::SpdmResponseCertificate => {
                match self.handle_encap_response_certificate(encap_response) {
                    Ok(need_continue) => {
                        if need_continue {
                            let _ = ack_params.spdm_encode(&mut self.common, encap_response_ack)?;
                            self.encode_encap_requst_get_certificate(encap_response_ack)
                        } else {
                            ack_params.payload_type =
                                SpdmEncapsulatedResponseAckPayloadType::ReqSlotNumber;
                            let _ = ack_params.spdm_encode(&mut self.common, encap_response_ack)?;
                            let _ = self
                                .common
                                .encap_context
                                .req_slot_id
                                .encode(encap_response_ack)
                                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
                            Ok(())
                        }
                    }
                    Err(e) => {
                        if e == SPDM_STATUS_NOT_READY_PEER {
                            ack_params.payload_type =
                                SpdmEncapsulatedResponseAckPayloadType::Absent;
                            let _ = ack_params.spdm_encode(&mut self.common, encap_response_ack)?;
                            Ok(())
                        } else {
                            Err(e)
                        }
                    }
                }
            }
            _ => Err(SPDM_STATUS_UNSUPPORTED_CAP),
        }
    }

    pub fn handle_encap_error_response_main(&self, error_code: u8) -> SpdmResult {
        if error_code == SpdmErrorCode::SpdmErrorResponseNotReady.get_u8() {
            return Err(SPDM_STATUS_NOT_READY_PEER);
        }

        Err(SPDM_STATUS_UNSUPPORTED_CAP)
    }
}
