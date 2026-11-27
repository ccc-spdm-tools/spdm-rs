// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::{
    common::SpdmCodec,
    config,
    error::{
        SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_CERT,
        SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_MSG_SIZE,
        SPDM_STATUS_INVALID_STATE_LOCAL,
    },
    message::{
        SpdmCertificateResponsePayload, SpdmGetCertificateRequestPayload, SpdmMessage,
        SpdmMessageGeneralPayload, SpdmMessageHeader, SpdmMessagePayload, SpdmRequestResponseCode,
        DELIVER_ENCAPSULATED_RESPONSE_HEADER_SIZE, MAX_SPDM_CERT_PORTION_LEN,
    },
    protocol::SpdmCertChainBuffer,
};

use super::ResponderContext;

impl ResponderContext {
    pub fn encode_encap_requst_get_certificate(
        &mut self,
        encap_request: &mut Writer,
    ) -> SpdmResult {
        if self.common.peer_info.peer_cert_chain_temp.is_none() {
            self.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());
        }

        let data_transfer_size = if self.common.config_info.data_transfer_size == 0 {
            config::SPDM_DATA_TRANSFER_SIZE as u32
        } else {
            self.common.config_info.data_transfer_size
        };
        let max_cert_portion_len = self.common.get_max_spdm_cert_portion_len(
            data_transfer_size.saturating_sub(DELIVER_ENCAPSULATED_RESPONSE_HEADER_SIZE),
        );
        let encapsulated_request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
            },
            payload: SpdmMessagePayload::SpdmGetCertificateRequest(
                SpdmGetCertificateRequestPayload {
                    offset: self
                        .common
                        .peer_info
                        .peer_cert_chain_temp
                        .as_ref()
                        .unwrap()
                        .data_size,
                    length: max_cert_portion_len,
                    slot_id: self.common.encap_context.req_slot_id,
                },
            ),
        };

        let _ = encapsulated_request.spdm_encode(&mut self.common, encap_request)?;

        Ok(())
    }

    pub fn handle_encap_response_certificate(&mut self, encap_response: &[u8]) -> SpdmResult<bool> {
        let mut reader = Reader::init(encap_response);
        let mut get_cert_completed = false;
        match SpdmMessageHeader::read(&mut reader) {
            Some(encap_header) => {
                if encap_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match encap_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseCertificate => {
                        let certificate = SpdmCertificateResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        if let Some(certificate) = certificate {
                            debug!("!!! mut_auth certificate : {:02x?}\n", certificate);

                            let peer_cert_chain_temp = self
                                .common
                                .peer_info
                                .peer_cert_chain_temp
                                .as_mut()
                                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
                            let offset = peer_cert_chain_temp.data_size;

                            if certificate.portion_length as usize > MAX_SPDM_CERT_PORTION_LEN
                                || certificate.portion_length
                                    > config::MAX_SPDM_CERT_CHAIN_DATA_SIZE as u32 - offset
                            {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }
                            if certificate.remainder_length
                                >= config::MAX_SPDM_CERT_CHAIN_DATA_SIZE as u32
                                    - offset
                                    - certificate.portion_length
                            {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }

                            if certificate.slot_id != self.common.encap_context.req_slot_id {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }

                            if offset == 0 {
                                self.common.encap_context.encap_cert_size =
                                    certificate.portion_length + certificate.remainder_length;
                            }

                            if self.common.encap_context.encap_cert_size != 0
                                && self.common.encap_context.encap_cert_size
                                    != offset
                                        + certificate.portion_length
                                        + certificate.remainder_length
                            {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }

                            peer_cert_chain_temp.data[(offset as usize)
                                ..(offset as usize + certificate.portion_length as usize)]
                                .copy_from_slice(
                                    &certificate.cert_chain
                                        [0..(certificate.portion_length as usize)],
                                );

                            peer_cert_chain_temp.data_size = offset + certificate.portion_length;

                            if certificate.remainder_length == 0 {
                                get_cert_completed = true;
                            }
                        } else {
                            error!("!!! mut_auth certificate : fail !!!\n");
                            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let payload = SpdmMessageGeneralPayload::read(&mut reader)
                            .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
                        self.handle_encap_error_response_main(payload.param1)?;
                    }
                    _ => return Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => return Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
        if self.common.encap_context.encap_cert_size == 0 {
            self.common.peer_info.peer_cert_chain_temp = None;
            return Err(SPDM_STATUS_INVALID_CERT);
        }

        if !get_cert_completed {
            return Ok(true);
        }

        let result = self.verify_spdm_certificate_chain().map(|_| {
            self.common.peer_info.peer_cert_chain[self.common.encap_context.req_slot_id as usize] =
                self.common.peer_info.peer_cert_chain_temp.take();
            false
        });

        self.common.peer_info.peer_cert_chain_temp = None;

        #[cfg(feature = "mandatory-mut-auth")]
        if result.is_ok() {
            self.common.mut_auth_done = true;
        }

        result
    }

    pub fn verify_spdm_certificate_chain(&mut self) -> SpdmResult {
        self.common
            .verify_peer_certificate_chain(self.common.encap_context.req_slot_id, true)
    }
}
