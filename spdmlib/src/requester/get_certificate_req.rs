// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_CERT, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_STATE_LOCAL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_spdm_certificate(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        offset: u32,
        length: u32,
        send_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        info!("!!! send certificate !!!");
        let send_used =
            self.encode_spdm_certificate_partial(slot_id, offset, length, send_buffer)?;

        self.send_message(session_id, &send_buffer[..send_used], false)
            .await?;

        Ok(send_used)
    }

    #[maybe_async::maybe_async]
    pub async fn receive_spdm_certificate(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        total_size: u32,
        offset: u32,
        length: u32,
        send_buffer: &[u8],
    ) -> SpdmResult<(u32, u32)> {
        info!("!!! receive certificate !!!");
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(session_id, &mut receive_buffer, false)
            .await?;
        let used = self
            .spdm_handle_response_not_ready(
                session_id,
                SpdmRequestResponseCode::SpdmRequestGetCertificate,
                &mut receive_buffer,
                used,
                false,
            )
            .await?;

        self.handle_spdm_certificate_partial_response(
            session_id,
            slot_id,
            total_size,
            offset,
            length,
            send_buffer,
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_certificate_partial(
        &mut self,
        slot_id: u8,
        offset: u32,
        length: u32,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
            },
            payload: SpdmMessagePayload::SpdmGetCertificateRequest(
                SpdmGetCertificateRequestPayload {
                    slot_id,
                    offset,
                    length,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_spdm_certificate_partial_response(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        total_size: u32,
        offset: u32,
        length: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult<(u32, u32)> {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseCertificate => {
                        let certificate = SpdmCertificateResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let used = reader.used();
                        if let Some(certificate) = certificate {
                            debug!("!!! certificate : {:02x?}\n", certificate);

                            if certificate.portion_length == 0
                                || certificate.portion_length > length
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
                            if total_size != 0
                                && total_size
                                    != offset
                                        + certificate.portion_length
                                        + certificate.remainder_length
                            {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }
                            if certificate.slot_id != slot_id {
                                error!("slot id is not match between requester and responder!\n");
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }

                            let peer_cert_chain_temp = self
                                .common
                                .peer_info
                                .peer_cert_chain_temp
                                .as_mut()
                                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;

                            peer_cert_chain_temp.data[(offset as usize)
                                ..(offset as usize + certificate.portion_length as usize)]
                                .copy_from_slice(
                                    &certificate.cert_chain
                                        [0..(certificate.portion_length as usize)],
                                );

                            peer_cert_chain_temp.data_size = offset + certificate.portion_length;

                            match session_id {
                                None => {
                                    self.common.append_message_b(send_buffer)?;
                                    self.common.append_message_b(&receive_buffer[..used])?;
                                }
                                Some(_session_id) => {}
                            }

                            Ok((certificate.portion_length, certificate.remainder_length))
                        } else {
                            error!("!!! certificate : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let status = self.spdm_handle_error_response_main(
                            session_id,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestGetCertificate,
                            SpdmRequestResponseCode::SpdmResponseCertificate,
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

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_certificate(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
    ) -> SpdmResult {
        let mut offset = 0u32;
        let data_transfer_size = if self.common.config_info.data_transfer_size == 0 {
            config::SPDM_DATA_TRANSFER_SIZE as u32
        } else {
            self.common.config_info.data_transfer_size
        };
        let max_cert_portion_len = self
            .common
            .get_max_spdm_cert_portion_len(data_transfer_size);
        let mut length = max_cert_portion_len;
        let mut total_size = 0u32;

        if slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetCertificate,
            session_id,
        );

        self.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        while length != 0 {
            let send_used = self
                .send_spdm_certificate(session_id, slot_id, offset, length, &mut send_buffer)
                .await?;

            let (portion_length, remainder_length) = self
                .receive_spdm_certificate(
                    session_id,
                    slot_id,
                    total_size,
                    offset,
                    length,
                    &send_buffer[..send_used],
                )
                .await?;

            if total_size == 0 {
                total_size = portion_length + remainder_length;
            }
            offset += portion_length;
            length = remainder_length;
            if length > max_cert_portion_len {
                length = max_cert_portion_len;
            }
        }
        if total_size == 0 {
            self.common.peer_info.peer_cert_chain_temp = None;
            return Err(SPDM_STATUS_INVALID_CERT);
        }

        let result = self.verify_spdm_certificate_chain_for_slot(slot_id);
        if result.is_ok() {
            self.common.peer_info.peer_cert_chain[slot_id as usize] =
                self.common.peer_info.peer_cert_chain_temp.take();
        }
        self.common.peer_info.peer_cert_chain_temp = None;
        result
    }

    pub fn verify_spdm_certificate_chain(&mut self) -> SpdmResult {
        self.verify_spdm_certificate_chain_for_slot(0)
    }

    pub fn verify_spdm_certificate_chain_for_slot(&mut self, slot_id: u8) -> SpdmResult {
        self.common.verify_peer_certificate_chain(slot_id, false)
    }
}
