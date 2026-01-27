// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD};
use crate::message::*;
use crate::protocol::{SpdmVersion, SPDM_MAX_SLOT_NUMBER};
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_spdm_digest(
        &mut self,
        session_id: Option<u32>,
        send_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        info!("!!! send digest !!!");

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetDigests,
            session_id,
        );

        let send_used = self.encode_spdm_digest(send_buffer)?;

        self.send_message(session_id, &send_buffer[..send_used], false)
            .await?;

        Ok(send_used)
    }

    #[maybe_async::maybe_async]
    pub async fn receive_spdm_digest(
        &mut self,
        session_id: Option<u32>,
        send_buffer: &[u8],
    ) -> SpdmResult {
        info!("!!! receive digest !!!");
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(session_id, &mut receive_buffer, false)
            .await?;

        self.handle_spdm_digest_response(session_id, send_buffer, &receive_buffer[..used])
    }

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_digest(&mut self, session_id: Option<u32>) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used = self.send_spdm_digest(session_id, &mut send_buffer).await?;
        self.receive_spdm_digest(session_id, &send_buffer[..send_used])
            .await
    }

    pub fn encode_spdm_digest(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetDigests,
            },
            payload: SpdmMessagePayload::SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_digest_response(
        &mut self,
        session_id: Option<u32>,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseDigests => {
                        let digests =
                            SpdmDigestsResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let used = reader.used();
                        if let Some(digests) = digests {
                            debug!("!!! digests : {:02x?}\n", digests);

                            match session_id {
                                None => {
                                    self.common.append_message_b(send_buffer)?;
                                    self.common.append_message_b(&receive_buffer[..used])?;
                                }
                                Some(_session_id) => {}
                            }

                            self.common.peer_info.peer_provisioned_slot_mask = digests.slot_mask;
                            if self.common.negotiate_info.spdm_version_sel
                                >= SpdmVersion::SpdmVersion13
                            {
                                self.common.peer_info.peer_supported_slot_mask =
                                    digests.supported_slot_mask;
                            }

                            if self.common.negotiate_info.spdm_version_sel
                                >= SpdmVersion::SpdmVersion13
                                && self.common.negotiate_info.multi_key_conn_rsp
                            {
                                for slot_index in 0..SPDM_MAX_SLOT_NUMBER {
                                    if (digests.slot_mask & (1 << slot_index)) != 0 {
                                        self.common.peer_info.peer_key_pair_id[slot_index] =
                                            Some(digests.key_pair_id[slot_index]);
                                        self.common.peer_info.peer_cert_info[slot_index] =
                                            Some(digests.certificate_info[slot_index]);
                                        self.common.peer_info.peer_key_usage_bit_mask[slot_index] =
                                            Some(digests.key_usage_mask[slot_index]);
                                    }
                                }
                            }

                            Ok(())
                        } else {
                            error!("!!! digests : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            session_id,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestGetDigests,
                            SpdmRequestResponseCode::SpdmResponseDigests,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
