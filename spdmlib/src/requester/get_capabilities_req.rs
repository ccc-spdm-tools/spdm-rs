// Copyright (c) 2020, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_NOT_READY_PEER,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_spdm_capability(&mut self, send_buffer: &mut [u8]) -> SpdmResult<usize> {
        info!("!!! send capability !!!");
        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            None,
        );

        let send_used = self.encode_spdm_capability(send_buffer)?;
        self.send_message(None, &send_buffer[..send_used], false)
            .await?;
        Ok(send_used)
    }

    #[maybe_async::maybe_async]
    pub async fn receive_spdm_capability(&mut self, send_buffer: &[u8]) -> SpdmResult {
        info!("!!! receive capability !!!");
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut used = self
            .receive_message(None, &mut receive_buffer, false)
            .await?;

        for _ in 0..super::handle_error_response_req::MAX_RESPOND_IF_READY_RETRY_COUNT {
            let result =
                self.handle_spdm_capability_response(0, send_buffer, &receive_buffer[..used]);
            match result {
                Err(status) if status == SPDM_STATUS_NOT_READY_PEER => {
                    if let Some(ext_data) =
                        self.parse_response_not_ready_ext_data(&receive_buffer[..used])
                    {
                        let delay_us = 1usize << (ext_data.rdt_exponent as usize).min(31);
                        crate::time::sleep(delay_us);
                        used = self
                            .send_receive_respond_if_ready(
                                None,
                                SpdmRequestResponseCode::SpdmRequestGetCapabilities,
                                ext_data.token,
                                &mut receive_buffer,
                                false,
                            )
                            .await?;
                        continue;
                    }
                    return Err(SPDM_STATUS_NOT_READY_PEER);
                }
                other => return other,
            }
        }
        Err(SPDM_STATUS_NOT_READY_PEER)
    }

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_capability(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used = self.send_spdm_capability(&mut send_buffer).await?;
        self.receive_spdm_capability(&send_buffer[..send_used])
            .await
    }

    pub fn encode_spdm_capability(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            },
            payload: SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                SpdmGetCapabilitiesRequestPayload {
                    ct_exponent: self.common.config_info.req_ct_exponent,
                    flags: self.common.config_info.req_capabilities,
                    data_transfer_size: self.common.config_info.data_transfer_size,
                    max_spdm_msg_size: self.common.config_info.max_spdm_msg_size,
                    ex_flags: SpdmRequestCapabilityExFlags::default(),
                    supported_algos_requested: self
                        .common
                        .config_info
                        .req_capabilities
                        .contains(SpdmRequestCapabilityFlags::CHUNK_CAP)
                        && self.common.config_info.supported_algos_ext_cap,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    /// Consume the SupportedAlgorithms block that the Responder returned in its CAPABILITIES
    /// response (DSP0274 1.3+ SUPPORTED_ALGOS_EXT_CAP). Returns `None` if the Requester did not
    /// request it, the Responder did not support it, or GET_CAPABILITIES has not completed yet.
    ///
    /// The Requester can use this to learn the Responder's supported algorithms before sending
    /// NEGOTIATE_ALGORITHMS, e.g. to pre-select mutually supported algorithms.
    pub fn get_peer_supported_algorithms(&self) -> Option<&SpdmSupportedAlgorithmsBlock> {
        self.common.peer_info.peer_supported_algorithms.as_ref()
    }

    pub fn handle_spdm_capability_response(
        &mut self,
        session_id: u32,
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
                    SpdmRequestResponseCode::SpdmResponseCapabilities => {
                        let capabilities = SpdmCapabilitiesResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let used = reader.used();
                        if let Some(capabilities) = capabilities {
                            debug!("!!! capabilities : {:02x?}\n", capabilities);
                            self.common.negotiate_info.req_ct_exponent_sel =
                                self.common.config_info.req_ct_exponent;
                            self.common.negotiate_info.req_capabilities_sel =
                                self.common.config_info.req_capabilities;
                            self.common.negotiate_info.rsp_ct_exponent_sel =
                                capabilities.ct_exponent;
                            self.common.negotiate_info.rsp_capabilities_sel = capabilities.flags;

                            // spdm 1.3: store the Responder's SupportedAlgorithms block (if it
                            // included one) so the caller can consume it via
                            // get_peer_supported_algorithms before NEGOTIATE_ALGORITHMS.
                            self.common.peer_info.peer_supported_algorithms =
                                capabilities.supported_algorithms;

                            if self.common.negotiate_info.spdm_version_sel
                                >= SpdmVersion::SpdmVersion12
                            {
                                self.common.negotiate_info.req_data_transfer_size_sel =
                                    self.common.config_info.data_transfer_size;
                                self.common.negotiate_info.req_max_spdm_msg_size_sel =
                                    self.common.config_info.max_spdm_msg_size;
                                self.common.negotiate_info.rsp_data_transfer_size_sel =
                                    capabilities.data_transfer_size;
                                self.common.negotiate_info.rsp_max_spdm_msg_size_sel =
                                    capabilities.max_spdm_msg_size;
                            }

                            self.common.append_message_a(send_buffer)?;
                            self.common.append_message_a(&receive_buffer[..used])?;

                            Ok(())
                        } else {
                            error!("!!! capabilities : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
                            SpdmRequestResponseCode::SpdmResponseCapabilities,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
