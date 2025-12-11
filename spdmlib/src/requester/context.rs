// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[cfg(feature = "chunk-cap")]
use crate::common::SpdmCodec;
use crate::common::{self, SpdmDeviceIo, SpdmTransportEncap};
use crate::common::{ManagedBufferA, ST1};
use crate::config;
use crate::error::*;
#[cfg(any(feature = "chunk-cap", feature = "mut-auth"))]
use crate::message::*;
use crate::protocol::*;

#[cfg(feature = "chunk-cap")]
use codec::{Codec, Reader, Writer};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

pub struct RequesterContext {
    pub common: common::SpdmContext,
    pub send_buffer: Arc<Mutex<[u8; config::MAX_SPDM_MSG_SIZE]>>,
    pub receive_buffer: Arc<Mutex<[u8; config::MAX_SPDM_MSG_SIZE]>>,
}

impl RequesterContext {
    pub fn new(
        device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
        transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
        config_info: common::SpdmConfigInfo,
        provision_info: common::SpdmProvisionInfo,
    ) -> Self {
        RequesterContext {
            common: common::SpdmContext::new(
                device_io,
                transport_encap,
                config_info,
                provision_info,
            ),
            send_buffer: Arc::new(Mutex::new([0u8; config::MAX_SPDM_MSG_SIZE])),
            receive_buffer: Arc::new(Mutex::new([0u8; config::MAX_SPDM_MSG_SIZE])),
        }
    }

    #[maybe_async::maybe_async]
    pub async fn init_connection(
        &mut self,
        transcript_vca: &mut Option<ManagedBufferA>,
    ) -> SpdmResult {
        *transcript_vca = None;
        self.send_receive_spdm_version().await?;
        self.send_receive_spdm_capability().await?;
        self.send_receive_spdm_algorithm().await?;
        *transcript_vca = Some(self.common.runtime_info.message_a.clone());
        Ok(())
    }

    #[maybe_async::maybe_async]
    pub async fn start_session(
        &mut self,
        use_psk: bool,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult<u32> {
        if !use_psk {
            let session_id = self
                .send_receive_spdm_key_exchange(slot_id, measurement_summary_hash_type)
                .await?;
            #[cfg(not(feature = "mut-auth"))]
            let req_slot_id: Option<u8> = None;
            #[cfg(feature = "mut-auth")]
            let req_slot_id = {
                if self
                    .common
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::MUT_AUTH_CAP)
                    && self
                        .common
                        .negotiate_info
                        .req_capabilities_sel
                        .contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP)
                {
                    let session = self
                        .common
                        .get_session_via_id(session_id)
                        .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;
                    let mut_auth_requested = session.get_mut_auth_requested();
                    if mut_auth_requested == SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ {
                        if self.common.runtime_info.get_local_used_cert_chain_slot_id()
                            < SPDM_MAX_SLOT_NUMBER as u8
                        {
                            Some(self.common.runtime_info.get_local_used_cert_chain_slot_id())
                        } else if self.common.runtime_info.get_local_used_cert_chain_slot_id()
                            == SPDM_PUB_KEY_SLOT_ID_KEY_EXCHANGE_RSP
                        {
                            Some(SPDM_PUB_KEY_SLOT_ID_FINISH)
                        } else {
                            None
                        }
                    } else {
                        self.session_based_mutual_authenticate(session_id).await?;
                        Some(self.common.runtime_info.get_local_used_cert_chain_slot_id())
                    }
                } else {
                    None
                }
            };

            self.send_receive_spdm_finish(req_slot_id, session_id)
                .await?;
            Ok(session_id)
        } else {
            let session_id = self
                .send_receive_spdm_psk_exchange(measurement_summary_hash_type, None)
                .await?;
            self.send_receive_spdm_psk_finish(session_id).await?;
            Ok(session_id)
        }
    }

    #[maybe_async::maybe_async]
    pub async fn end_session(&mut self, session_id: u32) -> SpdmResult {
        self.send_receive_spdm_end_session(session_id).await
    }

    #[maybe_async::maybe_async]
    pub async fn send_message(
        &mut self,
        session_id: Option<u32>,
        send_buffer: &[u8],
        is_app_message: bool,
    ) -> SpdmResult {
        if self.common.negotiate_info.rsp_max_spdm_msg_size_sel != 0
            && send_buffer.len() > self.common.negotiate_info.rsp_max_spdm_msg_size_sel as usize
        {
            return Err(SPDM_STATUS_SEND_FAIL);
        }

        if send_buffer.len() > config::MAX_SPDM_MSG_SIZE {
            return Err(SPDM_STATUS_SEND_FAIL);
        }

        if is_app_message {
            self.send_single_message(session_id, send_buffer, is_app_message)
                .await
        } else if (self.common.negotiate_info.rsp_data_transfer_size_sel != 0
            && send_buffer.len() > self.common.negotiate_info.rsp_data_transfer_size_sel as usize)
            || send_buffer.len() > config::SPDM_SENDER_DATA_TRANSFER_SIZE
        {
            if self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::CHUNK_CAP)
                && self
                    .common
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::CHUNK_CAP)
                && self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12
            {
                // If the request is too large, we need to send it in chunks.
                #[cfg(feature = "chunk-cap")]
                {
                    self.common.chunk_req_handle =
                        self.common.chunk_req_handle.overflowing_add(1).0;
                    self.common.chunk_context.chunk_seq_num = 0;
                    self.common.chunk_context.chunk_message_size = send_buffer.len();
                    self.common.chunk_context.chunk_msg_data_mut()?[..send_buffer.len()]
                        .copy_from_slice(send_buffer);
                    self.common.chunk_context.transferred_size = 0;
                    self.common.chunk_context.chunk_status =
                        common::SpdmChunkStatus::ChunkSendAndAck;
                    let result = self.send_large_request(session_id, send_buffer).await;
                    if let Err(e) = result {
                        self.common.chunk_context.chunk_seq_num = 0;
                        self.common.chunk_context.chunk_message_size = 0;
                        self.common.chunk_context.chunk_msg_data_mut()?.fill(0);
                        self.common.chunk_context.transferred_size = 0;
                        self.common.chunk_context.chunk_status = common::SpdmChunkStatus::Idle;
                        Err(e)
                    } else {
                        result
                    }
                }
                #[cfg(not(feature = "chunk-cap"))]
                Err(SPDM_STATUS_SEND_FAIL)
            } else {
                error!("!!! send_message: chunking is not supported, resquest too large !!!\n");
                // If chunking is not supported, we cannot send the message.
                Err(SPDM_STATUS_SEND_FAIL)
            }
        } else {
            self.send_single_message(session_id, send_buffer, is_app_message)
                .await
        }
    }

    #[maybe_async::maybe_async]
    async fn send_single_message(
        &mut self,
        session_id: Option<u32>,
        send_buffer: &[u8],
        is_app_message: bool,
    ) -> SpdmResult {
        if (self.common.negotiate_info.rsp_data_transfer_size_sel != 0
            && send_buffer.len() > self.common.negotiate_info.rsp_data_transfer_size_sel as usize)
            || send_buffer.len() > config::SPDM_SENDER_DATA_TRANSFER_SIZE
        {
            return Err(SPDM_STATUS_SEND_FAIL);
        }

        if is_app_message && session_id.is_none() {
            return Err(SPDM_STATUS_SEND_FAIL);
        }

        let mut transport_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used = if let Some(session_id) = session_id {
            self.common
                .encode_secured_message(
                    session_id,
                    send_buffer,
                    &mut transport_buffer,
                    true,
                    is_app_message,
                )
                .await?
        } else {
            self.common
                .encap(send_buffer, &mut transport_buffer)
                .await?
        };

        let mut device_io = self.common.device_io.lock();
        let device_io: &mut (dyn SpdmDeviceIo + Send + Sync) = device_io.deref_mut();

        device_io.send(Arc::new(&transport_buffer[..used])).await
    }

    #[maybe_async::maybe_async]
    pub async fn receive_message(
        &mut self,
        session_id: Option<u32>,
        receive_buffer: &mut [u8],
        crypto_request: bool,
    ) -> SpdmResult<usize> {
        info!("receive_message!\n");

        #[cfg(not(feature = "chunk-cap"))]
        {
            self.receive_single_message(session_id, receive_buffer, crypto_request)
                .await
        }

        #[cfg(feature = "chunk-cap")]
        let len = if self.common.chunk_context.chunk_status
            == common::SpdmChunkStatus::ChunkSendAndAck
        {
            let response_size = self.common.chunk_context.transferred_size;
            receive_buffer[..response_size]
                .copy_from_slice(&self.common.chunk_context.chunk_msg_data_mut()?[..response_size]);
            self.common.chunk_context.chunk_seq_num = 0;
            self.common.chunk_context.chunk_message_size = 0;
            self.common.chunk_context.chunk_msg_data_mut()?.fill(0);
            self.common.chunk_context.transferred_size = 0;
            self.common.chunk_context.chunk_status = common::SpdmChunkStatus::Idle;
            Ok(response_size)
        } else {
            self.receive_single_message(session_id, receive_buffer, crypto_request)
                .await
        };

        #[cfg(feature = "chunk-cap")]
        {
            let mut reader = Reader::init(receive_buffer);
            match SpdmMessageHeader::read(&mut reader) {
                Some(message_header) => {
                    if message_header.request_response_code
                        == SpdmRequestResponseCode::SpdmResponseError
                    {
                        let spdm_message_general_payload =
                            SpdmMessageGeneralPayload::read(&mut reader);
                        if let Some(spdm_message_general_payload) = spdm_message_general_payload {
                            if spdm_message_general_payload.param1
                                == SpdmErrorCode::SpdmErrorLargeResponse.get_u8()
                            {
                                if !self
                                    .common
                                    .negotiate_info
                                    .rsp_capabilities_sel
                                    .contains(SpdmResponseCapabilityFlags::CHUNK_CAP)
                                    || !self
                                        .common
                                        .negotiate_info
                                        .req_capabilities_sel
                                        .contains(SpdmRequestCapabilityFlags::CHUNK_CAP)
                                {
                                    return Err(SPDM_STATUS_ERROR_PEER);
                                }
                                if message_header.version
                                    != self.common.negotiate_info.spdm_version_sel
                                    || message_header.version < SpdmVersion::SpdmVersion12
                                {
                                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                }
                                let handle = u8::read(&mut reader);
                                if let Some(handle) = handle {
                                    // Initialize the chunk context to receive large response
                                    self.common.chunk_rsp_handle = handle; // The handle of large response
                                    self.common.chunk_context.chunk_seq_num = 0;
                                    self.common.chunk_context.chunk_message_size = 0;
                                    self.common.chunk_context.chunk_msg_data_mut()?.fill(0);
                                    self.common.chunk_context.transferred_size = 0;
                                    self.common.chunk_context.chunk_status =
                                        common::SpdmChunkStatus::ChunkGetAndResponse;
                                    // Handle large response error
                                    let result = self
                                        .receive_large_response(session_id, crypto_request)
                                        .await;
                                    if let Err(e) = result {
                                        self.common.chunk_rsp_handle = 0;
                                        self.common.chunk_context.chunk_seq_num = 0;
                                        self.common.chunk_context.chunk_message_size = 0;
                                        self.common.chunk_context.chunk_msg_data_mut()?.fill(0);
                                        self.common.chunk_context.transferred_size = 0;
                                        self.common.chunk_context.chunk_status =
                                            common::SpdmChunkStatus::Idle;
                                        return Err(e);
                                    }
                                    let message_len = self.common.chunk_context.transferred_size;
                                    receive_buffer[..message_len].copy_from_slice(
                                        &self.common.chunk_context.chunk_msg_data_mut()?
                                            [..message_len],
                                    );

                                    self.common.chunk_rsp_handle = 0;
                                    self.common.chunk_context.chunk_seq_num = 0;
                                    self.common.chunk_context.chunk_message_size = 0;
                                    self.common.chunk_context.chunk_msg_data_mut()?.fill(0);
                                    self.common.chunk_context.transferred_size = 0;
                                    self.common.chunk_context.chunk_status =
                                        common::SpdmChunkStatus::Idle;

                                    // If we have received all chunks, we can process the large message data
                                    Ok(message_len)
                                } else {
                                    error!("!!! receive_large_response: handle not found !!!\n");
                                    Err(SPDM_STATUS_INVALID_MSG_SIZE)
                                }
                            } else {
                                // If the error is not a large response error, return the error for further process.
                                Ok(len?)
                            }
                        } else {
                            error!("!!! chunk send ack : spdm message general payload fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_SIZE)
                        }
                    } else {
                        // If the spdm message is not an error response, return the message.
                        Ok(len?)
                    }
                }
                None => {
                    // Receive message may receive app message, so return success even spdm message header is not found.
                    Ok(len?)
                }
            }
        }
    }

    #[maybe_async::maybe_async]
    async fn receive_single_message(
        &mut self,
        session_id: Option<u32>,
        receive_buffer: &mut [u8],
        crypto_request: bool,
    ) -> SpdmResult<usize> {
        let timeout: usize = if crypto_request {
            2 << self.common.negotiate_info.rsp_ct_exponent_sel
        } else {
            ST1
        };

        let mut transport_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        let used = {
            let mut device_io = self.common.device_io.lock();
            let device_io: &mut (dyn SpdmDeviceIo + Send + Sync) = device_io.deref_mut();

            device_io
                .receive(Arc::new(Mutex::new(&mut transport_buffer)), timeout)
                .await
                .map_err(|_| SPDM_STATUS_RECEIVE_FAIL)?
        };

        if let Some(session_id) = session_id {
            self.common
                .decode_secured_message(
                    session_id,
                    &transport_buffer[..used],
                    &mut receive_buffer[..config::SPDM_DATA_TRANSFER_SIZE],
                )
                .await
        } else {
            self.common
                .decap(
                    &transport_buffer[..used],
                    &mut receive_buffer[..config::SPDM_DATA_TRANSFER_SIZE],
                )
                .await
        }
    }

    #[cfg(feature = "chunk-cap")]
    #[maybe_async::maybe_async]
    async fn receive_large_response(
        &mut self,
        session_id: Option<u32>,
        crypto_request: bool,
    ) -> SpdmResult<usize> {
        loop {
            let mut send_buffer = [0u8; config::SENDER_BUFFER_SIZE];
            let mut writer = Writer::init(&mut send_buffer);

            let chunk_get_request = SpdmMessage {
                header: SpdmMessageHeader {
                    version: self.common.negotiate_info.spdm_version_sel,
                    request_response_code: SpdmRequestResponseCode::SpdmRequestChunkGet,
                },
                payload: SpdmMessagePayload::SpdmChunkGetRequest(SpdmChunkGetRequestPayload {
                    handle: self.common.chunk_rsp_handle,
                    chunk_seq_num: self.common.chunk_context.chunk_seq_num,
                }),
            };
            let used = chunk_get_request.spdm_encode(&mut self.common, &mut writer)?;
            self.send_single_message(None, &send_buffer[..used], false)
                .await?;

            let mut receive_buffer = [0u8; config::SPDM_DATA_TRANSFER_SIZE];
            let used = self
                .receive_single_message(None, &mut receive_buffer, crypto_request)
                .await?;

            self.handle_spdm_chunk_response(&receive_buffer[..used], session_id)
                .map_err(|_| SPDM_STATUS_RECEIVE_FAIL)?;

            if self.common.chunk_context.transferred_size
                >= self.common.chunk_context.chunk_message_size
            {
                return Ok(self.common.chunk_context.transferred_size);
            }
        }
    }

    #[cfg(feature = "chunk-cap")]
    fn handle_spdm_chunk_response(
        &mut self,
        receive_buffer: &[u8],
        session_id: Option<u32>,
    ) -> SpdmResult {
        let offset_of_response_of_large_request_in_chunk_send_ack =
            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
                SPDM_VERSION_1_4_OFFSET_OF_RESPONSE_OF_LARGE_REQUEST_IN_CHUNK_SEND_ACK
            } else {
                SPDM_VERSION_1_2_OFFSET_OF_RESPONSE_OF_LARGE_REQUEST_IN_CHUNK_SEND_ACK
            };
        let max_chunk_seq_num =
            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
                u32::MAX
            } else {
                u16::MAX as u32
            };
        let mut reader = Reader::init(receive_buffer);

        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseChunkResponse => {
                        let chunk_response =
                            SpdmChunkResponsePayload::spdm_read(&mut self.common, &mut reader);
                        if let Some(chunk_response) = chunk_response {
                            if chunk_response.handle != self.common.chunk_rsp_handle {
                                error!("!!! receive_large_response: handle mismatch !!!\n");
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }
                            if chunk_response.chunk_seq_num == 0
                                && self.common.chunk_context.chunk_seq_num == 0
                            {
                                if chunk_response.chunk_size < (config::SPDM_MIN_DATA_TRANSFER_SIZE -
                                    SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_RESPONSE) as u32
                                {
                                    error!("!!! receive_large_response: chunk size too small !!!\n");
                                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                };
                                if let Some(large_message_size) = chunk_response.large_message_size
                                {
                                    if large_message_size > config::MAX_SPDM_MSG_SIZE as u32 {
                                        error!("!!! receive_large_response: large message size exceeds max size !!!\n");
                                        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                    }
                                    // Check the large message size. Since the large message could be chunked because it
                                    // is in last chunk ack message, so it could be smaller than min data transfer size.
                                    if large_message_size
                                        < (config::SPDM_MIN_DATA_TRANSFER_SIZE
                                            - offset_of_response_of_large_request_in_chunk_send_ack)
                                            as u32
                                    {
                                        error!("!!! receive_large_response: large message size too small !!!\n");
                                        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                    }

                                    // Early check whether large message size is too large to be received in chunks.
                                    let data_transfer_size = config::SPDM_DATA_TRANSFER_SIZE;
                                    let max_large_response_size = (data_transfer_size
                                        - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_RESPONSE)
                                        * (u16::MAX as usize - 1)
                                        + data_transfer_size
                                        - offset_of_response_of_large_request_in_chunk_send_ack;
                                    if large_message_size as usize > max_large_response_size {
                                        error!("!!! receive_large_response: request too large to receive in chunks !!!\n");
                                        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                    }

                                    self.common.chunk_context.chunk_message_size =
                                        large_message_size as usize;
                                } else {
                                    error!("!!! receive_large_response: large message size not found !!!\n");
                                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                };
                                self.common.chunk_context.chunk_seq_num += 1;
                            } else if chunk_response.chunk_seq_num
                                == self.common.chunk_context.chunk_seq_num
                            {
                                if chunk_response.chunk_size
                                    < (config::SPDM_MIN_DATA_TRANSFER_SIZE
                                        - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_RESPONSE)
                                        as u32
                                    && !chunk_response
                                        .response_attributes
                                        .contains(SpdmChunkSenderAttributes::LAST_CHUNK)
                                {
                                    error!(
                                        "!!! receive_large_response: chunk size too small !!!\n"
                                    );
                                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                };
                                if self.common.chunk_context.chunk_seq_num < max_chunk_seq_num {
                                    self.common.chunk_context.chunk_seq_num += 1;
                                } else {
                                    error!(
                                        "!!! receive_large_response: chunk seq num overflow !!!\n"
                                    );
                                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                }
                            } else {
                                error!("!!! receive_large_response: chunk seq num mismatch !!!\n");
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }
                            if chunk_response
                                .response_attributes
                                .contains(SpdmChunkSenderAttributes::LAST_CHUNK)
                            {
                                if self.common.chunk_context.transferred_size
                                    != self.common.chunk_context.chunk_message_size
                                {
                                    error!("!!! receive_large_response: last chunk received but response size not match !!!\n");
                                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                }
                            } else if self.common.chunk_context.transferred_size
                                >= self.common.chunk_context.chunk_message_size
                            {
                                error!("!!! receive_large_response: transferred size reaches response size without last chunk not received !!!\n");
                                return Err(SPDM_STATUS_ERROR_PEER);
                            }
                        } else {
                            error!("!!! receive_large_response: invalid chunk response !!!\n");
                            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                        };
                        Ok(())
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            session_id,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestChunkSend,
                            SpdmRequestResponseCode::SpdmResponseChunkSendAck,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    #[cfg(feature = "chunk-cap")]
    #[maybe_async::maybe_async]
    async fn send_large_request(
        &mut self,
        session_id: Option<u32>,
        send_buffer: &[u8],
    ) -> SpdmResult {
        // Check and fail if the request is so large that it cannot be send in chunks
        let data_transfer_size = core::cmp::min(
            config::SPDM_SENDER_DATA_TRANSFER_SIZE,
            self.common.negotiate_info.rsp_data_transfer_size_sel as usize,
        );
        let max_large_request_size = (data_transfer_size
            - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_SEND)
            * (u16::MAX as usize - 1)
            + data_transfer_size
            - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_SEND;
        if send_buffer.len() > max_large_request_size {
            error!("!!! send_large_request: request too large to send in chunks !!!\n");
            return Err(SPDM_STATUS_SEND_FAIL);
        }

        while self.common.chunk_context.transferred_size
            < self.common.chunk_context.chunk_message_size
        {
            let mut send_buffer = [0u8; config::SENDER_BUFFER_SIZE];
            let mut writer = Writer::init(&mut send_buffer);

            let chunk_seq_num = self.common.chunk_context.chunk_seq_num;
            let max_chunk_size = if chunk_seq_num == 0 {
                data_transfer_size - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_SEND
            } else {
                data_transfer_size - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_SEND
            };
            let remaining_bytes = self.common.chunk_context.chunk_message_size
                - self.common.chunk_context.transferred_size;
            let (chunk_sender_attributes, chunk_size) = if remaining_bytes > max_chunk_size {
                (SpdmChunkSenderAttributes::default(), max_chunk_size as u32)
            } else {
                (
                    SpdmChunkSenderAttributes::LAST_CHUNK,
                    remaining_bytes as u32,
                )
            };
            let large_message_size = if chunk_seq_num == 0 {
                Some(self.common.chunk_context.chunk_message_size as u32)
            } else {
                None
            };

            let request = SpdmMessage {
                header: SpdmMessageHeader {
                    version: self.common.negotiate_info.spdm_version_sel,
                    request_response_code: SpdmRequestResponseCode::SpdmRequestChunkSend,
                },
                payload: SpdmMessagePayload::SpdmChunkSendRequest(SpdmChunkSendRequestPayload {
                    chunk_sender_attributes,
                    handle: self.common.chunk_req_handle,
                    chunk_seq_num,
                    chunk_size,
                    large_message_size,
                }),
            };
            let send_used = request.spdm_encode(&mut self.common, &mut writer)?;

            self.send_single_message(session_id, &send_buffer[..send_used], false)
                .await?;
            let mut receive_buffer = [0u8; config::SPDM_DATA_TRANSFER_SIZE];
            let used = self
                .receive_single_message(session_id, &mut receive_buffer, false)
                .await?;

            let mut early_error_detected = false;
            self.handle_spdm_chunk_send_ack_response(
                &receive_buffer[..used],
                &mut early_error_detected,
            )
            .map_err(|_| SPDM_STATUS_SEND_FAIL)?;
            if early_error_detected {
                // Early error detected and been saved to chunk_context, stop sending chunks.
                break;
            }
        }

        Ok(())
    }

    #[cfg(feature = "chunk-cap")]
    fn handle_spdm_chunk_send_ack_response(
        &mut self,
        receive_buffer: &[u8],
        early_error_detected: &mut bool,
    ) -> SpdmResult {
        let max_chunk_seq_num =
            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
                u32::MAX
            } else {
                u16::MAX as u32
            };
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseChunkSendAck => {
                        let chunk_send_ack = SpdmChunkSendAckResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        if let Some(chunk_send_ack) = chunk_send_ack {
                            if chunk_send_ack
                                .chunk_receiver_attributes
                                .contains(SpdmChunkReceiverAttributes::EARLY_ERROR_DETECTED)
                            {
                                let chunk_msg_data =
                                    self.common.chunk_context.chunk_msg_data_mut()?;
                                let mut reader = Reader::init(
                                    &chunk_msg_data
                                        [..chunk_send_ack.response_to_large_request_size],
                                );
                                return match SpdmMessageHeader::read(&mut reader) {
                                    Some(message_header) => {
                                        if message_header.request_response_code
                                            == SpdmRequestResponseCode::SpdmResponseError
                                            && message_header.version
                                                == self.common.negotiate_info.spdm_version_sel
                                        {
                                            let spdm_message_general_payload =
                                                SpdmMessageGeneralPayload::read(&mut reader)
                                                    .unwrap();
                                            if spdm_message_general_payload.param1
                                                != SpdmErrorCode::SpdmErrorLargeResponse.get_u8()
                                            {
                                                *early_error_detected = true;
                                                Ok(())
                                            } else {
                                                error!("!!! chunk send ack : early error detected but invalid error payload !!!\n");
                                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                            }
                                        } else {
                                            error!("!!! chunk send ack : early error detected but payload is not an error response !!!\n");
                                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                                        }
                                    }
                                    None => {
                                        error!("!!! chunk send ack : early error detected but invalid message received !!!\n");
                                        Err(SPDM_STATUS_INVALID_MSG_SIZE)
                                    }
                                };
                            }
                            if chunk_send_ack.handle != self.common.chunk_req_handle {
                                error!("!!! chunk send ack : handle mismatch !!!\n");
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }
                            if chunk_send_ack.chunk_seq_num
                                != self.common.chunk_context.chunk_seq_num
                            {
                                error!("!!! chunk send ack : chunk seq num mismatch !!!\n");
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            } else {
                                assert!(
                                    self.common.chunk_context.chunk_seq_num < max_chunk_seq_num
                                );
                                self.common.chunk_context.chunk_seq_num += 1;
                            }
                            Ok(())
                        } else {
                            error!("!!! chunk send ack : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let spdm_message_general_payload =
                            SpdmMessageGeneralPayload::read(&mut reader);
                        if let Some(spdm_message_general_payload) = spdm_message_general_payload {
                            if spdm_message_general_payload.param1
                                == SpdmErrorCode::SpdmErrorLargeResponse.get_u8()
                            {
                                // Store the large response error and let receive message to handle
                                let len = receive_buffer.len();
                                if len > config::RECEIVER_BUFFER_SIZE {
                                    error!("!!! chunk send ack : received large response error with unexpected size !!!\n");
                                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                }
                                self.common.chunk_context.chunk_msg_data_mut()?[..len]
                                    .copy_from_slice(&receive_buffer[..len]);
                                self.common.chunk_context.chunk_message_size = len;
                                self.common.chunk_context.transferred_size = len;
                                Ok(())
                            } else {
                                error!("!!! chunk send ack : error response received but error is not large response for chunk send !!!\n");
                                Err(SPDM_STATUS_INVALID_MSG_FIELD)
                            }
                        } else {
                            error!("!!! chunk send ack : spdm message general payload fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_ERROR_PEER),
        }
    }
}
