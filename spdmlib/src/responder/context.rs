// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::app_message_handler::dispatch_secured_app_message_cb;
#[cfg(feature = "chunk-cap")]
use crate::common::{self, SpdmCodec};
use crate::common::{session::SpdmSessionState, SpdmDeviceIo, SpdmTransportEncap};
use crate::common::{SpdmConnectionState, ST1};
use crate::config;
use crate::error::*;
use crate::message::*;
use crate::protocol::{SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags};
use crate::watchdog::{reset_watchdog, start_watchdog};
use codec::{Codec, Reader, Writer};
extern crate alloc;
use core::ops::DerefMut;

#[cfg(feature = "chunk-cap")]
use crate::protocol::SpdmVersion;

use alloc::sync::Arc;
use spin::Mutex;

pub struct ResponderContext {
    pub common: crate::common::SpdmContext,
    pub send_buffer: Arc<Mutex<[u8; config::MAX_SPDM_MSG_SIZE]>>,
    pub receive_buffer: Arc<Mutex<[u8; config::RECEIVER_BUFFER_SIZE]>>,
}

impl ResponderContext {
    pub fn new(
        device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
        transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
        config_info: crate::common::SpdmConfigInfo,
        provision_info: crate::common::SpdmProvisionInfo,
    ) -> Self {
        ResponderContext {
            common: crate::common::SpdmContext::new(
                device_io,
                transport_encap,
                config_info,
                provision_info,
            ),
            send_buffer: Arc::new(Mutex::new([0u8; config::MAX_SPDM_MSG_SIZE])),
            receive_buffer: Arc::new(Mutex::new([0u8; config::RECEIVER_BUFFER_SIZE])),
        }
    }

    #[maybe_async::maybe_async]
    pub async fn send_message(
        &mut self,
        session_id: Option<u32>,
        send_buffer: &[u8],
        is_app_message: bool,
    ) -> SpdmResult {
        let mut err_buffer = [0u8; config::SPDM_SENDER_DATA_TRANSFER_SIZE];
        let mut writer = Writer::init(&mut err_buffer);

        let send_buffer = if self.common.negotiate_info.req_max_spdm_msg_size_sel != 0
            && (send_buffer.len() > self.common.negotiate_info.req_max_spdm_msg_size_sel as usize)
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorResponseTooLarge, 0, &mut writer);
            writer.used_slice()
        } else if is_app_message && session_id.is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorSessionRequired, 0, &mut writer);
            writer.used_slice()
        } else if (self.common.negotiate_info.req_data_transfer_size_sel != 0
            && (send_buffer.len() > self.common.negotiate_info.req_data_transfer_size_sel as usize))
            || send_buffer.len() > config::SPDM_SENDER_DATA_TRANSFER_SIZE
        {
            #[cfg(feature = "chunk-cap")]
            if self
                .common
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::CHUNK_CAP)
                && self
                    .common
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::CHUNK_CAP)
            {
                self.common.chunk_rsp_handle = self.common.chunk_rsp_handle.overflowing_add(1).0;
                self.common.chunk_context.chunk_seq_num = 0;
                self.common.chunk_context.chunk_message_size = send_buffer.len();
                self.common.chunk_context.chunk_message_data[..send_buffer.len()]
                    .copy_from_slice(send_buffer);
                self.common.chunk_context.transferred_size = 0;
                self.common.chunk_context.chunk_status =
                    common::SpdmChunkStatus::ChunkGetAndResponse;
                self.write_spdm_error(SpdmErrorCode::SpdmErrorLargeResponse, 0, &mut writer);
                let _ = self.common.chunk_rsp_handle.encode(&mut writer);
                writer.used_slice()
            } else {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorResponseTooLarge, 0, &mut writer);
                writer.used_slice()
            }
            #[cfg(not(feature = "chunk-cap"))]
            {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorResponseTooLarge, 0, &mut writer);
                writer.used_slice()
            }
        } else {
            send_buffer
        };

        let mut transport_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used = if let Some(session_id) = session_id {
            self.common
                .encode_secured_message(
                    session_id,
                    send_buffer,
                    &mut transport_buffer,
                    false,
                    is_app_message,
                )
                .await?
        } else {
            self.common
                .encap(send_buffer, &mut transport_buffer)
                .await?
        };

        {
            let mut device_io = self.common.device_io.lock();
            let device_io: &mut (dyn SpdmDeviceIo + Send + Sync) = device_io.deref_mut();
            device_io.send(Arc::new(&transport_buffer[..used])).await?;
        }

        #[allow(unused_mut)]
        let mut opcode = send_buffer[1];
        #[cfg(feature = "chunk-cap")]
        if self.common.chunk_context.chunk_status == common::SpdmChunkStatus::ChunkSendAndAck {
            if self.common.chunk_context.transferred_size
                == self.common.chunk_context.chunk_message_size
            {
                opcode = self.common.chunk_context.chunk_message_data[1];
                self.common.chunk_context.chunk_seq_num = 0;
                self.common.chunk_context.chunk_message_size = 0;
                self.common.chunk_context.chunk_message_data.fill(0);
                self.common.chunk_context.transferred_size = 0;
                self.common.chunk_context.chunk_status = common::SpdmChunkStatus::Idle;
            }
        } else if self.common.chunk_context.chunk_status
            == common::SpdmChunkStatus::ChunkGetAndResponse
            && self.common.chunk_context.transferred_size
                == self.common.chunk_context.chunk_message_size
        {
            opcode = self.common.chunk_context.chunk_message_data[1];
            self.common.chunk_context.chunk_seq_num = 0;
            self.common.chunk_context.chunk_message_size = 0;
            self.common.chunk_context.chunk_message_data.fill(0);
            self.common.chunk_context.transferred_size = 0;
            self.common.chunk_context.chunk_status = common::SpdmChunkStatus::Idle;
        }
        if opcode == SpdmRequestResponseCode::SpdmResponseVersion.get_u8() {
            self.common
                .runtime_info
                .set_connection_state(SpdmConnectionState::SpdmConnectionAfterVersion);
        } else if opcode == SpdmRequestResponseCode::SpdmResponseCapabilities.get_u8() {
            self.common
                .runtime_info
                .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);
        } else if opcode == SpdmRequestResponseCode::SpdmResponseAlgorithms.get_u8() {
            self.common
                .runtime_info
                .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);
        } else if opcode == SpdmRequestResponseCode::SpdmResponseDigests.get_u8() {
            if self.common.runtime_info.get_connection_state().get_u8()
                < SpdmConnectionState::SpdmConnectionAfterDigest.get_u8()
            {
                self.common
                    .runtime_info
                    .set_connection_state(SpdmConnectionState::SpdmConnectionAfterDigest);
            }
        } else if opcode == SpdmRequestResponseCode::SpdmResponseCertificate.get_u8() {
            if self.common.runtime_info.get_connection_state().get_u8()
                < SpdmConnectionState::SpdmConnectionAfterCertificate.get_u8()
            {
                self.common
                    .runtime_info
                    .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCertificate);
            }
        } else if opcode == SpdmRequestResponseCode::SpdmResponseChallengeAuth.get_u8() {
            self.common
                .runtime_info
                .set_connection_state(SpdmConnectionState::SpdmConnectionAuthenticated);
        } else if opcode == SpdmRequestResponseCode::SpdmResponseFinishRsp.get_u8()
            && session_id.is_none()
        {
            let session_id =
                if let Some(session_id) = self.common.runtime_info.get_last_session_id() {
                    session_id
                } else {
                    return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
                };

            let heartbeat_period = {
                let session = self
                    .common
                    .get_session_via_id(session_id)
                    .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
                session.set_session_state(
                    crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                );

                session.heartbeat_period
            };

            if self
                .common
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::HBEAT_CAP)
                && self
                    .common
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::HBEAT_CAP)
            {
                start_watchdog(session_id, heartbeat_period as u16 * 2);
            }

            self.common.runtime_info.set_last_session_id(None);
        } else if opcode == SpdmRequestResponseCode::SpdmResponseEndSessionAck.get_u8() {
            let session = self
                .common
                .get_session_via_id(session_id.unwrap())
                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
            session.teardown();
        } else if (opcode == SpdmRequestResponseCode::SpdmResponseFinishRsp.get_u8()
            || opcode == SpdmRequestResponseCode::SpdmResponsePskFinishRsp.get_u8())
            && session_id.is_some()
        {
            #[allow(clippy::unnecessary_unwrap)]
            let session_id = session_id.unwrap();

            let heartbeat_period = {
                let session = self
                    .common
                    .get_session_via_id(session_id)
                    .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
                session.set_session_state(
                    crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                );

                session.heartbeat_period
            };

            if self
                .common
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::HBEAT_CAP)
                && self
                    .common
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::HBEAT_CAP)
            {
                start_watchdog(session_id, heartbeat_period as u16 * 2);
            }
        }

        Ok(())
    }

    #[maybe_async::maybe_async]
    pub async fn process_message(
        &mut self,
        crypto_request: bool,
        app_handle: usize, // interpreted/managed by User
    ) -> Result<SpdmResult, usize> {
        let response_buffer_arc = self.send_buffer.clone();
        let mut response_buffer = response_buffer_arc.try_lock().ok_or(0_usize)?;
        let mut writer = Writer::init(&mut response_buffer[..]);
        let req_buffer_arc = self.receive_buffer.clone();
        let mut request_buffer = req_buffer_arc.try_lock().ok_or(0_usize)?;

        match self
            .receive_message(&mut request_buffer[..], crypto_request)
            .await
        {
            Ok((used, secured_message)) => {
                if secured_message {
                    let mut read = Reader::init(&request_buffer[0..used]);
                    let session_id = u32::read(&mut read).ok_or(used)?;

                    let spdm_session = self.common.get_session_via_id(session_id).ok_or(used)?;

                    let mut app_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

                    let decode_size = spdm_session.decode_spdm_secured_message(
                        &request_buffer[..used],
                        &mut app_buffer,
                        true,
                    );
                    if decode_size.is_err() {
                        return Err(used);
                    }
                    let decode_size = decode_size.unwrap();

                    let mut spdm_buffer = [0u8; config::SPDM_DATA_TRANSFER_SIZE];
                    let decap_result = {
                        let mut transport_encap = self.common.transport_encap.lock();
                        let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
                            transport_encap.deref_mut();
                        transport_encap
                            .decap_app(
                                Arc::new(&app_buffer[0..decode_size]),
                                Arc::new(Mutex::new(&mut spdm_buffer)),
                            )
                            .await
                    };
                    match decap_result {
                        Err(_) => Err(used),
                        Ok((decode_size, is_app_message)) => {
                            // reset watchdog in any session messages.
                            if self
                                .common
                                .negotiate_info
                                .req_capabilities_sel
                                .contains(SpdmRequestCapabilityFlags::HBEAT_CAP)
                                && self
                                    .common
                                    .negotiate_info
                                    .rsp_capabilities_sel
                                    .contains(SpdmResponseCapabilityFlags::HBEAT_CAP)
                            {
                                reset_watchdog(session_id);
                            }

                            if !is_app_message {
                                // If responder is expecting chunk_get or chunk_send requests and gets
                                // other requests instead, drop out of chunking mode.
                                #[cfg(feature = "chunk-cap")]
                                {
                                    let mut reader = Reader::init(&spdm_buffer[0..decode_size]);
                                    match SpdmMessageHeader::read(&mut reader) {
                                        Some(message_header) => {
                                            if self.common.chunk_context.chunk_status
                                                == common::SpdmChunkStatus::ChunkSendAndAck
                                                && message_header.request_response_code
                                                    != SpdmRequestResponseCode::SpdmRequestChunkSend
                                            {
                                                self.common.chunk_req_handle = 0;
                                                self.common.chunk_context.chunk_seq_num = 0;
                                                self.common.chunk_context.chunk_message_size = 0;
                                                self.common
                                                    .chunk_context
                                                    .chunk_message_data
                                                    .fill(0);
                                                self.common.chunk_context.transferred_size = 0;
                                                self.common.chunk_context.chunk_status =
                                                    common::SpdmChunkStatus::Idle;
                                            }
                                            if self.common.chunk_context.chunk_status
                                                == common::SpdmChunkStatus::ChunkGetAndResponse
                                                && message_header.request_response_code
                                                    != SpdmRequestResponseCode::SpdmRequestChunkGet
                                            {
                                                self.common.chunk_rsp_handle = self
                                                    .common
                                                    .chunk_rsp_handle
                                                    .overflowing_add(1)
                                                    .0;
                                                self.common.chunk_context.chunk_seq_num = 0;
                                                self.common.chunk_context.chunk_message_size = 0;
                                                self.common
                                                    .chunk_context
                                                    .chunk_message_data
                                                    .fill(0);
                                                self.common.chunk_context.transferred_size = 0;
                                                self.common.chunk_context.chunk_status =
                                                    common::SpdmChunkStatus::Idle;
                                            }
                                        }
                                        None => {
                                            return Ok(Err(SPDM_STATUS_UNSUPPORTED_CAP));
                                        }
                                    }
                                }
                                let (status, send_buffer) = self.dispatch_secured_message(
                                    session_id,
                                    &spdm_buffer[0..decode_size],
                                    &mut writer,
                                );
                                if let Some(send_buffer) = send_buffer {
                                    if let Err(err) = self
                                        .send_message(Some(session_id), send_buffer, false)
                                        .await
                                    {
                                        Ok(Err(err))
                                    } else {
                                        Ok(status)
                                    }
                                } else {
                                    Ok(status)
                                }
                            } else {
                                let (status, send_buffer) = self.dispatch_secured_app_message(
                                    session_id,
                                    &spdm_buffer[..decode_size],
                                    app_handle,
                                    &mut writer,
                                );
                                if let Some(send_buffer) = send_buffer {
                                    if let Err(err) =
                                        self.send_message(Some(session_id), send_buffer, true).await
                                    {
                                        Ok(Err(err))
                                    } else {
                                        Ok(status)
                                    }
                                } else {
                                    Ok(status)
                                }
                            }
                        }
                    }
                } else {
                    // Chunk re-send not supported, so if responder is expecting chunk_send or chunk_get requests and gets
                    // other requests, it will return error.
                    #[cfg(feature = "chunk-cap")]
                    {
                        let mut reader = Reader::init(&request_buffer[0..used]);
                        match SpdmMessageHeader::read(&mut reader) {
                            Some(message_header) => {
                                if self.common.chunk_context.chunk_status
                                    == common::SpdmChunkStatus::ChunkSendAndAck
                                    && message_header.request_response_code
                                        != SpdmRequestResponseCode::SpdmRequestChunkSend
                                {
                                    self.common.chunk_req_handle = 0;
                                    self.common.chunk_context.chunk_seq_num = 0;
                                    self.common.chunk_context.chunk_message_size = 0;
                                    self.common.chunk_context.chunk_message_data.fill(0);
                                    self.common.chunk_context.transferred_size = 0;
                                    self.common.chunk_context.chunk_status =
                                        common::SpdmChunkStatus::Idle;
                                }
                                if self.common.chunk_context.chunk_status
                                    == common::SpdmChunkStatus::ChunkGetAndResponse
                                    && message_header.request_response_code
                                        != SpdmRequestResponseCode::SpdmRequestChunkGet
                                {
                                    self.common.chunk_rsp_handle =
                                        self.common.chunk_rsp_handle.overflowing_add(1).0;
                                    self.common.chunk_context.chunk_seq_num = 0;
                                    self.common.chunk_context.chunk_message_size = 0;
                                    self.common.chunk_context.chunk_message_data.fill(0);
                                    self.common.chunk_context.transferred_size = 0;
                                    self.common.chunk_context.chunk_status =
                                        common::SpdmChunkStatus::Idle;
                                }
                            }
                            None => {
                                return Ok(Err(SPDM_STATUS_UNSUPPORTED_CAP));
                            }
                        }
                    }
                    let (status, send_buffer) =
                        self.dispatch_message(&request_buffer[0..used], &mut writer);
                    if let Some(send_buffer) = send_buffer {
                        if let Err(err) = self.send_message(None, send_buffer, false).await {
                            Ok(Err(err))
                        } else {
                            Ok(status)
                        }
                    } else {
                        Ok(status)
                    }
                }
            }
            Err(used) => Err(used),
        }
    }

    // Debug note: receive_buffer is used as return value, when receive got a command
    // whose value is not normal, will return Err to caller to handle the raw packet,
    // So can't swap transport_buffer and receive_buffer, even though it should be by
    // their name suggestion. (03.01.2022)
    #[maybe_async::maybe_async]
    async fn receive_message(
        &mut self,
        receive_buffer: &mut [u8],
        crypto_request: bool,
    ) -> Result<(usize, bool), usize> {
        info!("receive_message!\n");

        let timeout: usize = if crypto_request {
            2 << self.common.negotiate_info.req_ct_exponent_sel
        } else {
            ST1
        };

        let mut transport_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        let used = {
            let mut device_io = self.common.device_io.lock();
            let device_io: &mut (dyn SpdmDeviceIo + Send + Sync) = device_io.deref_mut();
            device_io
                .receive(Arc::new(Mutex::new(receive_buffer)), timeout)
                .await?
        };

        let (used, secured_message) = {
            let mut transport_encap = self.common.transport_encap.lock();
            let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
                transport_encap.deref_mut();
            transport_encap
                .decap(
                    Arc::new(&receive_buffer[..used]),
                    Arc::new(Mutex::new(&mut transport_buffer)),
                )
                .await
                .map_err(|_| used)?
        };

        receive_buffer[..used].copy_from_slice(&transport_buffer[..used]);
        Ok((used, secured_message))
    }

    fn dispatch_secured_message<'a>(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let mut reader = Reader::init(bytes);

        let session = self.common.get_immutable_session_via_id(session_id);
        if session.is_none() {
            return (Err(SPDM_STATUS_UNSUPPORTED_CAP), None);
        }
        let session = session.unwrap();

        match session.get_session_state() {
            SpdmSessionState::SpdmSessionHandshaking => {
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
                if in_clear_text {
                    return (Err(SPDM_STATUS_UNSUPPORTED_CAP), None);
                }

                match SpdmMessageHeader::read(&mut reader) {
                    Some(message_header) => match message_header.request_response_code {
                        #[cfg(feature = "mut-auth")]
                        SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest => {
                            self.handle_get_encapsulated_request(bytes, writer)
                        }
                        #[cfg(feature = "mut-auth")]
                        SpdmRequestResponseCode::SpdmRequestDeliverEncapsulatedResponse => {
                            self.handle_deliver_encapsulated_reponse(bytes, writer)
                        }
                        SpdmRequestResponseCode::SpdmRequestFinish => {
                            self.handle_spdm_finish(session_id, bytes, writer)
                        }

                        SpdmRequestResponseCode::SpdmRequestPskFinish => {
                            self.handle_spdm_psk_finish(session_id, bytes, writer)
                        }

                        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                            self.handle_spdm_vendor_defined_request(Some(session_id), bytes, writer)
                        }

                        #[cfg(feature = "chunk-cap")]
                        SpdmRequestResponseCode::SpdmRequestChunkSend => {
                            self.handle_spdm_chunk_send(Some(session_id), bytes, writer)
                        }
                        #[cfg(feature = "chunk-cap")]
                        SpdmRequestResponseCode::SpdmRequestChunkGet => {
                            self.handle_spdm_chunk_get(Some(session_id), bytes, writer)
                        }

                        SpdmRequestResponseCode::SpdmRequestGetVersion
                        | SpdmRequestResponseCode::SpdmRequestGetCapabilities
                        | SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
                        | SpdmRequestResponseCode::SpdmRequestGetDigests
                        | SpdmRequestResponseCode::SpdmRequestGetCertificate
                        | SpdmRequestResponseCode::SpdmRequestChallenge
                        | SpdmRequestResponseCode::SpdmRequestGetMeasurements
                        | SpdmRequestResponseCode::SpdmRequestKeyExchange
                        | SpdmRequestResponseCode::SpdmRequestPskExchange
                        | SpdmRequestResponseCode::SpdmRequestHeartbeat
                        | SpdmRequestResponseCode::SpdmRequestKeyUpdate
                        | SpdmRequestResponseCode::SpdmRequestEndSession => self
                            .handle_error_request(
                                SpdmErrorCode::SpdmErrorUnexpectedRequest,
                                bytes,
                                writer,
                            ),

                        SpdmRequestResponseCode::SpdmRequestResponseIfReady => self
                            .handle_error_request(
                                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                                bytes,
                                writer,
                            ),

                        _ => (Err(SPDM_STATUS_UNSUPPORTED_CAP), None),
                    },
                    None => (Err(SPDM_STATUS_UNSUPPORTED_CAP), None),
                }
            }
            SpdmSessionState::SpdmSessionEstablished => {
                match SpdmMessageHeader::read(&mut reader) {
                    Some(message_header) => match message_header.request_response_code {
                        SpdmRequestResponseCode::SpdmRequestGetDigests => {
                            self.handle_spdm_digest(bytes, Some(session_id), writer)
                        }
                        SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                            self.handle_spdm_certificate(bytes, Some(session_id), writer)
                        }
                        SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                            self.handle_spdm_measurement(Some(session_id), bytes, writer)
                        }

                        SpdmRequestResponseCode::SpdmRequestHeartbeat => {
                            self.handle_spdm_heartbeat(session_id, bytes, writer)
                        }

                        SpdmRequestResponseCode::SpdmRequestKeyUpdate => {
                            self.handle_spdm_key_update(session_id, bytes, writer)
                        }

                        SpdmRequestResponseCode::SpdmRequestEndSession => {
                            self.handle_spdm_end_session(session_id, bytes, writer)
                        }
                        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                            self.handle_spdm_vendor_defined_request(Some(session_id), bytes, writer)
                        }

                        #[cfg(feature = "chunk-cap")]
                        SpdmRequestResponseCode::SpdmRequestChunkSend => {
                            self.handle_spdm_chunk_send(Some(session_id), bytes, writer)
                        }
                        #[cfg(feature = "chunk-cap")]
                        SpdmRequestResponseCode::SpdmRequestChunkGet => {
                            self.handle_spdm_chunk_get(Some(session_id), bytes, writer)
                        }

                        SpdmRequestResponseCode::SpdmRequestGetVersion
                        | SpdmRequestResponseCode::SpdmRequestGetCapabilities
                        | SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
                        | SpdmRequestResponseCode::SpdmRequestChallenge
                        | SpdmRequestResponseCode::SpdmRequestKeyExchange
                        | SpdmRequestResponseCode::SpdmRequestPskExchange
                        | SpdmRequestResponseCode::SpdmRequestFinish
                        | SpdmRequestResponseCode::SpdmRequestPskFinish => self
                            .handle_error_request(
                                SpdmErrorCode::SpdmErrorUnexpectedRequest,
                                bytes,
                                writer,
                            ),

                        SpdmRequestResponseCode::SpdmRequestResponseIfReady => self
                            .handle_error_request(
                                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                                bytes,
                                writer,
                            ),

                        _ => (Err(SPDM_STATUS_UNSUPPORTED_CAP), None),
                    },
                    None => (Err(SPDM_STATUS_UNSUPPORTED_CAP), None),
                }
            }
            SpdmSessionState::SpdmSessionNotStarted => (Err(SPDM_STATUS_UNSUPPORTED_CAP), None),
            SpdmSessionState::Unknown(_) => (Err(SPDM_STATUS_UNSUPPORTED_CAP), None),
        }
    }

    fn dispatch_secured_app_message<'a>(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        app_handle: usize,
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        debug!("dispatching secured app message\n");

        dispatch_secured_app_message_cb(self, session_id, bytes, app_handle, writer)
    }

    pub fn dispatch_message<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let mut reader = Reader::init(bytes);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmRequestGetVersion => {
                    self.handle_spdm_version(bytes, writer)
                }
                SpdmRequestResponseCode::SpdmRequestGetCapabilities => {
                    self.handle_spdm_capability(bytes, writer)
                }
                SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms => {
                    self.handle_spdm_algorithm(bytes, writer)
                }
                SpdmRequestResponseCode::SpdmRequestGetDigests => {
                    self.handle_spdm_digest(bytes, None, writer)
                }
                SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                    self.handle_spdm_certificate(bytes, None, writer)
                }
                SpdmRequestResponseCode::SpdmRequestChallenge => {
                    self.handle_spdm_challenge(bytes, writer)
                }
                SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                    self.handle_spdm_measurement(None, bytes, writer)
                }

                SpdmRequestResponseCode::SpdmRequestKeyExchange => {
                    self.handle_spdm_key_exchange(bytes, writer)
                }

                SpdmRequestResponseCode::SpdmRequestPskExchange => {
                    self.handle_spdm_psk_exchange(bytes, writer)
                }

                SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                    self.handle_spdm_vendor_defined_request(None, bytes, writer)
                }

                #[cfg(feature = "chunk-cap")]
                SpdmRequestResponseCode::SpdmRequestChunkSend => {
                    self.handle_spdm_chunk_send(None, bytes, writer)
                }
                #[cfg(feature = "chunk-cap")]
                SpdmRequestResponseCode::SpdmRequestChunkGet => {
                    self.handle_spdm_chunk_get(None, bytes, writer)
                }

                SpdmRequestResponseCode::SpdmRequestFinish => {
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
                    if in_clear_text {
                        if let Some(session_id) = self.common.runtime_info.get_last_session_id() {
                            if let Some(session) =
                                self.common.get_immutable_session_via_id(session_id)
                            {
                                if session.get_session_state()
                                    == SpdmSessionState::SpdmSessionHandshaking
                                {
                                    return self.handle_spdm_finish(session_id, bytes, writer);
                                }
                            }
                        }
                    }

                    self.handle_error_request(
                        SpdmErrorCode::SpdmErrorUnexpectedRequest,
                        bytes,
                        writer,
                    )
                }

                SpdmRequestResponseCode::SpdmRequestPskFinish
                | SpdmRequestResponseCode::SpdmRequestHeartbeat
                | SpdmRequestResponseCode::SpdmRequestKeyUpdate
                | SpdmRequestResponseCode::SpdmRequestEndSession => self.handle_error_request(
                    SpdmErrorCode::SpdmErrorUnexpectedRequest,
                    bytes,
                    writer,
                ),

                SpdmRequestResponseCode::SpdmRequestResponseIfReady => self.handle_error_request(
                    SpdmErrorCode::SpdmErrorUnsupportedRequest,
                    bytes,
                    writer,
                ),

                _ => (Err(SPDM_STATUS_UNSUPPORTED_CAP), None),
            },
            None => (Err(SPDM_STATUS_UNSUPPORTED_CAP), None),
        }
    }

    #[cfg(feature = "chunk-cap")]
    fn handle_spdm_chunk_send<'a>(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (result, rsp_slice) = self.write_spdm_chunk_send_response(session_id, bytes, writer);
        if result.is_err() {
            self.common.chunk_req_handle = 0;
            self.common.chunk_context.chunk_seq_num = 0;
            self.common.chunk_context.chunk_message_size = 0;
            self.common.chunk_context.chunk_message_data.fill(0);
            self.common.chunk_context.transferred_size = 0;
            self.common.chunk_context.chunk_status = common::SpdmChunkStatus::Idle;
        }

        (result, rsp_slice)
    }

    #[cfg(feature = "chunk-cap")]
    fn write_spdm_chunk_send_response<'a>(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
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
        if !self
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::CHUNK_CAP)
            || !self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::CHUNK_CAP)
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnsupportedRequest, 0, writer);
            return (Err(SPDM_STATUS_UNSUPPORTED_CAP), Some(writer.used_slice()));
        }

        if self.common.runtime_info.get_connection_state()
            == SpdmConnectionState::SpdmConnectionNotStarted
            || self.common.runtime_info.get_connection_state()
                == SpdmConnectionState::SpdmConnectionAfterVersion
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }

        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(SpdmMessageHeader {
            version,
            request_response_code: _,
        }) = message_header
        {
            if version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            if version < SpdmVersion::SpdmVersion12 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnsupportedRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }
        let chunk_send_request =
            SpdmChunkSendRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(chunk_send_request) = chunk_send_request {
            if self.common.chunk_context.chunk_status == common::SpdmChunkStatus::Idle {
                let large_message_size = chunk_send_request.large_message_size.unwrap() as usize;
                let max_chunk_size = (config::SPDM_DATA_TRANSFER_SIZE
                    - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_SEND)
                    as u32;

                // Early check whether large message size is too large to be received in chunks.
                let data_transfer_size = config::SPDM_DATA_TRANSFER_SIZE;
                let max_large_request_size = (data_transfer_size
                    - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_SEND)
                    * (u16::MAX as usize - 1)
                    + data_transfer_size
                    - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_SEND;

                if chunk_send_request.chunk_seq_num != 0
                    || !(config::SPDM_MIN_DATA_TRANSFER_SIZE..=config::MAX_SPDM_MSG_SIZE)
                        .contains(&large_message_size)
                    || large_message_size > max_large_request_size
                    || chunk_send_request
                        .chunk_sender_attributes
                        .contains(SpdmChunkSenderAttributes::LAST_CHUNK)
                    || chunk_send_request.chunk_size > max_chunk_size
                {
                    error!("!!! invalid chunk send request, first chunk send is expected or request contains illegal data !!!\n");
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_PEER),
                        Some(writer.used_slice()),
                    );
                }
                self.common.chunk_req_handle = chunk_send_request.handle;
                self.common.chunk_context.chunk_seq_num = chunk_send_request.chunk_seq_num;
                self.common.chunk_context.chunk_message_size = large_message_size;
                self.common.chunk_context.chunk_status = common::SpdmChunkStatus::ChunkSendAndAck;
            } else if self.common.chunk_context.chunk_status
                == common::SpdmChunkStatus::ChunkSendAndAck
            {
                let max_chunk_size = (config::SPDM_DATA_TRANSFER_SIZE
                    - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_SEND)
                    as u32;
                if self.common.chunk_context.chunk_seq_num < max_chunk_seq_num {
                    self.common.chunk_context.chunk_seq_num += 1;
                } else {
                    error!("!!! chunk_send: chunk_seq_num overflow detected !!!\n");
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_PEER),
                        Some(writer.used_slice()),
                    );
                }
                if chunk_send_request.chunk_seq_num != self.common.chunk_context.chunk_seq_num
                    || chunk_send_request.handle != self.common.chunk_req_handle
                    || (!chunk_send_request
                        .chunk_sender_attributes
                        .contains(SpdmChunkSenderAttributes::LAST_CHUNK)
                        && chunk_send_request.chunk_size > max_chunk_size)
                    || self.common.chunk_context.transferred_size
                        > self.common.chunk_context.chunk_message_size
                {
                    error!("!!! invalid chunk send request !!!\n");
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_PEER),
                        Some(writer.used_slice()),
                    );
                }
            } else {
                error!("!!! chunk_send : invalid chunk status !!!\n");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_STATE_PEER),
                    Some(writer.used_slice()),
                );
            }

            let (response_status, response_to_large_request_size) = if chunk_send_request
                .chunk_sender_attributes
                .contains(SpdmChunkSenderAttributes::LAST_CHUNK)
            {
                if self.common.chunk_context.transferred_size
                    != self.common.chunk_context.chunk_message_size
                {
                    error!("!!! chunk_send : last chunk is received but large request is not successfully transferred !!!\n");
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_PEER),
                        Some(writer.used_slice()),
                    );
                }

                let request = self.common.chunk_context.chunk_message_data;

                let (status, send_buffer) = if let Some(session_id) = session_id {
                    self.dispatch_secured_message(
                        session_id,
                        &request[..self.common.chunk_context.transferred_size],
                        writer,
                    )
                } else {
                    self.dispatch_message(
                        &request[..self.common.chunk_context.transferred_size],
                        writer,
                    )
                };

                if let Some(send_buffer) = send_buffer {
                    let last_chunk_send_ack_size =
                        send_buffer.len() + offset_of_response_of_large_request_in_chunk_send_ack;
                    if (self.common.negotiate_info.req_data_transfer_size_sel != 0
                        && last_chunk_send_ack_size
                            > self.common.negotiate_info.req_data_transfer_size_sel as usize)
                        || last_chunk_send_ack_size > config::SPDM_SENDER_DATA_TRANSFER_SIZE
                    {
                        self.common.chunk_rsp_handle =
                            self.common.chunk_rsp_handle.overflowing_add(1).0;
                        self.common.chunk_context.chunk_seq_num = 0;
                        self.common.chunk_context.chunk_message_size = send_buffer.len();
                        self.common.chunk_context.chunk_message_data[..send_buffer.len()]
                            .copy_from_slice(send_buffer);
                        self.common.chunk_context.transferred_size = 0;
                        self.common.chunk_context.chunk_status =
                            common::SpdmChunkStatus::ChunkGetAndResponse;
                        self.write_spdm_error(SpdmErrorCode::SpdmErrorLargeResponse, 0, writer);
                        let _ = self.common.chunk_rsp_handle.encode(writer);
                        return (Ok(()), Some(writer.used_slice()));
                    } else {
                        self.common.chunk_context.chunk_message_size = send_buffer.len();
                        self.common.chunk_context.chunk_message_data[..send_buffer.len()]
                            .copy_from_slice(send_buffer);
                        self.common.chunk_context.transferred_size = send_buffer.len();
                        (status, send_buffer.len())
                    }
                } else {
                    return (status, None);
                }
            } else {
                (Ok(()), 0)
            };

            // Writer may be used to generate response to large request in last chunk send
            writer.clear();

            let response = SpdmMessage {
                header: SpdmMessageHeader {
                    version: self.common.negotiate_info.spdm_version_sel,
                    request_response_code: SpdmRequestResponseCode::SpdmResponseChunkSendAck,
                },
                payload: SpdmMessagePayload::SpdmChunkSendAckResponse(
                    SpdmChunkSendAckResponsePayload {
                        chunk_receiver_attributes: SpdmChunkReceiverAttributes::default(),
                        handle: self.common.chunk_req_handle,
                        chunk_seq_num: self.common.chunk_context.chunk_seq_num,
                        response_to_large_request_size,
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

            (response_status, Some(writer.used_slice()))
        } else {
            error!("!!! chunk_send : invalid chunk send request !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            )
        }
    }

    #[cfg(feature = "chunk-cap")]
    fn handle_spdm_chunk_get<'a>(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (result, rsp_slice) = self.write_spdm_chunk_get_response(session_id, bytes, writer);
        if result.is_err() {
            self.common.chunk_context.chunk_status = common::SpdmChunkStatus::Idle;
            self.common.chunk_context.chunk_seq_num = 0;
            self.common.chunk_context.chunk_message_size = 0;
            self.common.chunk_context.transferred_size = 0;
            self.common.chunk_context.chunk_message_data.fill(0);
        }

        (result, rsp_slice)
    }

    #[cfg(feature = "chunk-cap")]
    fn write_spdm_chunk_get_response<'a>(
        &mut self,
        _session_id: Option<u32>,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let max_chunk_seq_num =
            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
                u32::MAX
            } else {
                u16::MAX as u32
            };
        if !self
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::CHUNK_CAP)
            || !self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::CHUNK_CAP)
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnsupportedRequest, 0, writer);
            return (Err(SPDM_STATUS_UNSUPPORTED_CAP), Some(writer.used_slice()));
        }

        if self.common.runtime_info.get_connection_state()
            == SpdmConnectionState::SpdmConnectionNotStarted
            || self.common.runtime_info.get_connection_state()
                == SpdmConnectionState::SpdmConnectionAfterVersion
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }

        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(SpdmMessageHeader {
            version,
            request_response_code: _,
        }) = message_header
        {
            if version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            if version < SpdmVersion::SpdmVersion12 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnsupportedRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            let chunk_get_request =
                SpdmChunkGetRequestPayload::spdm_read(&mut self.common, &mut reader);
            if let Some(chunk_get_request) = chunk_get_request {
                if self.common.chunk_context.chunk_status
                    != common::SpdmChunkStatus::ChunkGetAndResponse
                {
                    error!("!!! chunk_get : unexpected chunk_get request !!!\n");
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_PEER),
                        Some(writer.used_slice()),
                    );
                }
                if chunk_get_request.chunk_seq_num != self.common.chunk_context.chunk_seq_num
                    || chunk_get_request.handle != self.common.chunk_rsp_handle
                {
                    error!("!!! chunk_get : unexpected chunk_seq_num or handle !!!\n");
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_PEER),
                        Some(writer.used_slice()),
                    );
                }
            }
        }

        let data_transfer_size = core::cmp::min(
            config::SPDM_SENDER_DATA_TRANSFER_SIZE,
            self.common.negotiate_info.req_data_transfer_size_sel as usize,
        );

        let large_message_size = if self.common.chunk_context.chunk_seq_num == 0 {
            let max_large_response_size = (data_transfer_size
                - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_RESPONSE)
                * (u16::MAX as usize - 1)
                + data_transfer_size
                - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_RESPONSE;
            if self.common.chunk_context.chunk_message_size > max_large_response_size {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorResponseTooLarge, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_STATE_PEER),
                    Some(writer.used_slice()),
                );
            }
            Some(self.common.chunk_context.chunk_message_size as u32)
        } else {
            None
        };

        let remaining_bytes = self.common.chunk_context.chunk_message_size
            - self.common.chunk_context.transferred_size;
        let max_chunk_size = if self.common.chunk_context.chunk_seq_num == 0 {
            data_transfer_size - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_RESPONSE
        } else {
            data_transfer_size - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_RESPONSE
        };
        let chunk_size = core::cmp::min(max_chunk_size, remaining_bytes) as u32;

        let response_attributes = if self.common.chunk_context.transferred_size
            + chunk_size as usize
            >= self.common.chunk_context.chunk_message_size
        {
            SpdmChunkSenderAttributes::LAST_CHUNK
        } else {
            SpdmChunkSenderAttributes::default()
        };

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseChunkResponse,
            },
            payload: SpdmMessagePayload::SpdmChunkResponse(SpdmChunkResponsePayload {
                response_attributes,
                handle: self.common.chunk_rsp_handle,
                chunk_seq_num: self.common.chunk_context.chunk_seq_num,
                chunk_size,
                large_message_size,
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

        assert!(self.common.chunk_context.chunk_seq_num < max_chunk_seq_num);
        self.common.chunk_context.chunk_seq_num += 1;

        (Ok(()), Some(writer.used_slice()))
    }
}
