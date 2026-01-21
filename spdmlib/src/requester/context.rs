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
use codec::{Codec, Reader, Writer};
use core::ops::DerefMut;
extern crate alloc;
use alloc::sync::Arc;
use spin::Mutex;

/// Substate for KEY_UPDATE command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
    KeyVerificationSend = 3,
    KeyVerificationReceive = 4,
}

/// Substate for HEARTBEAT command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for END_SESSION command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndSessionSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for START_SESSION (FINISH) command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishingSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for NEGOTIATE_ALGORITHMS command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiateAlgorithmsSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for GET_VERSION command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GettingVersionSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for GET_CAPABILITIES command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GettingCapabilitiesSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for INIT_CONNECTION (GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitConnectionSubstate {
    Init = 0,
    SpdmVersion = 1,
    SpdmCapability = 2,
    SpdmAlgorithm = 3,
}

/// Substate for GET_CERTIFICATE command (can have multiple portions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GettingCertificateSubstate {
    Init = 0,
    Retrieving = 1,                // Normal certificate retrieval in progress
    RetrievingResume = 2,          // Resuming from receive phase (request already sent)
    VerifyingCertificateChain = 3, // Certificate chain verification in progress
}

/// Substate for GET_MEASUREMENTS command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GettingMeasurementsSubstate {
    Init = 0,
    Measuring = 1,       // Normal measurement retrieval in progress
    MeasuringResume = 2, // Resuming from receive phase (request already sent)
}

/// Substate for VENDOR_DEFINED_REQUEST command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for GET_DIGESTS command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GettingDigestsSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for CHALLENGE command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengingSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for KEY_EXCHANGE command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangingSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for PSK_EXCHANGE command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskExchangingSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Substate for PSK_FINISH command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskFinishingSubstate {
    Init = 0,
    Send = 1,
    Receive = 2,
}

/// Common state tracking for SPDM command checkpointing
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdmCommandState {
    Idle,
    KeyUpdating(KeyUpdateSubstate),
    Heartbeating(HeartbeatSubstate),
    EndingSession(EndSessionSubstate),
    Finishing(FinishingSubstate),
    NegotiatingAlgorithms(NegotiateAlgorithmsSubstate),
    GettingCapabilities(GettingCapabilitiesSubstate),
    GettingVersion(GettingVersionSubstate),
    InitializingConnection(InitConnectionSubstate),
    GettingCertificate(GettingCertificateSubstate),
    GettingMeasurements(GettingMeasurementsSubstate),
    VendorRequesting(VendorSubstate),
    GettingDigests(GettingDigestsSubstate),
    Challenging(ChallengingSubstate),
    KeyExchanging(KeyExchangingSubstate),
    PskExchanging(PskExchangingSubstate),
    PskFinishing(PskFinishingSubstate),
}

impl SpdmCommandState {
    pub fn as_u16(&self) -> u16 {
        match self {
            SpdmCommandState::Idle => 0,
            SpdmCommandState::KeyUpdating(substate) => 0x10 | (*substate as u16),
            SpdmCommandState::Heartbeating(substate) => 0x20 | (*substate as u16),
            SpdmCommandState::EndingSession(substate) => 0x30 | (*substate as u16),
            SpdmCommandState::Finishing(substate) => 0x40 | (*substate as u16),
            SpdmCommandState::NegotiatingAlgorithms(substate) => 0x50 | (*substate as u16),
            SpdmCommandState::GettingCapabilities(substate) => 0x60 | (*substate as u16),
            SpdmCommandState::GettingVersion(substate) => 0x70 | (*substate as u16),
            SpdmCommandState::InitializingConnection(substate) => 0x80 | (*substate as u16),
            SpdmCommandState::GettingCertificate(substate) => 0x90 | (*substate as u16),
            SpdmCommandState::GettingMeasurements(substate) => 0xA0 | (*substate as u16),
            SpdmCommandState::VendorRequesting(substate) => 0xB0 | (*substate as u16),
            SpdmCommandState::GettingDigests(substate) => 0xC0 | (*substate as u16),
            SpdmCommandState::Challenging(substate) => 0xD0 | (*substate as u16),
            SpdmCommandState::KeyExchanging(substate) => 0xE0 | (*substate as u16),
            SpdmCommandState::PskExchanging(substate) => 0xF0 | (*substate as u16),
            SpdmCommandState::PskFinishing(substate) => 0x100 | (*substate as u16),
        }
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(SpdmCommandState::Idle),
            0x10 => Some(SpdmCommandState::KeyUpdating(KeyUpdateSubstate::Init)),
            0x11 => Some(SpdmCommandState::KeyUpdating(KeyUpdateSubstate::Send)),
            0x12 => Some(SpdmCommandState::KeyUpdating(KeyUpdateSubstate::Receive)),
            0x13 => Some(SpdmCommandState::KeyUpdating(
                KeyUpdateSubstate::KeyVerificationSend,
            )),
            0x14 => Some(SpdmCommandState::KeyUpdating(
                KeyUpdateSubstate::KeyVerificationReceive,
            )),
            0x20 => Some(SpdmCommandState::Heartbeating(HeartbeatSubstate::Init)),
            0x21 => Some(SpdmCommandState::Heartbeating(HeartbeatSubstate::Send)),
            0x22 => Some(SpdmCommandState::Heartbeating(HeartbeatSubstate::Receive)),
            0x30 => Some(SpdmCommandState::EndingSession(EndSessionSubstate::Init)),
            0x31 => Some(SpdmCommandState::EndingSession(EndSessionSubstate::Send)),
            0x32 => Some(SpdmCommandState::EndingSession(EndSessionSubstate::Receive)),
            0x40 => Some(SpdmCommandState::Finishing(FinishingSubstate::Init)),
            0x41 => Some(SpdmCommandState::Finishing(FinishingSubstate::Send)),
            0x42 => Some(SpdmCommandState::Finishing(FinishingSubstate::Receive)),
            0x50 => Some(SpdmCommandState::NegotiatingAlgorithms(
                NegotiateAlgorithmsSubstate::Init,
            )),
            0x51 => Some(SpdmCommandState::NegotiatingAlgorithms(
                NegotiateAlgorithmsSubstate::Send,
            )),
            0x52 => Some(SpdmCommandState::NegotiatingAlgorithms(
                NegotiateAlgorithmsSubstate::Receive,
            )),
            0x60 => Some(SpdmCommandState::GettingCapabilities(
                GettingCapabilitiesSubstate::Init,
            )),
            0x61 => Some(SpdmCommandState::GettingCapabilities(
                GettingCapabilitiesSubstate::Send,
            )),
            0x62 => Some(SpdmCommandState::GettingCapabilities(
                GettingCapabilitiesSubstate::Receive,
            )),
            0x70 => Some(SpdmCommandState::GettingVersion(
                GettingVersionSubstate::Init,
            )),
            0x71 => Some(SpdmCommandState::GettingVersion(
                GettingVersionSubstate::Send,
            )),
            0x72 => Some(SpdmCommandState::GettingVersion(
                GettingVersionSubstate::Receive,
            )),
            0x80 => Some(SpdmCommandState::InitializingConnection(
                InitConnectionSubstate::Init,
            )),
            0x81 => Some(SpdmCommandState::InitializingConnection(
                InitConnectionSubstate::SpdmVersion,
            )),
            0x82 => Some(SpdmCommandState::InitializingConnection(
                InitConnectionSubstate::SpdmCapability,
            )),
            0x83 => Some(SpdmCommandState::InitializingConnection(
                InitConnectionSubstate::SpdmAlgorithm,
            )),
            0x90 => Some(SpdmCommandState::GettingCertificate(
                GettingCertificateSubstate::Init,
            )),
            0x91 => Some(SpdmCommandState::GettingCertificate(
                GettingCertificateSubstate::Retrieving,
            )),
            0x92 => Some(SpdmCommandState::GettingCertificate(
                GettingCertificateSubstate::RetrievingResume,
            )),
            0x93 => Some(SpdmCommandState::GettingCertificate(
                GettingCertificateSubstate::VerifyingCertificateChain,
            )),
            0xA0 => Some(SpdmCommandState::GettingMeasurements(
                GettingMeasurementsSubstate::Init,
            )),
            0xA1 => Some(SpdmCommandState::GettingMeasurements(
                GettingMeasurementsSubstate::Measuring,
            )),
            0xA2 => Some(SpdmCommandState::GettingMeasurements(
                GettingMeasurementsSubstate::MeasuringResume,
            )),
            0xB0 => Some(SpdmCommandState::VendorRequesting(VendorSubstate::Init)),
            0xB1 => Some(SpdmCommandState::VendorRequesting(VendorSubstate::Send)),
            0xB2 => Some(SpdmCommandState::VendorRequesting(VendorSubstate::Receive)),
            0xC0 => Some(SpdmCommandState::GettingDigests(
                GettingDigestsSubstate::Init,
            )),
            0xC1 => Some(SpdmCommandState::GettingDigests(
                GettingDigestsSubstate::Send,
            )),
            0xC2 => Some(SpdmCommandState::GettingDigests(
                GettingDigestsSubstate::Receive,
            )),
            0xD0 => Some(SpdmCommandState::Challenging(ChallengingSubstate::Init)),
            0xD1 => Some(SpdmCommandState::Challenging(ChallengingSubstate::Send)),
            0xD2 => Some(SpdmCommandState::Challenging(ChallengingSubstate::Receive)),
            0xE0 => Some(SpdmCommandState::KeyExchanging(KeyExchangingSubstate::Init)),
            0xE1 => Some(SpdmCommandState::KeyExchanging(KeyExchangingSubstate::Send)),
            0xE2 => Some(SpdmCommandState::KeyExchanging(
                KeyExchangingSubstate::Receive,
            )),
            0xF0 => Some(SpdmCommandState::PskExchanging(PskExchangingSubstate::Init)),
            0xF1 => Some(SpdmCommandState::PskExchanging(PskExchangingSubstate::Send)),
            0xF2 => Some(SpdmCommandState::PskExchanging(
                PskExchangingSubstate::Receive,
            )),
            0x100 => Some(SpdmCommandState::PskFinishing(PskFinishingSubstate::Init)),
            0x101 => Some(SpdmCommandState::PskFinishing(PskFinishingSubstate::Send)),
            0x102 => Some(SpdmCommandState::PskFinishing(
                PskFinishingSubstate::Receive,
            )),
            _ => None,
        }
    }
}

impl Codec for SpdmCommandState {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.as_u16().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let value = u16::read(r)?;
        Self::from_u16(value)
    }
}

#[derive(Debug)]
pub struct CommandExecutionState {
    pub command_state: SpdmCommandState,
    pub send_buffer: Arc<Mutex<([u8; config::MAX_SPDM_MSG_SIZE], usize)>>,
    pub state_data: u64,
}

impl Default for CommandExecutionState {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandExecutionState {
    pub fn new() -> Self {
        CommandExecutionState {
            command_state: SpdmCommandState::Idle,
            send_buffer: Arc::new(Mutex::new(([0u8; config::MAX_SPDM_MSG_SIZE], 0))),
            state_data: 0,
        }
    }
}

impl Codec for CommandExecutionState {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;

        cnt += self.command_state.encode(bytes)?;

        let guard = self.send_buffer.lock();
        let buffer_size = guard.1 as u16;
        cnt += buffer_size.encode(bytes)?;

        for i in 0..buffer_size as usize {
            cnt += guard.0[i].encode(bytes)?;
        }

        cnt += self.state_data.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let command_state = SpdmCommandState::read(r)?;

        let buffer_size = u16::read(r)? as usize;

        if buffer_size > config::MAX_SPDM_MSG_SIZE {
            return None;
        }

        let mut buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        for item in buffer.iter_mut().take(buffer_size) {
            *item = u8::read(r)?;
        }

        let state_data = u64::read(r)?;

        Some(CommandExecutionState {
            command_state,
            send_buffer: Arc::new(Mutex::new((buffer, buffer_size))),
            state_data,
        })
    }
}

pub struct RequesterContext {
    pub common: common::SpdmContext,
    pub exec_state: CommandExecutionState,
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
            exec_state: CommandExecutionState::new(),
        }
    }

    /// Get a copy of the send buffer data without holding the lock across await points.
    /// Returns (buffer_copy, used_length)
    pub fn get_send_buffer_copy(&self) -> ([u8; config::MAX_SPDM_MSG_SIZE], usize) {
        let guard = self.exec_state.send_buffer.lock();
        let mut temp = [0u8; config::MAX_SPDM_MSG_SIZE];
        temp[..guard.1].copy_from_slice(&guard.0[..guard.1]);
        (temp, guard.1)
    }

    #[maybe_async::maybe_async]
    pub async fn init_connection(
        &mut self,
        transcript_vca: &mut Option<ManagedBufferA>,
    ) -> SpdmResult {
        use InitConnectionSubstate::*;

        let current_state = self.exec_state.command_state;
        debug!("init_connection - current state: {:?}\n", current_state);

        match current_state {
            SpdmCommandState::Idle => {
                *transcript_vca = None;
                self.exec_state.command_state = SpdmCommandState::InitializingConnection(Init);
            }
            SpdmCommandState::InitializingConnection(_)
            | SpdmCommandState::GettingVersion(_)
            | SpdmCommandState::GettingCapabilities(_)
            | SpdmCommandState::NegotiatingAlgorithms(_) => {
                // Continue from checkpoint
                debug!("Resuming init_connection from checkpoint\n");
            }
            _ => {
                error!("Invalid state transition for init_connection\n");
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }
        }

        // GET_VERSION phase
        if matches!(
            self.exec_state.command_state,
            SpdmCommandState::InitializingConnection(Init) | SpdmCommandState::GettingVersion(_)
        ) {
            debug!("init_connection: GET_VERSION phase\n");
            self.send_receive_spdm_version().await?;
            self.exec_state.command_state = SpdmCommandState::InitializingConnection(SpdmVersion);
        }

        // GET_CAPABILITIES phase
        if matches!(
            self.exec_state.command_state,
            SpdmCommandState::InitializingConnection(SpdmVersion)
                | SpdmCommandState::GettingCapabilities(_)
        ) {
            debug!("init_connection: GET_CAPABILITIES phase\n");
            self.send_receive_spdm_capability().await?;
            self.exec_state.command_state =
                SpdmCommandState::InitializingConnection(SpdmCapability);
        }

        // NEGOTIATE_ALGORITHMS phase
        if matches!(
            self.exec_state.command_state,
            SpdmCommandState::InitializingConnection(SpdmCapability)
                | SpdmCommandState::NegotiatingAlgorithms(_)
        ) {
            debug!("init_connection: NEGOTIATE_ALGORITHMS phase\n");
            self.send_receive_spdm_algorithm().await?;
            self.exec_state.command_state = SpdmCommandState::InitializingConnection(SpdmAlgorithm);
        }

        // Complete
        if matches!(
            self.exec_state.command_state,
            SpdmCommandState::InitializingConnection(SpdmAlgorithm)
        ) {
            *transcript_vca = Some(self.common.runtime_info.message_a.clone());
            self.exec_state.command_state = SpdmCommandState::Idle;
            return Ok(());
        }

        Err(SPDM_STATUS_INVALID_STATE_LOCAL)
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
                    self.common.chunk_context.chunk_message_data[..send_buffer.len()]
                        .copy_from_slice(send_buffer);
                    self.common.chunk_context.transferred_size = 0;
                    self.common.chunk_context.chunk_status =
                        common::SpdmChunkStatus::ChunkSendAndAck;
                    let result = self.send_large_request(session_id, send_buffer).await;
                    if let Err(e) = result {
                        self.common.chunk_context.chunk_seq_num = 0;
                        self.common.chunk_context.chunk_message_size = 0;
                        self.common.chunk_context.chunk_message_data.fill(0);
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
                .copy_from_slice(&self.common.chunk_context.chunk_message_data[..response_size]);
            self.common.chunk_context.chunk_seq_num = 0;
            self.common.chunk_context.chunk_message_size = 0;
            self.common.chunk_context.chunk_message_data.fill(0);
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
                                    self.common.chunk_context.chunk_message_data.fill(0);
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
                                        self.common.chunk_context.chunk_message_data.fill(0);
                                        self.common.chunk_context.transferred_size = 0;
                                        self.common.chunk_context.chunk_status =
                                            common::SpdmChunkStatus::Idle;
                                        return Err(e);
                                    }
                                    let message_len = self.common.chunk_context.transferred_size;
                                    receive_buffer[..message_len].copy_from_slice(
                                        &self.common.chunk_context.chunk_message_data
                                            [..message_len],
                                    );

                                    self.common.chunk_rsp_handle = 0;
                                    self.common.chunk_context.chunk_seq_num = 0;
                                    self.common.chunk_context.chunk_message_size = 0;
                                    self.common.chunk_context.chunk_message_data.fill(0);
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
                                let mut reader = Reader::init(
                                    &self.common.chunk_context.chunk_message_data
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
                                self.common.chunk_context.chunk_message_data[..len]
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
