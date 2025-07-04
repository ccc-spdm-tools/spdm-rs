// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

pub mod key_schedule;
pub mod opaque;
pub mod session;
pub mod spdm_codec;

use crate::message::SpdmRequestResponseCode;
use crate::{crypto, protocol::*};
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::{convert::TryFrom, ops::DerefMut};

pub use opaque::*;
pub use spdm_codec::SpdmCodec;

use crate::config::{self, MAX_ROOT_CERT_SUPPORT, MAX_SPDM_SESSION_COUNT};
use crate::error::{
    SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_DECAP_FAIL,
    SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_INVALID_STATE_LOCAL,
    SPDM_STATUS_SESSION_NUMBER_EXCEED,
};

use codec::{enum_builder, Codec, Reader, Writer};
use session::*;

enum_builder! {
    @U8
    EnumName: SpdmConnectionState;
    EnumVal{
        // Before GET_VERSION/VERSION
        SpdmConnectionNotStarted => 0x0,
        // After GET_VERSION/VERSION
        SpdmConnectionAfterVersion => 0x1,
        // After GET_CAPABILITIES/CAPABILITIES
        SpdmConnectionAfterCapabilities => 0x2,
        // After NEGOTIATE_ALGORITHMS/ALGORITHMS
        SpdmConnectionNegotiated => 0x3,
        // After GET_DIGESTS/DIGESTS
        SpdmConnectionAfterDigest => 0x4,
        // After GET_CERTIFICATE/CERTIFICATE
        SpdmConnectionAfterCertificate => 0x5,
        // After CHALLENGE/CHALLENGE_AUTH,
        // and ENCAP CHALLENGE/CHALLENGE_AUTH if MUT_AUTH is enabled.
        SpdmConnectionAuthenticated => 0x5
    }
}
#[allow(clippy::derivable_impls)]
impl Default for SpdmConnectionState {
    fn default() -> SpdmConnectionState {
        SpdmConnectionState::SpdmConnectionNotStarted
    }
}

#[cfg(feature = "hashed-transcript-data")]
pub use crate::crypto::SpdmHashCtx;

#[cfg(feature = "downcast")]
use core::any::Any;

/// The maximum amount of time the Responder has to provide a
/// response to requests that do not require cryptographic processing, such
/// as the GET_CAPABILITIES , GET_VERSION , or NEGOTIATE_ALGORITHMS
/// request messages. See SPDM spec. 1.1.0  Page 29 for more information:
/// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.0.pdf
pub const ST1: usize = 1_000_000;

/// used as parameter to be slot_id when use_psk is true
pub const INVALID_SLOT: u8 = 0xFF;

/// used to as the first next_half_session_id
pub const INITIAL_SESSION_ID: u16 = 0xFFFD;
pub const INVALID_HALF_SESSION_ID: u16 = 0x0;
pub const INVALID_SESSION_ID: u32 = 0x0;

#[maybe_async::maybe_async]
pub trait SpdmDeviceIo {
    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult;

    async fn receive(
        &mut self,
        buffer: Arc<Mutex<&mut [u8]>>,
        timeout: usize,
    ) -> Result<usize, usize>;

    async fn flush_all(&mut self) -> SpdmResult;

    #[cfg(feature = "downcast")]
    fn as_any(&mut self) -> &mut dyn Any;
}

use core::fmt::Debug;

#[maybe_async::maybe_async]
pub trait SpdmTransportEncap {
    async fn encap(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        transport_buffer: Arc<Mutex<&mut [u8]>>,
        secured_message: bool,
    ) -> SpdmResult<usize>;

    async fn decap(
        &mut self,
        transport_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)>;

    async fn encap_app(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        app_buffer: Arc<Mutex<&mut [u8]>>,
        is_app_message: bool,
    ) -> SpdmResult<usize>;

    async fn decap_app(
        &mut self,
        app_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)>;

    // for session
    fn get_sequence_number_count(&mut self) -> u8;
    fn get_max_random_count(&mut self) -> u16;
}

pub struct SpdmContextData {
    pub config_info: SpdmConfigInfo,
    pub negotiate_info: SpdmNegotiateInfo,
    pub runtime_info: SpdmRuntimeInfo,

    pub provision_info: SpdmProvisionInfo,
    pub peer_info: SpdmPeerInfo,

    #[cfg(feature = "mut-auth")]
    pub encap_context: SpdmEncapContext,

    #[cfg(feature = "mandatory-mut-auth")]
    pub mut_auth_done: bool,

    pub session: [SpdmSession; config::MAX_SPDM_SESSION_COUNT],
}

pub struct SpdmContext {
    pub device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
    pub transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    pub data: SpdmContextData,
}

impl SpdmContext {
    pub fn new(
        device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
        transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
        config_info: SpdmConfigInfo,
        provision_info: SpdmProvisionInfo,
    ) -> Self {
        SpdmContext {
            device_io,
            transport_encap,
            data: SpdmContextData {
                config_info,
                negotiate_info: SpdmNegotiateInfo::default(),
                runtime_info: SpdmRuntimeInfo::default(),
                provision_info,
                peer_info: SpdmPeerInfo::default(),
                #[cfg(feature = "mut-auth")]
                encap_context: SpdmEncapContext::default(),
                #[cfg(feature = "mandatory-mut-auth")]
                mut_auth_done: false,
                session: gen_array(config::MAX_SPDM_SESSION_COUNT),
            },
        }
    }

    pub fn get_hash_size(&self) -> u16 {
        self.data.negotiate_info.base_hash_sel.get_size()
    }
    pub fn get_asym_key_size(&self) -> u16 {
        self.data.negotiate_info.base_asym_sel.get_size()
    }
    pub fn get_dhe_key_size(&self) -> u16 {
        self.data.negotiate_info.dhe_sel.get_size()
    }

    pub fn reset_runtime_info(&mut self) {
        self.data.runtime_info = SpdmRuntimeInfo::default();
    }

    pub fn reset_negotiate_info(&mut self) {
        self.data.negotiate_info = SpdmNegotiateInfo::default();
    }

    pub fn reset_peer_info(&mut self) {
        self.data.peer_info = SpdmPeerInfo::default();
    }

    pub fn reset_context(&mut self) {
        self.reset_runtime_info();
        self.reset_negotiate_info();
        self.reset_peer_info();

        #[cfg(feature = "mut-auth")]
        {
            self.data.encap_context = SpdmEncapContext::default();
        }

        #[cfg(feature = "mandatory-mut-auth")]
        {
            self.data.mut_auth_done = false;
        }

        for s in &mut self.data.session {
            s.set_default();
        }
    }

    pub fn get_immutable_session_via_id(&self, session_id: u32) -> Option<&SpdmSession> {
        self.data.session
            .iter()
            .find(|&session| session.get_session_id() == session_id)
    }

    pub fn get_session_via_id(&mut self, session_id: u32) -> Option<&mut SpdmSession> {
        self.data.session
            .iter_mut()
            .find(|session| session.get_session_id() == session_id)
    }

    pub fn get_next_avaiable_session(&mut self) -> Option<&mut SpdmSession> {
        self.get_session_via_id(0)
    }

    pub fn get_session_status(&self) -> [(u32, SpdmSessionState); config::MAX_SPDM_SESSION_COUNT] {
        let mut status =
            [(0u32, SpdmSessionState::SpdmSessionNotStarted); config::MAX_SPDM_SESSION_COUNT];
        for (i, it) in status
            .iter_mut()
            .enumerate()
            .take(config::MAX_SPDM_SESSION_COUNT)
        {
            it.0 = self.data.session[i].get_session_id();
            it.1 = self.data.session[i].get_session_state();
        }
        status
    }

    pub fn get_next_half_session_id(&self, is_requester: bool) -> SpdmResult<u16> {
        let shift = if is_requester { 0 } else { 16 };

        for (index, s) in self.data.session.iter().enumerate().take(MAX_SPDM_SESSION_COUNT) {
            if ((s.get_session_id() & (0xFFFF << shift)) >> shift) as u16 == INVALID_HALF_SESSION_ID
            {
                return Ok(INITIAL_SESSION_ID - index as u16);
            }
        }

        Err(SPDM_STATUS_SESSION_NUMBER_EXCEED)
    }

    pub fn construct_my_cert_chain(&mut self) -> SpdmResult {
        for slot_id in 0..SPDM_MAX_SLOT_NUMBER {
            if self.data.provision_info.my_cert_chain[slot_id].is_none()
                && self.data.provision_info.my_cert_chain_data[slot_id].is_some()
            {
                let cert_chain = self.data.provision_info.my_cert_chain_data[slot_id]
                    .as_ref()
                    .unwrap();
                let (root_cert_begin, root_cert_end) =
                    crypto::cert_operation::get_cert_from_cert_chain(
                        &cert_chain.data[..(cert_chain.data_size as usize)],
                        0,
                    )?;
                let root_cert = &cert_chain.data[root_cert_begin..root_cert_end];
                if let Some(root_hash) =
                    crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, root_cert)
                {
                    let data_size = 4 + root_hash.data_size + cert_chain.data_size;
                    let mut data =
                        [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE];
                    data[0] = (data_size & 0xFF) as u8;
                    data[1] = (data_size >> 8) as u8;
                    data[4..(4 + root_hash.data_size as usize)]
                        .copy_from_slice(&root_hash.data[..(root_hash.data_size as usize)]);
                    data[(4 + root_hash.data_size as usize)..(data_size as usize)]
                        .copy_from_slice(&cert_chain.data[..(cert_chain.data_size as usize)]);
                    self.data.provision_info.my_cert_chain[slot_id] =
                        Some(SpdmCertChainBuffer { data_size, data });
                    debug!("my_cert_chain - {:02x?}\n", &data[..(data_size as usize)]);
                } else {
                    return Err(SPDM_STATUS_CRYPTO_ERROR);
                }
            }
        }

        Ok(())
    }

    pub fn get_signing_prefix_context(&self) -> [u8; 64] {
        let spdm_version = u8::from(self.data.negotiate_info.spdm_version_sel);
        let mut signing_prefix = SPDM_VERSION_1_X_SIGNING_PREFIX_CONTEXT;
        for i in 0..SPDM_VERSION_SIGNING_PREFIX_NUMBER {
            signing_prefix[SPDM_VERSION_SIGNING_PREFIX_LENGTH * i
                + SPDM_VERSION_SIGNING_PREFIX_MAJOR_VER_INDEX] = 0x30 + ((spdm_version >> 4) & 0xF);
            signing_prefix[SPDM_VERSION_SIGNING_PREFIX_LENGTH * i
                + SPDM_VERSION_SIGNING_PREFIX_MINOR_VER_INDEX] = 0x30 + (spdm_version & 0xF);
        }
        signing_prefix
    }

    pub fn append_message_a(&mut self, new_message: &[u8]) -> SpdmResult {
        self.data.runtime_info
            .message_a
            .append_message(new_message)
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        Ok(())
    }
    pub fn reset_message_a(&mut self) {
        self.data.runtime_info.message_a.reset_message();
    }

    pub fn append_message_b(&mut self, new_message: &[u8]) -> SpdmResult {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.data.runtime_info
                .message_b
                .append_message(new_message)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            if self.data.runtime_info.digest_context_m1m2.is_none() {
                self.data.runtime_info.digest_context_m1m2 =
                    crypto::hash::hash_ctx_init(self.data.negotiate_info.base_hash_sel);
                if self.data.runtime_info.digest_context_m1m2.is_none() {
                    return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
                }

                crypto::hash::hash_ctx_update(
                    self.data.runtime_info.digest_context_m1m2.as_mut().unwrap(),
                    self.data.runtime_info.message_a.as_ref(),
                )?;
            }

            crypto::hash::hash_ctx_update(
                self.data.runtime_info.digest_context_m1m2.as_mut().unwrap(),
                new_message,
            )?;
        }

        Ok(())
    }
    pub fn reset_message_b(&mut self) {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.data.runtime_info.message_b.reset_message();
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            self.data.runtime_info.digest_context_m1m2 = None;
        }
    }

    pub fn append_message_c(&mut self, new_message: &[u8]) -> SpdmResult {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.data.runtime_info
                .message_c
                .append_message(new_message)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            if self.data.runtime_info.digest_context_m1m2.is_none() {
                self.data.runtime_info.digest_context_m1m2 =
                    crypto::hash::hash_ctx_init(self.data.negotiate_info.base_hash_sel);
                if self.data.runtime_info.digest_context_m1m2.is_none() {
                    return Err(SPDM_STATUS_CRYPTO_ERROR);
                }

                crypto::hash::hash_ctx_update(
                    self.data.runtime_info.digest_context_m1m2.as_mut().unwrap(),
                    self.data.runtime_info.message_a.as_ref(),
                )?;
            }

            crypto::hash::hash_ctx_update(
                self.data.runtime_info.digest_context_m1m2.as_mut().unwrap(),
                new_message,
            )?;
        }

        Ok(())
    }
    pub fn reset_message_c(&mut self) {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.data.runtime_info.message_c.reset_message();
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            self.data.runtime_info.digest_context_m1m2 = None;
        }
    }

    pub fn append_message_m(&mut self, session_id: Option<u32>, new_message: &[u8]) -> SpdmResult {
        #[cfg(not(feature = "hashed-transcript-data"))]
        match session_id {
            None => self
                .data.runtime_info
                .message_m
                .append_message(new_message)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?,
            Some(session_id) => {
                let session = if let Some(s) = self.get_session_via_id(session_id) {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
                };
                session
                    .runtime_info
                    .message_m
                    .append_message(new_message)
                    .ok_or(SPDM_STATUS_BUFFER_FULL)?
            }
        };

        #[cfg(feature = "hashed-transcript-data")]
        {
            match session_id {
                Some(session_id) => {
                    let base_hash_sel = self.data.negotiate_info.base_hash_sel;
                    let spdm_version_sel = self.data.negotiate_info.spdm_version_sel;
                    let message_a = self.data.runtime_info.message_a.clone();

                    let session = if let Some(s) = self.get_session_via_id(session_id) {
                        s
                    } else {
                        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
                    };
                    if session.runtime_info.digest_context_l1l2.is_none() {
                        session.runtime_info.digest_context_l1l2 =
                            crypto::hash::hash_ctx_init(base_hash_sel);
                        if session.runtime_info.digest_context_l1l2.is_none() {
                            return Err(SPDM_STATUS_CRYPTO_ERROR);
                        }

                        if spdm_version_sel >= SpdmVersion::SpdmVersion12 {
                            crypto::hash::hash_ctx_update(
                                session.runtime_info.digest_context_l1l2.as_mut().unwrap(),
                                message_a.as_ref(),
                            )?;
                        }
                    }

                    crypto::hash::hash_ctx_update(
                        session.runtime_info.digest_context_l1l2.as_mut().unwrap(),
                        new_message,
                    )?;
                }
                None => {
                    if self.data.runtime_info.digest_context_l1l2.is_none() {
                        self.data.runtime_info.digest_context_l1l2 =
                            crypto::hash::hash_ctx_init(self.data.negotiate_info.base_hash_sel);
                        if self.data.runtime_info.digest_context_l1l2.is_none() {
                            return Err(SPDM_STATUS_CRYPTO_ERROR);
                        }

                        if self.data.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
                            crypto::hash::hash_ctx_update(
                                self.data.runtime_info.digest_context_l1l2.as_mut().unwrap(),
                                self.data.runtime_info.message_a.as_ref(),
                            )?;
                        }
                    }

                    crypto::hash::hash_ctx_update(
                        self.data.runtime_info.digest_context_l1l2.as_mut().unwrap(),
                        new_message,
                    )?;
                }
            }
        }

        Ok(())
    }
    pub fn reset_message_m(&mut self, session_id: Option<u32>) {
        #[cfg(not(feature = "hashed-transcript-data"))]
        match session_id {
            None => self.data.runtime_info.message_m.reset_message(),
            Some(session_id) => {
                let session = if let Some(s) = self.get_session_via_id(session_id) {
                    s
                } else {
                    return;
                };
                session.runtime_info.message_m.reset_message();
            }
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            match session_id {
                Some(session_id) => {
                    let session = if let Some(s) = self.get_session_via_id(session_id) {
                        s
                    } else {
                        return;
                    };
                    session.runtime_info.digest_context_l1l2 = None;
                }
                None => {
                    self.data.runtime_info.digest_context_l1l2 = None;
                }
            }
        }
    }

    pub fn append_message_k(&mut self, session_id: u32, new_message: &[u8]) -> SpdmResult {
        let session = self
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            session
                .runtime_info
                .message_k
                .append_message(new_message)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            if session.runtime_info.digest_context_th.is_none() {
                session.runtime_info.digest_context_th =
                    crypto::hash::hash_ctx_init(session.get_crypto_param().base_hash_algo);
                if session.runtime_info.digest_context_th.is_none() {
                    return Err(SPDM_STATUS_CRYPTO_ERROR);
                }
                crypto::hash::hash_ctx_update(
                    session.runtime_info.digest_context_th.as_mut().unwrap(),
                    session.runtime_info.message_a.as_ref(),
                )?;
                if session.runtime_info.rsp_cert_hash.is_some() {
                    crypto::hash::hash_ctx_update(
                        session.runtime_info.digest_context_th.as_mut().unwrap(),
                        session
                            .runtime_info
                            .rsp_cert_hash
                            .as_ref()
                            .unwrap()
                            .as_ref(),
                    )?;
                }
            }

            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                new_message,
            )?;
        }

        Ok(())
    }
    pub fn reset_message_k(&mut self, session_id: u32) {
        let session = self.get_session_via_id(session_id).unwrap();

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            session.runtime_info.message_f.reset_message();
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            session.runtime_info.digest_context_th = None;
        }
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn append_message_f(
        &mut self,
        _is_requester: bool,
        session_id: u32,
        new_message: &[u8],
    ) -> SpdmResult {
        let session = self
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        let _ = session
            .runtime_info
            .message_f
            .append_message(new_message)
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        Ok(())
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn append_message_f(
        &mut self,
        is_requester: bool,
        session_id: u32,
        new_message: &[u8],
    ) -> SpdmResult {
        let session = self
            .get_immutable_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        if session.runtime_info.digest_context_th.is_none() {
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        if !session.runtime_info.message_f_initialized {
            let mut_cert_digest = if !session.get_use_psk()
                && !session.get_mut_auth_requested().is_empty()
            {
                if is_requester {
                    let slot_id = self.data.runtime_info.get_local_used_cert_chain_slot_id();
                    if let Some(cert_chain) = &self.data.provision_info.my_cert_chain[slot_id as usize] {
                        Some(
                            crypto::hash::hash_all(
                                self.data.negotiate_info.base_hash_sel,
                                &cert_chain.data[..cert_chain.data_size as usize],
                            )
                            .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
                        )
                    } else {
                        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
                    }
                } else {
                    let slot_id = self.data.runtime_info.get_peer_used_cert_chain_slot_id();
                    if let Some(cert_chain) = &self.data.peer_info.peer_cert_chain[slot_id as usize] {
                        Some(
                            crypto::hash::hash_all(
                                self.data.negotiate_info.base_hash_sel,
                                cert_chain.as_ref(),
                            )
                            .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
                        )
                    } else {
                        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
                    }
                }
            } else {
                None
            };

            if let Some(mut_cert_digest) = mut_cert_digest {
                let session = self
                    .get_session_via_id(session_id)
                    .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;

                crypto::hash::hash_ctx_update(
                    session.runtime_info.digest_context_th.as_mut().unwrap(),
                    &mut_cert_digest.data[..mut_cert_digest.data_size as usize],
                )?;
            }
            let session = self
                .get_session_via_id(session_id)
                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
            session.runtime_info.message_f_initialized = true;
        }

        let session = self
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        crypto::hash::hash_ctx_update(
            session.runtime_info.digest_context_th.as_mut().unwrap(),
            new_message,
        )
    }

    pub fn reset_message_f(&mut self, session_id: u32) {
        let session = self.get_session_via_id(session_id).unwrap();

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            session.runtime_info.message_f.reset_message();
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            session.runtime_info.digest_context_th = None;
        }
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn calc_req_transcript_data(
        &self,
        use_psk: bool,
        slot_id: u8,
        is_mut_auth: bool,
        message_k: &ManagedBufferK,
        message_f: Option<&ManagedBufferF>,
    ) -> SpdmResult<ManagedBufferTH> {
        let mut message = ManagedBufferTH::default();
        message
            .append_message(self.data.runtime_info.message_a.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        debug!("message_a - {:02x?}", self.data.runtime_info.message_a.as_ref());

        if !use_psk {
            if self.data.peer_info.peer_cert_chain[slot_id as usize].is_none() {
                error!("peer_cert_chain is not populated!\n");
                return Err(SPDM_STATUS_INVALID_PARAMETER);
            }

            let cert_chain_data = &self.data.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data[..(self.data.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];
            let cert_chain_hash =
                crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
            message
                .append_message(cert_chain_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("cert_chain_data - {:02x?}", cert_chain_data);
        }
        message
            .append_message(message_k.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        debug!("message_k - {:02x?}", message_k.as_ref());

        if !use_psk && is_mut_auth {
            let slot_id = self.data.runtime_info.get_local_used_cert_chain_slot_id();
            if self.data.provision_info.my_cert_chain[slot_id as usize].is_none() {
                error!("mut cert_chain is not populated!\n");
                return Err(SPDM_STATUS_INVALID_PARAMETER);
            }

            let cert_chain_data = &self.data.provision_info.my_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data[..(self.data.provision_info.my_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];
            let cert_chain_hash =
                crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
            message
                .append_message(cert_chain_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("my_cert_chain_data - {:02x?}", cert_chain_data);
        }

        if let Some(message_f) = message_f {
            message
                .append_message(message_f.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("message_f - {:02x?}", message_f.as_ref());
        }

        Ok(message)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn calc_rsp_transcript_data(
        &self,
        use_psk: bool,
        slot_id: u8,
        is_mut_auth: bool,
        message_k: &ManagedBufferK,
        message_f: Option<&ManagedBufferF>,
    ) -> SpdmResult<ManagedBufferTH> {
        let mut message = ManagedBufferTH::default();
        message
            .append_message(self.data.runtime_info.message_a.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        debug!("message_a - {:02x?}", self.data.runtime_info.message_a.as_ref());
        if !use_psk {
            if self.data.provision_info.my_cert_chain[slot_id as usize].is_none() {
                error!("my_cert_chain is not populated!\n");
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }

            let my_cert_chain_data = self.data.provision_info.my_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
            let cert_chain_data = my_cert_chain_data.as_ref();
            let cert_chain_hash =
                crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;

            message
                .append_message(cert_chain_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("cert_chain_data - {:02x?}", cert_chain_data);
        }
        message
            .append_message(message_k.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        debug!("message_k - {:02x?}", message_k.as_ref());

        if !use_psk && is_mut_auth {
            let slot_id = self.data.runtime_info.get_peer_used_cert_chain_slot_id();
            if self.data.peer_info.peer_cert_chain[slot_id as usize].is_none() {
                error!("peer_cert_chain is not populated!\n");
                return Err(SPDM_STATUS_INVALID_PARAMETER);
            }

            let cert_chain_data = &self.data.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .as_ref();
            let cert_chain_hash =
                crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
            message
                .append_message(cert_chain_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("peer_cert_chain_data - {:02x?}", cert_chain_data);
        }

        if let Some(message_f) = message_f {
            message
                .append_message(message_f.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("message_f - {:02x?}", message_f.as_ref());
        }

        Ok(message)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn calc_req_transcript_hash(
        &self,
        use_psk: bool,
        slot_id: u8,
        is_mut_auth: bool,
        session: &SpdmSession,
    ) -> SpdmResult<SpdmDigestStruct> {
        let message_k = &session.runtime_info.message_k;
        let message_f = Some(&session.runtime_info.message_f);
        let message =
            self.calc_req_transcript_data(use_psk, slot_id, is_mut_auth, message_k, message_f)?;

        let transcript_hash =
            crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        Ok(transcript_hash)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn calc_rsp_transcript_hash(
        &self,
        use_psk: bool,
        slot_id: u8,
        is_mut_auth: bool,
        session: &SpdmSession,
    ) -> SpdmResult<SpdmDigestStruct> {
        let message_k = &session.runtime_info.message_k;
        let message_f = Some(&session.runtime_info.message_f);
        let message =
            self.calc_rsp_transcript_data(use_psk, slot_id, is_mut_auth, message_k, message_f)?;

        let transcript_hash =
            crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        Ok(transcript_hash)
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn calc_req_transcript_hash(
        &self,
        _use_psk: bool,
        _slot_id: u8,
        _is_mut_auth: bool,
        session: &SpdmSession,
    ) -> SpdmResult<SpdmDigestStruct> {
        let transcript_hash = crypto::hash::hash_ctx_finalize(
            session
                .runtime_info
                .digest_context_th
                .as_ref()
                .cloned()
                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?,
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        Ok(transcript_hash)
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn calc_rsp_transcript_hash(
        &self,
        _use_psk: bool,
        _slot_id: u8,
        _is_mut_auth: bool,
        session: &SpdmSession,
    ) -> SpdmResult<SpdmDigestStruct> {
        let transcript_hash = crypto::hash::hash_ctx_finalize(
            session
                .runtime_info
                .digest_context_th
                .as_ref()
                .cloned()
                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?,
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        Ok(transcript_hash)
    }

    pub fn get_certchain_hash_local(
        &self,
        use_psk: bool,
        slot_id: usize,
    ) -> Option<SpdmDigestStruct> {
        if !use_psk {
            if self.data.provision_info.my_cert_chain[slot_id].is_none() {
                error!("my_cert_chain is not populated!\n");
                return None;
            }

            let my_cert_chain_data = self.data.provision_info.my_cert_chain[slot_id].as_ref()?;
            let cert_chain_data = my_cert_chain_data.as_ref();
            let cert_chain_hash =
                crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(None::<SpdmDigestStruct>);
            if let Ok(hash) = cert_chain_hash {
                Some(SpdmDigestStruct::from(hash.as_ref()))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_certchain_hash_peer(
        &self,
        use_psk: bool,
        slot_id: usize,
    ) -> Option<SpdmDigestStruct> {
        if !use_psk {
            if self.data.peer_info.peer_cert_chain[slot_id].is_none() {
                error!("peer_cert_chain is not populated!\n");
                return None;
            }

            let cert_chain_data = &self.data.peer_info.peer_cert_chain[slot_id].as_ref()?.data
                [..(self.data.peer_info.peer_cert_chain[slot_id].as_ref()?.data_size as usize)];
            let cert_chain_hash =
                crypto::hash::hash_all(self.data.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(None::<SpdmDigestStruct>);

            if let Ok(hash) = cert_chain_hash {
                Some(SpdmDigestStruct::from(hash.as_ref()))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn reset_buffer_via_request_code(
        &mut self,
        opcode: SpdmRequestResponseCode,
        session_id: Option<u32>,
    ) {
        if opcode != SpdmRequestResponseCode::SpdmRequestGetMeasurements {
            self.reset_message_m(session_id)
        }
        match opcode {
            SpdmRequestResponseCode::SpdmRequestGetMeasurements
            | SpdmRequestResponseCode::SpdmRequestKeyExchange
            | SpdmRequestResponseCode::SpdmRequestFinish
            | SpdmRequestResponseCode::SpdmRequestPskExchange
            | SpdmRequestResponseCode::SpdmRequestPskFinish
            | SpdmRequestResponseCode::SpdmRequestKeyUpdate
            | SpdmRequestResponseCode::SpdmRequestHeartbeat
            | SpdmRequestResponseCode::SpdmRequestEndSession => {
                if self.data.runtime_info.connection_state.get_u8()
                    < SpdmConnectionState::SpdmConnectionAuthenticated.get_u8()
                {
                    self.reset_message_b();
                    self.reset_message_c();
                }
            }
            SpdmRequestResponseCode::SpdmRequestGetDigests => {
                self.reset_message_b();
            }
            _ => {}
        }
    }

    #[maybe_async::maybe_async]
    pub async fn encap(
        &mut self,
        send_buffer: &[u8],
        transport_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut transport_encap = self.transport_encap.lock();
        let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
            transport_encap.deref_mut();
        let send_buffer = Arc::new(send_buffer);
        let transport_buffer = Mutex::new(transport_buffer);
        let transport_buffer = Arc::new(transport_buffer);
        transport_encap
            .encap(send_buffer, transport_buffer, false)
            .await
    }

    #[maybe_async::maybe_async]
    pub async fn encode_secured_message(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        transport_buffer: &mut [u8],
        is_requester: bool,
        is_app_message: bool,
    ) -> SpdmResult<usize> {
        let mut app_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used = {
            let mut transport_encap = self.transport_encap.lock();
            let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
                transport_encap.deref_mut();
            let send_buffer = Arc::new(send_buffer);
            let app_buffer = Mutex::new(&mut app_buffer[..]);
            let app_buffer = Arc::new(app_buffer);
            transport_encap
                .encap_app(send_buffer, app_buffer, is_app_message)
                .await?
        };

        let spdm_session = self
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

        let mut encoded_send_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let encode_size = spdm_session.encode_spdm_secured_message(
            &app_buffer[0..used],
            &mut encoded_send_buffer,
            is_requester,
        )?;

        let mut transport_encap = self.transport_encap.lock();
        let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
            transport_encap.deref_mut();
        transport_encap
            .encap(
                Arc::new(&encoded_send_buffer[..encode_size]),
                Arc::new(Mutex::new(transport_buffer)),
                true,
            )
            .await
    }

    #[maybe_async::maybe_async]
    pub async fn decap(
        &mut self,
        transport_buffer: &[u8],
        receive_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut transport_encap = self.transport_encap.lock();
        let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
            transport_encap.deref_mut();

        let (used, secured_message) = transport_encap
            .decap(
                Arc::new(transport_buffer),
                Arc::new(Mutex::new(receive_buffer)),
            )
            .await?;

        if secured_message {
            return Err(SPDM_STATUS_DECAP_FAIL); //need check
        }

        Ok(used)
    }

    #[maybe_async::maybe_async]
    pub async fn decode_secured_message(
        &mut self,
        session_id: u32,
        transport_buffer: &[u8],
        receive_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut encoded_receive_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        let (used, secured_message) = {
            let mut transport_encap = self.transport_encap.lock();
            let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
                transport_encap.deref_mut();

            transport_encap
                .decap(
                    Arc::new(transport_buffer),
                    Arc::new(Mutex::new(&mut encoded_receive_buffer)),
                )
                .await?
        };

        if !secured_message {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }

        let spdm_session = self
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

        let mut app_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
        let decode_size = spdm_session.decode_spdm_secured_message(
            &encoded_receive_buffer[..used],
            &mut app_buffer,
            false,
        )?;

        let mut transport_encap = self.transport_encap.lock();
        let transport_encap: &mut (dyn SpdmTransportEncap + Send + Sync) =
            transport_encap.deref_mut();

        let used = transport_encap
            .decap_app(
                Arc::new(&app_buffer[0..decode_size]),
                Arc::new(Mutex::new(receive_buffer)),
            )
            .await?;

        Ok(used.0)
    }
}

#[derive(Debug, Default)]
pub struct SpdmConfigInfo {
    pub spdm_version: [Option<SpdmVersion>; MAX_SPDM_VERSION_COUNT],
    pub req_capabilities: SpdmRequestCapabilityFlags,
    pub rsp_capabilities: SpdmResponseCapabilityFlags,
    pub req_ct_exponent: u8,
    pub rsp_ct_exponent: u8,
    pub measurement_specification: SpdmMeasurementSpecification,
    pub measurement_hash_algo: SpdmMeasurementHashAlgo,
    pub base_hash_algo: SpdmBaseHashAlgo,
    pub base_asym_algo: SpdmBaseAsymAlgo,
    pub dhe_algo: SpdmDheAlgo,
    pub aead_algo: SpdmAeadAlgo,
    pub req_asym_algo: SpdmReqAsymAlgo,
    pub key_schedule_algo: SpdmKeyScheduleAlgo,
    pub other_params_support: SpdmAlgoOtherParams,
    pub session_policy: u8,
    pub runtime_content_change_support: bool,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
    pub heartbeat_period: u8, // used by responder only
    pub secure_spdm_version: [Option<SecuredMessageVersion>; MAX_SECURE_SPDM_VERSION_COUNT],
    pub mel_specification: SpdmMelSpecification, // spdm 1.3
}

impl Codec for SpdmConfigInfo {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;

        // Count and encode populated spdm_version entries
        let spdm_version_count = self.spdm_version.iter().filter(|v| v.is_some()).count() as u8;
        size += spdm_version_count.encode(writer)?;
        for v in &self.spdm_version {
            if let Some(version) = v {
                size += version.encode(writer)?;
            }
        }

        size += self.req_capabilities.encode(writer)?;
        size += self.rsp_capabilities.encode(writer)?;
        size += self.req_ct_exponent.encode(writer)?;
        size += self.rsp_ct_exponent.encode(writer)?;
        size += self.measurement_specification.encode(writer)?;
        size += self.measurement_hash_algo.encode(writer)?;
        size += self.base_hash_algo.encode(writer)?;
        size += self.base_asym_algo.encode(writer)?;
        size += self.dhe_algo.encode(writer)?;
        size += self.aead_algo.encode(writer)?;
        size += self.req_asym_algo.encode(writer)?;
        size += self.key_schedule_algo.encode(writer)?;
        size += self.other_params_support.encode(writer)?;
        size += self.session_policy.encode(writer)?;
        size += (self.runtime_content_change_support as u8).encode(writer)?;
        size += self.data_transfer_size.encode(writer)?;
        size += self.max_spdm_msg_size.encode(writer)?;
        size += self.heartbeat_period.encode(writer)?;

        // Count and encode populated secure_spdm_version entries
        let secure_spdm_version_count = self.secure_spdm_version.iter().filter(|v| v.is_some()).count() as u8;
        size += secure_spdm_version_count.encode(writer)?;
        for v in &self.secure_spdm_version {
            if let Some(version) = v {
                size += version.encode(writer)?;
            }
        }

        size += self.mel_specification.encode(writer)?;
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        // Read spdm_version count and entries
        let spdm_version_count = u8::read(reader)? as usize;
        let mut spdm_version = [None; MAX_SPDM_VERSION_COUNT];
        for i in 0..spdm_version_count.min(MAX_SPDM_VERSION_COUNT) {
            spdm_version[i] = Some(SpdmVersion::read(reader)?);
        }

        let req_capabilities = SpdmRequestCapabilityFlags::read(reader)?;
        let rsp_capabilities = SpdmResponseCapabilityFlags::read(reader)?;
        let req_ct_exponent = u8::read(reader)?;
        let rsp_ct_exponent = u8::read(reader)?;
        let measurement_specification = SpdmMeasurementSpecification::read(reader)?;
        let measurement_hash_algo = SpdmMeasurementHashAlgo::read(reader)?;
        let base_hash_algo = SpdmBaseHashAlgo::read(reader)?;
        let base_asym_algo = SpdmBaseAsymAlgo::read(reader)?;
        let dhe_algo = SpdmDheAlgo::read(reader)?;
        let aead_algo = SpdmAeadAlgo::read(reader)?;
        let req_asym_algo = SpdmReqAsymAlgo::read(reader)?;
        let key_schedule_algo = SpdmKeyScheduleAlgo::read(reader)?;
        let other_params_support = SpdmAlgoOtherParams::read(reader)?;
        let session_policy = u8::read(reader)?;
        let runtime_content_change_support = u8::read(reader)? != 0;
        let data_transfer_size = u32::read(reader)?;
        let max_spdm_msg_size = u32::read(reader)?;
        let heartbeat_period = u8::read(reader)?;

        // Read secure_spdm_version count and entries
        let secure_spdm_version_count = u8::read(reader)? as usize;
        let mut secure_spdm_version = [None; MAX_SECURE_SPDM_VERSION_COUNT];
        for i in 0..secure_spdm_version_count.min(MAX_SECURE_SPDM_VERSION_COUNT) {
            secure_spdm_version[i] = Some(SecuredMessageVersion::read(reader)?);
        }

        let mel_specification = SpdmMelSpecification::read(reader)?;

        Some(Self {
            spdm_version,
            req_capabilities,
            rsp_capabilities,
            req_ct_exponent,
            rsp_ct_exponent,
            measurement_specification,
            measurement_hash_algo,
            base_hash_algo,
            base_asym_algo,
            dhe_algo,
            aead_algo,
            req_asym_algo,
            key_schedule_algo,
            other_params_support,
            session_policy,
            runtime_content_change_support,
            data_transfer_size,
            max_spdm_msg_size,
            heartbeat_period,
            secure_spdm_version,
            mel_specification,
        })
    }
}

#[derive(Debug, Default)]
pub struct SpdmNegotiateInfo {
    pub spdm_version_sel: SpdmVersion,
    pub req_capabilities_sel: SpdmRequestCapabilityFlags,
    pub rsp_capabilities_sel: SpdmResponseCapabilityFlags,
    pub req_ct_exponent_sel: u8,
    pub rsp_ct_exponent_sel: u8,
    pub measurement_specification_sel: SpdmMeasurementSpecification,
    pub measurement_hash_sel: SpdmMeasurementHashAlgo,
    pub base_hash_sel: SpdmBaseHashAlgo,
    pub base_asym_sel: SpdmBaseAsymAlgo,
    pub dhe_sel: SpdmDheAlgo,
    pub aead_sel: SpdmAeadAlgo,
    pub req_asym_sel: SpdmReqAsymAlgo,
    pub key_schedule_sel: SpdmKeyScheduleAlgo,
    pub other_params_support: SpdmAlgoOtherParams,
    pub termination_policy_set: bool, // used by responder to take action when code or configuration changed.
    pub req_data_transfer_size_sel: u32, // spdm 1.2
    pub req_max_spdm_msg_size_sel: u32, // spdm 1.2
    pub rsp_data_transfer_size_sel: u32, // spdm 1.2
    pub rsp_max_spdm_msg_size_sel: u32, // spdm 1.2
    pub mel_specification_sel: SpdmMelSpecification, // spdm 1.3
    pub multi_key_conn_req: bool,     // spdm 1.3
    pub multi_key_conn_rsp: bool,     // spdm 1.3
}

impl Codec for SpdmNegotiateInfo {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += self.spdm_version_sel.encode(writer)?;
        size += self.req_capabilities_sel.encode(writer)?;
        size += self.rsp_capabilities_sel.encode(writer)?;
        size += self.req_ct_exponent_sel.encode(writer)?;
        size += self.rsp_ct_exponent_sel.encode(writer)?;
        size += self.measurement_specification_sel.encode(writer)?;
        size += self.measurement_hash_sel.encode(writer)?;
        size += self.base_hash_sel.encode(writer)?;
        size += self.base_asym_sel.encode(writer)?;
        size += self.dhe_sel.encode(writer)?;
        size += self.aead_sel.encode(writer)?;
        size += self.req_asym_sel.encode(writer)?;
        size += self.key_schedule_sel.encode(writer)?;
        size += self.other_params_support.encode(writer)?;
        size += (self.termination_policy_set as u8).encode(writer)?;
        size += self.req_data_transfer_size_sel.encode(writer)?;
        size += self.req_max_spdm_msg_size_sel.encode(writer)?;
        size += self.rsp_data_transfer_size_sel.encode(writer)?;
        size += self.rsp_max_spdm_msg_size_sel.encode(writer)?;
        size += self.mel_specification_sel.encode(writer)?;
        size += (self.multi_key_conn_req as u8).encode(writer)?;
        size += (self.multi_key_conn_rsp as u8).encode(writer)?;
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            spdm_version_sel: SpdmVersion::read(reader)?,
            req_capabilities_sel: SpdmRequestCapabilityFlags::read(reader)?,
            rsp_capabilities_sel: SpdmResponseCapabilityFlags::read(reader)?,
            req_ct_exponent_sel: u8::read(reader)?,
            rsp_ct_exponent_sel: u8::read(reader)?,
            measurement_specification_sel: SpdmMeasurementSpecification::read(reader)?,
            measurement_hash_sel: SpdmMeasurementHashAlgo::read(reader)?,
            base_hash_sel: SpdmBaseHashAlgo::read(reader)?,
            base_asym_sel: SpdmBaseAsymAlgo::read(reader)?,
            dhe_sel: SpdmDheAlgo::read(reader)?,
            aead_sel: SpdmAeadAlgo::read(reader)?,
            req_asym_sel: SpdmReqAsymAlgo::read(reader)?,
            key_schedule_sel: SpdmKeyScheduleAlgo::read(reader)?,
            other_params_support: SpdmAlgoOtherParams::read(reader)?,
            termination_policy_set: u8::read(reader)? != 0,
            req_data_transfer_size_sel: u32::read(reader)?,
            req_max_spdm_msg_size_sel: u32::read(reader)?,
            rsp_data_transfer_size_sel: u32::read(reader)?,
            rsp_max_spdm_msg_size_sel: u32::read(reader)?,
            mel_specification_sel: SpdmMelSpecification::read(reader)?,
            multi_key_conn_req: u8::read(reader)? != 0,
            multi_key_conn_rsp: u8::read(reader)? != 0,
        })
    }
}

pub const MAX_MANAGED_BUFFER_A_SIZE: usize = 150 + 2 * 255; // for version response, there can be more than MAX_SPDM_VERSION_COUNT versions.
pub const MAX_MANAGED_BUFFER_B_SIZE: usize =
    24 + SPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_NUMBER + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE;
pub const MAX_MANAGED_BUFFER_C_SIZE: usize =
    78 + SPDM_MAX_HASH_SIZE * 2 + SPDM_MAX_ASYM_KEY_SIZE + MAX_SPDM_OPAQUE_SIZE;
pub const MAX_MANAGED_BUFFER_M_SIZE: usize = 47
    + SPDM_NONCE_SIZE
    + config::MAX_SPDM_MEASUREMENT_RECORD_SIZE
    + SPDM_MAX_ASYM_KEY_SIZE
    + MAX_SPDM_OPAQUE_SIZE;
pub const MAX_MANAGED_BUFFER_K_SIZE: usize = 84
    + SPDM_MAX_DHE_KEY_SIZE * 2
    + SPDM_MAX_HASH_SIZE * 2
    + SPDM_MAX_ASYM_KEY_SIZE
    + MAX_SPDM_OPAQUE_SIZE * 2;
pub const MAX_MANAGED_BUFFER_F_SIZE: usize = 8 + SPDM_MAX_HASH_SIZE * 2 + SPDM_MAX_ASYM_KEY_SIZE;
pub const MAX_MANAGED_BUFFER_M1M2_SIZE: usize =
    MAX_MANAGED_BUFFER_A_SIZE + MAX_MANAGED_BUFFER_B_SIZE + MAX_MANAGED_BUFFER_C_SIZE;
pub const MAX_MANAGED_BUFFER_L1L2_SIZE: usize =
    MAX_MANAGED_BUFFER_A_SIZE + MAX_MANAGED_BUFFER_M_SIZE;
pub const MAX_MANAGED_BUFFER_TH_SIZE: usize = MAX_MANAGED_BUFFER_A_SIZE
    + SPDM_MAX_HASH_SIZE
    + MAX_MANAGED_BUFFER_K_SIZE
    + SPDM_MAX_HASH_SIZE
    + MAX_MANAGED_BUFFER_F_SIZE;

pub const SPDM_VERSION_1_X_SIGNING_PREFIX_CONTEXT_SIZE: usize =
    SPDM_VERSION_SIGNING_PREFIX_LENGTH * SPDM_VERSION_SIGNING_PREFIX_NUMBER;
pub const SPDM_VERSION_1_X_SIGN_CONTEXT_SIZE: usize = 36;

pub const MAX_MANAGED_BUFFER_12SIGN_SIZE: usize = SPDM_VERSION_1_X_SIGNING_PREFIX_CONTEXT_SIZE
    + SPDM_VERSION_1_X_SIGN_CONTEXT_SIZE
    + SPDM_MAX_HASH_SIZE;

#[derive(Debug, Clone)]
pub struct ManagedBufferA(usize, [u8; MAX_MANAGED_BUFFER_A_SIZE]);

impl ManagedBufferA {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferA {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferA {
    fn default() -> Self {
        ManagedBufferA(0usize, [0u8; MAX_MANAGED_BUFFER_A_SIZE])
    }
}

impl Codec for ManagedBufferA {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += (self.0 as u64).encode(writer)?;
        size += writer.extend_from_slice(&self.1[..self.0]).ok_or(codec::EncodeErr)?;
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let data_size = u64::read(reader)? as usize;
        if data_size > MAX_MANAGED_BUFFER_A_SIZE {
            return None;
        }
        let mut data = [0u8; MAX_MANAGED_BUFFER_A_SIZE];
        for i in 0..data_size {
            data[i] = u8::read(reader)?;
        }
        Some(ManagedBufferA(data_size, data))
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferB(usize, [u8; MAX_MANAGED_BUFFER_B_SIZE]);

impl ManagedBufferB {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferB {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferB {
    fn default() -> Self {
        ManagedBufferB(0usize, [0u8; MAX_MANAGED_BUFFER_B_SIZE])
    }
}

impl Codec for ManagedBufferB {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += (self.0 as u64).encode(writer)?;
        size += writer.extend_from_slice(&self.1[..self.0]).ok_or(codec::EncodeErr)?;
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let data_size = u64::read(reader)? as usize;
        if data_size > MAX_MANAGED_BUFFER_B_SIZE {
            return None;
        }
        let mut data = [0u8; MAX_MANAGED_BUFFER_B_SIZE];
        for i in 0..data_size {
            data[i] = u8::read(reader)?;
        }
        Some(ManagedBufferB(data_size, data))
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferC(usize, [u8; MAX_MANAGED_BUFFER_C_SIZE]);

impl ManagedBufferC {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferC {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferC {
    fn default() -> Self {
        ManagedBufferC(0usize, [0u8; MAX_MANAGED_BUFFER_C_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferM(usize, [u8; MAX_MANAGED_BUFFER_M_SIZE]);

impl ManagedBufferM {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferM {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferM {
    fn default() -> Self {
        ManagedBufferM(0usize, [0u8; MAX_MANAGED_BUFFER_M_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferK(usize, [u8; MAX_MANAGED_BUFFER_K_SIZE]);

impl ManagedBufferK {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferK {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferK {
    fn default() -> Self {
        ManagedBufferK(0usize, [0u8; MAX_MANAGED_BUFFER_K_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferF(usize, [u8; MAX_MANAGED_BUFFER_F_SIZE]);

impl ManagedBufferF {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferF {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferF {
    fn default() -> Self {
        ManagedBufferF(0usize, [0u8; MAX_MANAGED_BUFFER_F_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferM1M2(usize, [u8; MAX_MANAGED_BUFFER_M1M2_SIZE]);

impl ManagedBufferM1M2 {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferM1M2 {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferM1M2 {
    fn default() -> Self {
        ManagedBufferM1M2(0usize, [0u8; MAX_MANAGED_BUFFER_M1M2_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferL1L2(usize, [u8; MAX_MANAGED_BUFFER_L1L2_SIZE]);

impl ManagedBufferL1L2 {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferL1L2 {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferL1L2 {
    fn default() -> Self {
        ManagedBufferL1L2(0usize, [0u8; MAX_MANAGED_BUFFER_L1L2_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferTH(usize, [u8; MAX_MANAGED_BUFFER_TH_SIZE]);

impl ManagedBufferTH {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBufferTH {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferTH {
    fn default() -> Self {
        ManagedBufferTH(0usize, [0u8; MAX_MANAGED_BUFFER_TH_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBuffer12Sign(usize, [u8; MAX_MANAGED_BUFFER_12SIGN_SIZE]);

impl ManagedBuffer12Sign {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBuffer12Sign {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBuffer12Sign {
    fn default() -> Self {
        ManagedBuffer12Sign(0usize, [0u8; MAX_MANAGED_BUFFER_12SIGN_SIZE])
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum SpdmMeasurementContentChanged {
    NotSupported,
    DetectedChange,
    NoChange,
}

impl Default for SpdmMeasurementContentChanged {
    fn default() -> Self {
        Self::NotSupported
    }
}

impl Codec for SpdmMeasurementContentChanged {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let value: u8 = (*self).into();
        value.encode(writer)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let value = u8::read(reader)?;
        Self::try_from(value).ok()
    }
}

impl TryFrom<u8> for SpdmMeasurementContentChanged {
    type Error = ();
    fn try_from(content_changed: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        if content_changed == 0b0000_0000 {
            Ok(Self::NotSupported)
        } else if content_changed == 0b0001_0000 {
            Ok(Self::DetectedChange)
        } else if content_changed == 0b0010_0000 {
            Ok(Self::NoChange)
        } else {
            Err(())
        }
    }
}

impl From<SpdmMeasurementContentChanged> for u8 {
    fn from(content_changed: SpdmMeasurementContentChanged) -> Self {
        match content_changed {
            SpdmMeasurementContentChanged::NotSupported => 0b0000_0000,
            SpdmMeasurementContentChanged::DetectedChange => 0b0001_0000,
            SpdmMeasurementContentChanged::NoChange => 0b0010_0000,
        }
    }
}

#[derive(Debug, Clone, Default)]
#[cfg(not(feature = "hashed-transcript-data"))]
pub struct SpdmRuntimeInfo {
    connection_state: SpdmConnectionState,
    last_session_id: Option<u32>,
    local_used_cert_chain_slot_id: u8,
    peer_used_cert_chain_slot_id: u8,
    pub need_measurement_summary_hash: bool,
    pub need_measurement_signature: bool,
    pub message_a: ManagedBufferA,
    pub message_b: ManagedBufferB,
    pub message_c: ManagedBufferC,
    pub message_m: ManagedBufferM,
    pub content_changed: SpdmMeasurementContentChanged, // used by responder, set when content changed and spdm version is 1.2.
                                                        // used by requester, consume when measurement response report content changed.
}

#[derive(Debug, Clone, Default)]
#[cfg(feature = "hashed-transcript-data")]
pub struct SpdmRuntimeInfo {
    connection_state: SpdmConnectionState,
    last_session_id: Option<u32>,
    local_used_cert_chain_slot_id: u8,
    peer_used_cert_chain_slot_id: u8,
    pub need_measurement_summary_hash: bool,
    pub need_measurement_signature: bool,
    pub message_a: ManagedBufferA,
    pub digest_context_m1m2: Option<SpdmHashCtx>, // for M1/M2
    pub digest_context_l1l2: Option<SpdmHashCtx>, // for out of session get measurement/measurement
    pub content_changed: SpdmMeasurementContentChanged, // used by responder, set when content changed and spdm version is 1.2.
                                                        // used by requester, consume when measurement response report content changed.
}

impl SpdmRuntimeInfo {
    pub fn set_connection_state(&mut self, connection_state: SpdmConnectionState) {
        self.connection_state = connection_state;
    }

    pub fn get_connection_state(&self) -> SpdmConnectionState {
        self.connection_state
    }

    pub fn set_last_session_id(&mut self, last_session_id: Option<u32>) {
        self.last_session_id = last_session_id;
    }

    pub fn get_last_session_id(&self) -> Option<u32> {
        self.last_session_id
    }

    pub fn set_peer_used_cert_chain_slot_id(&mut self, slot_id: u8) {
        self.peer_used_cert_chain_slot_id = slot_id;
    }

    pub fn get_peer_used_cert_chain_slot_id(&self) -> u8 {
        self.peer_used_cert_chain_slot_id
    }

    pub fn set_local_used_cert_chain_slot_id(&mut self, slot_id: u8) {
        self.local_used_cert_chain_slot_id = slot_id;
    }

    pub fn get_local_used_cert_chain_slot_id(&self) -> u8 {
        self.local_used_cert_chain_slot_id
    }
}

#[cfg(not(feature = "hashed-transcript-data"))]
impl Codec for SpdmRuntimeInfo {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += self.connection_state.encode(writer)?;
        size += self.last_session_id.encode(writer)?;
        size += self.local_used_cert_chain_slot_id.encode(writer)?;
        size += self.peer_used_cert_chain_slot_id.encode(writer)?;
        size += (self.need_measurement_summary_hash as u8).encode(writer)?;
        size += (self.need_measurement_signature as u8).encode(writer)?;
        size += self.message_a.encode(writer)?;
        size += self.message_b.encode(writer)?;
        size += self.message_c.encode(writer)?;
        size += self.message_m.encode(writer)?;
        size += self.content_changed.encode(writer)?;
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            connection_state: SpdmConnectionState::read(reader)?,
            last_session_id: Option::<u32>::read(reader)?,
            local_used_cert_chain_slot_id: u8::read(reader)?,
            peer_used_cert_chain_slot_id: u8::read(reader)?,
            need_measurement_summary_hash: u8::read(reader)? != 0,
            need_measurement_signature: u8::read(reader)? != 0,
            message_a: ManagedBufferA::read(reader)?,
            message_b: ManagedBufferB::read(reader)?,
            message_c: ManagedBufferC::read(reader)?,
            message_m: ManagedBufferM::read(reader)?,
            content_changed: SpdmMeasurementContentChanged::read(reader)?,
        })
    }
}

#[cfg(feature = "hashed-transcript-data")]
impl Codec for SpdmRuntimeInfo {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += self.connection_state.encode(writer)?;
        // FIXME: add bool if last_session_id is present
        size += self.last_session_id.encode(writer)?;
        size += self.local_used_cert_chain_slot_id.encode(writer)?;
        size += self.peer_used_cert_chain_slot_id.encode(writer)?;
        size += (self.need_measurement_summary_hash as u8).encode(writer)?;
        size += (self.need_measurement_signature as u8).encode(writer)?;
        size += self.message_a.encode(writer)?;
        // Option<SpdmHashCtx>
        size += match &self.digest_context_m1m2 {
            Some(ctx) => 1u8.encode(writer)? + ctx.encode(writer)?,
            None => 0u8.encode(writer)?,
        };
        size += match &self.digest_context_l1l2 {
            Some(ctx) => 1u8.encode(writer)? + ctx.encode(writer)?,
            None => 0u8.encode(writer)?,
        };
        size += self.content_changed.encode(writer)?;
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            connection_state: SpdmConnectionState::read(reader)?,
            last_session_id: Option::<u32>::read(reader)?,
            local_used_cert_chain_slot_id: u8::read(reader)?,
            peer_used_cert_chain_slot_id: u8::read(reader)?,
            need_measurement_summary_hash: u8::read(reader)? != 0,
            need_measurement_signature: u8::read(reader)? != 0,
            message_a: ManagedBufferA::read(reader)?,
            digest_context_m1m2: {
                let present = u8::read(reader)?;
                if present != 0 {
                    Some(SpdmHashCtx::read(reader)?)
                } else {
                    None
                }
            },
            digest_context_l1l2: {
                let present = u8::read(reader)?;
                if present != 0 {
                    Some(SpdmHashCtx::read(reader)?)
                } else {
                    None
                }
            },
            content_changed: SpdmMeasurementContentChanged::read(reader)?,
        })
    }
}

#[derive(Clone)]
pub struct SpdmProvisionInfo {
    pub my_cert_chain_data: [Option<SpdmCertChainData>; SPDM_MAX_SLOT_NUMBER],
    pub my_cert_chain: [Option<SpdmCertChainBuffer>; SPDM_MAX_SLOT_NUMBER],
    pub peer_root_cert_data: [Option<SpdmCertChainData>; MAX_ROOT_CERT_SUPPORT],
    pub local_supported_slot_mask: u8,
    pub local_key_pair_id: [Option<u8>; SPDM_MAX_SLOT_NUMBER],
    pub local_cert_info: [Option<SpdmCertificateModelType>; SPDM_MAX_SLOT_NUMBER],
    pub local_key_usage_bit_mask: [Option<SpdmKeyUsageMask>; SPDM_MAX_SLOT_NUMBER],
}

impl Default for SpdmProvisionInfo {
    fn default() -> Self {
        SpdmProvisionInfo {
            my_cert_chain_data: [None; SPDM_MAX_SLOT_NUMBER],
            my_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
            peer_root_cert_data: [None; MAX_ROOT_CERT_SUPPORT],
            local_supported_slot_mask: 0xff,
            local_key_pair_id: [None; SPDM_MAX_SLOT_NUMBER],
            local_cert_info: [None; SPDM_MAX_SLOT_NUMBER],
            local_key_usage_bit_mask: [None; SPDM_MAX_SLOT_NUMBER],
        }
    }
}

#[derive(Default, Debug)]
pub struct SpdmPeerInfo {
    pub peer_cert_chain: [Option<SpdmCertChainBuffer>; SPDM_MAX_SLOT_NUMBER],
    pub peer_cert_chain_temp: Option<SpdmCertChainBuffer>,
    pub peer_supported_slot_mask: u8,
    pub peer_provisioned_slot_mask: u8,
    pub peer_key_pair_id: [Option<u8>; SPDM_MAX_SLOT_NUMBER],
    pub peer_cert_info: [Option<SpdmCertificateModelType>; SPDM_MAX_SLOT_NUMBER],
    pub peer_key_usage_bit_mask: [Option<SpdmKeyUsageMask>; SPDM_MAX_SLOT_NUMBER],
}

impl Codec for SpdmPeerInfo {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        for v in &self.peer_cert_chain {
            size += v.encode(writer)?;
        }
        size += self.peer_cert_chain_temp.encode(writer)?;
        size += self.peer_supported_slot_mask.encode(writer)?;
        size += self.peer_provisioned_slot_mask.encode(writer)?;
        for v in &self.peer_key_pair_id {
            size += v.encode(writer)?;
        }
        for v in &self.peer_cert_info {
            size += v.encode(writer)?;
        }
        for v in &self.peer_key_usage_bit_mask {
            size += v.encode(writer)?;
        }
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let mut peer_cert_chain = [None; SPDM_MAX_SLOT_NUMBER];
        for v in &mut peer_cert_chain {
            *v = Option::<SpdmCertChainBuffer>::read(reader)?;
        }
        let peer_cert_chain_temp = Option::<SpdmCertChainBuffer>::read(reader)?;
        let peer_supported_slot_mask = u8::read(reader)?;
        let peer_provisioned_slot_mask = u8::read(reader)?;

        let mut peer_key_pair_id = [None; SPDM_MAX_SLOT_NUMBER];
        for v in &mut peer_key_pair_id {
            *v = Option::<u8>::read(reader)?;
        }
        let mut peer_cert_info = [None; SPDM_MAX_SLOT_NUMBER];
        for v in &mut peer_cert_info {
            *v = Option::<SpdmCertificateModelType>::read(reader)?;
        }
        let mut peer_key_usage_bit_mask = [None; SPDM_MAX_SLOT_NUMBER];
        for v in &mut peer_key_usage_bit_mask {
            *v = Option::<SpdmKeyUsageMask>::read(reader)?;
        }

        Some(Self {
            peer_cert_chain,
            peer_cert_chain_temp,
            peer_supported_slot_mask,
            peer_provisioned_slot_mask,
            peer_key_pair_id,
            peer_cert_info,
            peer_key_usage_bit_mask,
        })
    }
}

#[cfg(feature = "mut-auth")]
#[derive(Default, Debug)]
pub struct SpdmEncapContext {
    pub req_slot_id: u8,
    pub request_id: u8,
    pub encap_cert_size: u16,
}

#[cfg(feature = "mut-auth")]
impl Codec for SpdmEncapContext {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += self.req_slot_id.encode(writer)?;
        size += self.request_id.encode(writer)?;
        size += self.encap_cert_size.encode(writer)?;
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            req_slot_id: u8::read(reader)?,
            request_id: u8::read(reader)?,
            encap_cert_size: u16::read(reader)?,
        })
    }
}
