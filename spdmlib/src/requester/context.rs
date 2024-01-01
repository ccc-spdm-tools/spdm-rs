// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::{self, SpdmDeviceIo, SpdmTransportEncap};
use crate::common::{ManagedBufferA, ST1};
use crate::config;
use crate::error::{SpdmResult, SPDM_STATUS_RECEIVE_FAIL, SPDM_STATUS_SEND_FAIL};
use crate::protocol::*;

use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

pub struct RequesterContext {
    pub common: common::SpdmContext,
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
                    self.session_based_mutual_authenticate(session_id).await?;
                    Some(self.common.runtime_info.get_local_used_cert_chain_slot_id())
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
        if self.common.negotiate_info.rsp_data_transfer_size_sel != 0
            && send_buffer.len() > self.common.negotiate_info.rsp_data_transfer_size_sel as usize
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
                .decode_secured_message(session_id, &transport_buffer[..used], receive_buffer)
                .await
        } else {
            self.common
                .decap(&transport_buffer[..used], receive_buffer)
                .await
        }
    }
}
