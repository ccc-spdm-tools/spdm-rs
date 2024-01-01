// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::{SpdmCodec, SpdmContext, SpdmDeviceIo, SpdmTransportEncap};
use crate::config::MAX_SPDM_MSG_SIZE;
use crate::message::SpdmMessage;
use codec::{Reader, Writer};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[allow(unused, unused_mut)]
macro_rules! create_spdm_context {
    ($context_name: ident) => {
        let transport_encap = TransportEncap {};
        let transport_encap: alloc::sync::Arc<
            spin::Mutex<dyn crate::common::SpdmTransportEncap + Send + Sync>,
        > = alloc::sync::Arc::new(spin::Mutex::new(transport_encap));
        let device_io = DeviceIO {};
        let device_io: alloc::sync::Arc<
            spin::Mutex<dyn crate::common::SpdmDeviceIo + Send + Sync>,
        > = alloc::sync::Arc::new(spin::Mutex::new(device_io));
        let config_info = SpdmConfigInfo::default();
        let provision_info = SpdmProvisionInfo::default();
        #[allow(unused, unused_mut)]
        let mut $context_name =
            SpdmContext::new(device_io, transport_encap, config_info, provision_info);
    };
}

#[allow(unused)]
pub fn new_spdm_message(value: SpdmMessage, mut context: SpdmContext) -> SpdmMessage {
    let u8_slice = &mut [0u8; MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(u8_slice);
    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    let spdm_message: SpdmMessage = SpdmMessage::spdm_read(&mut context, &mut reader).unwrap();
    spdm_message
}

#[allow(unused)]
pub(crate) use create_spdm_context;

pub struct DeviceIO;
pub struct TransportEncap;

#[maybe_async::maybe_async]
impl SpdmDeviceIo for DeviceIO {
    async fn send(&mut self, _buffer: Arc<&[u8]>) -> crate::error::SpdmResult {
        unimplemented!()
    }

    async fn receive(
        &mut self,
        _buffer: Arc<Mutex<&mut [u8]>>,
        _timeoutt: usize,
    ) -> Result<usize, usize> {
        unimplemented!()
    }

    async fn flush_all(&mut self) -> crate::error::SpdmResult {
        unimplemented!()
    }
}

#[maybe_async::maybe_async]
impl SpdmTransportEncap for TransportEncap {
    async fn encap(
        &mut self,
        _spdm_buffer: Arc<&[u8]>,
        _transport_buffer: Arc<Mutex<&mut [u8]>>,
        _secured_messagesage: bool,
    ) -> crate::error::SpdmResult<usize> {
        unimplemented!()
    }

    async fn decap(
        &mut self,
        _transport_buffer: Arc<&[u8]>,
        _spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> crate::error::SpdmResult<(usize, bool)> {
        unimplemented!()
    }

    async fn encap_app(
        &mut self,
        _spdm_buffer: Arc<&[u8]>,
        _app_buffer: Arc<Mutex<&mut [u8]>>,
        _is_app_messagesage: bool,
    ) -> crate::error::SpdmResult<usize> {
        unimplemented!()
    }

    async fn decap_app(
        &mut self,
        _app_buffer: Arc<&[u8]>,
        _spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> crate::error::SpdmResult<(usize, bool)> {
        unimplemented!()
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        unimplemented!()
    }

    fn get_max_random_count(&mut self) -> u16 {
        unimplemented!()
    }
}
