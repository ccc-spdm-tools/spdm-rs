// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::enum_builder;
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmTransportEncap;
use spdmlib::error::{
    SpdmResult, SPDM_STATUS_DECAP_APP_FAIL, SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_ENCAP_APP_FAIL,
    SPDM_STATUS_ENCAP_FAIL,
};
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::Deref;
use core::ops::DerefMut;
use spin::Mutex;

enum_builder! {
    @U8
    EnumName: MctpMessageType;
    EnumVal{
        MctpMessageTypeMctpControl => 0x00,
        MctpMessageTypePldm => 0x01,
        MctpMessageTypeNcsi => 0x02,
        MctpMessageTypeEthernet => 0x03,
        MctpMessageTypeNvme => 0x04,
        MctpMessageTypeSpdm => 0x05,
        MctpMessageTypeSecuredMctp => 0x06,
        MctpMessageTypeVendorDefinedPci => 0x7E,
        MctpMessageTypeVendorDefinedIana => 0x7F
    }
}
impl Default for MctpMessageType {
    fn default() -> MctpMessageType {
        MctpMessageType::MctpMessageTypeMctpControl
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MctpMessageHeader {
    pub r#type: MctpMessageType,
}

impl Codec for MctpMessageHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.r#type.encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<MctpMessageHeader> {
        let r#type = MctpMessageType::read(r)?;
        Some(MctpMessageHeader { r#type })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MctpTransportEncap {}

#[maybe_async::maybe_async]
impl SpdmTransportEncap for MctpTransportEncap {
    async fn encap(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        transport_buffer: Arc<Mutex<&mut [u8]>>,
        secured_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let mut transport_buffer = transport_buffer.lock();
        let transport_buffer = transport_buffer.deref_mut();
        let mut writer = Writer::init(transport_buffer);
        let mctp_header = MctpMessageHeader {
            r#type: if secured_message {
                MctpMessageType::MctpMessageTypeSecuredMctp
            } else {
                MctpMessageType::MctpMessageTypeSpdm
            },
        };
        mctp_header
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_ENCAP_FAIL)?;
        let header_size = writer.used();
        if transport_buffer.len() < header_size + payload_len {
            return Err(SPDM_STATUS_ENCAP_FAIL);
        }
        transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(&spdm_buffer);
        Ok(header_size + payload_len)
    }

    async fn decap(
        &mut self,
        transport_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let transport_buffer: &[u8] = transport_buffer.deref();
        let mut reader = Reader::init(transport_buffer);
        let secured_message;
        match MctpMessageHeader::read(&mut reader) {
            Some(mctp_header) => match mctp_header.r#type {
                MctpMessageType::MctpMessageTypeSpdm => {
                    secured_message = false;
                }
                MctpMessageType::MctpMessageTypeSecuredMctp => {
                    secured_message = true;
                }
                _ => return Err(SPDM_STATUS_DECAP_FAIL),
            },
            None => return Err(SPDM_STATUS_DECAP_FAIL),
        }
        let header_size = reader.used();
        let payload_size = transport_buffer.len() - header_size;
        let mut spdm_buffer = spdm_buffer.lock();
        let spdm_buffer = spdm_buffer.deref_mut();
        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        let payload = &transport_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, secured_message))
    }

    async fn encap_app(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        app_buffer: Arc<Mutex<&mut [u8]>>,
        is_app_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let mut app_buffer = app_buffer.lock();
        let app_buffer = app_buffer.deref_mut();
        let mut writer = Writer::init(app_buffer);
        let mctp_header = if is_app_message {
            MctpMessageHeader {
                r#type: MctpMessageType::MctpMessageTypePldm,
            }
        } else {
            MctpMessageHeader {
                r#type: MctpMessageType::MctpMessageTypeSpdm,
            }
        };
        mctp_header
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_ENCAP_APP_FAIL)?;
        let header_size = writer.used();
        if app_buffer.len() < header_size + payload_len {
            return Err(SPDM_STATUS_ENCAP_APP_FAIL);
        }
        app_buffer[header_size..(header_size + payload_len)].copy_from_slice(&spdm_buffer);
        Ok(header_size + payload_len)
    }

    async fn decap_app(
        &mut self,
        app_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(&app_buffer);
        let mut is_app_mesaage = false;
        match MctpMessageHeader::read(&mut reader) {
            Some(mctp_header) => match mctp_header.r#type {
                MctpMessageType::MctpMessageTypeSpdm => {}
                MctpMessageType::MctpMessageTypePldm => {
                    is_app_mesaage = true;
                }
                _ => return Err(SPDM_STATUS_DECAP_APP_FAIL),
            },
            None => return Err(SPDM_STATUS_DECAP_APP_FAIL),
        }
        let header_size = reader.used();
        let payload_size = app_buffer.len() - header_size;
        let mut spdm_buffer = spdm_buffer.lock();
        let spdm_buffer = spdm_buffer.deref_mut();
        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_DECAP_APP_FAIL);
        }
        let payload = &app_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, is_app_mesaage))
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        2
    }
    fn get_max_random_count(&mut self) -> u16 {
        32
    }
}

#[cfg(test)]
mod tests {
    use spdmlib::config;

    use super::*;

    #[test]
    fn test_case0_mctpmessageheader() {
        let u8_slice = &mut [0u8; 1];
        let mut writer = Writer::init(u8_slice);
        let value = MctpMessageHeader {
            r#type: MctpMessageType::MctpMessageTypeMctpControl,
        };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(1, reader.left());
        let mctp_message_header = MctpMessageHeader::read(&mut reader).unwrap();
        assert_eq!(0, reader.left());
        assert_eq!(
            mctp_message_header.r#type,
            MctpMessageType::MctpMessageTypeMctpControl
        );
    }
    #[test]
    fn test_case0_encap() {
        use crate::header::tests::alloc::sync::Arc;
        extern crate alloc;
        use core::ops::DerefMut;
        use spin::Mutex;

        {
            let mut mctp_transport_encap = MctpTransportEncap {};
            let mut transport_buffer = [100u8; config::SENDER_BUFFER_SIZE];
            let spdm_buffer = [100u8; config::MAX_SPDM_MSG_SIZE];

            let status = executor::block_on(mctp_transport_encap.encap(
                &spdm_buffer,
                &mut transport_buffer,
                false,
            ))
            .is_ok();
            assert!(status);
        }

        {
            let mut mctp_transport_encap = MctpTransportEncap {};
            let mut transport_buffer = [100u8; config::SENDER_BUFFER_SIZE];
            let spdm_buffer = [100u8; config::MAX_SPDM_MSG_SIZE];

            let status = executor::block_on(mctp_transport_encap.encap(
                &spdm_buffer,
                &mut transport_buffer,
                true,
            ))
            .is_ok();
            assert!(status);
        }

        {
            let mut mctp_transport_encap = MctpTransportEncap {};
            let mut transport_buffer = [100u8; config::SENDER_BUFFER_SIZE];
            let spdm_buffer = [100u8; config::SENDER_BUFFER_SIZE];

            let status = executor::block_on(mctp_transport_encap.encap(
                &spdm_buffer,
                &mut transport_buffer,
                true,
            ))
            .is_ok();
            assert!(status);
        }
    }
    #[test]
    fn test_case0_decap() {
        let mut mctp_transport_encap = MctpTransportEncap {};

        let mut spdm_buffer = [100u8; config::MAX_SPDM_MSG_SIZE];

        let transport_buffer = &mut [0u8; 10];

        let status =
            executor::block_on(mctp_transport_encap.decap(transport_buffer, &mut spdm_buffer))
                .is_err();
        assert!(status);

        let mut writer = Writer::init(transport_buffer);
        let value = MctpMessageHeader {
            r#type: MctpMessageType::MctpMessageTypeSpdm,
        };
        assert!(value.encode(&mut writer).is_ok());

        let status =
            executor::block_on(mctp_transport_encap.decap(transport_buffer, &mut spdm_buffer))
                .is_ok();
        assert!(status);

        let transport_buffer = &mut [0u8; 2];
        let mut writer = Writer::init(transport_buffer);
        let value = MctpMessageHeader {
            r#type: MctpMessageType::MctpMessageTypeSecuredMctp,
        };
        assert!(value.encode(&mut writer).is_ok());

        let status =
            executor::block_on(mctp_transport_encap.decap(transport_buffer, &mut spdm_buffer))
                .is_ok();
        assert!(status);
    }
    #[test]
    fn test_case0_encap_app() {
        let mut mctp_transport_encap = MctpTransportEncap {};
        let mut app_buffer = [0u8; 100];
        let spdm_buffer = [0u8; 10];

        let status = executor::block_on(mctp_transport_encap.encap_app(
            &spdm_buffer,
            &mut app_buffer,
            false,
        ))
        .is_ok();
        assert!(status);

        let spdm_buffer = [100u8; config::MAX_SPDM_MSG_SIZE];

        let status = executor::block_on(mctp_transport_encap.encap_app(
            &spdm_buffer,
            &mut app_buffer,
            false,
        ))
        .is_err();
        assert!(status);
    }
    #[test]
    fn test_case0_decap_app() {
        let mut mctp_transport_encap = MctpTransportEncap {};

        let mut spdm_buffer = [100u8; config::MAX_SPDM_MSG_SIZE];

        let transport_buffer = &mut [0u8; 10];

        let status =
            executor::block_on(mctp_transport_encap.decap_app(transport_buffer, &mut spdm_buffer))
                .is_err();
        assert!(status);

        let mut writer = Writer::init(transport_buffer);
        let value = MctpMessageHeader {
            r#type: MctpMessageType::MctpMessageTypeSpdm,
        };
        assert!(value.encode(&mut writer).is_ok());

        let status =
            executor::block_on(mctp_transport_encap.decap_app(transport_buffer, &mut spdm_buffer))
                .is_ok();
        assert!(status);
    }
    #[test]
    fn test_case0_get_sequence_number_count() {
        let mut mctp_transport_encap = MctpTransportEncap {};
        assert_eq!(mctp_transport_encap.get_sequence_number_count(), 2);
    }
    #[test]
    fn test_case0_get_max_random_count() {
        let mut mctp_transport_encap = MctpTransportEncap {};
        assert_eq!(mctp_transport_encap.get_max_random_count(), 32);
    }
}
