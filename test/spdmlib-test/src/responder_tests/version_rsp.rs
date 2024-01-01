// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, TestSpdmMessage};
use codec::{Codec, Reader, Writer};
use spdmlib::common::*;
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_handle_spdm_version() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let bytes = &mut [0u8; 1024];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        context.handle_spdm_version(bytes, &mut writer);

        let data = context.common.runtime_info.message_a.as_ref();
        let u8_slice = &mut [0u8; 1024];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut reader = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );

        let u8_slice = &u8_slice[4..];
        let mut reader = Reader::init(u8_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();

        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseVersion
        );
        if let SpdmMessagePayload::SpdmVersionResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.version_number_entry_count, 0x03);
            assert_eq!(payload.versions[0].update, 0);
            assert_eq!(payload.versions[0].version, SpdmVersion::SpdmVersion10);
            assert_eq!(payload.versions[1].update, 0);
            assert_eq!(payload.versions[1].version, SpdmVersion::SpdmVersion11);
            assert_eq!(payload.versions[2].update, 0);
            assert_eq!(payload.versions[2].version, SpdmVersion::SpdmVersion12);
        }
    };
    executor::block_on(future);
}

pub fn construct_version_positive() -> (TestSpdmMessage, TestSpdmMessage) {
    use crate::protocol;
    let get_version_msg = TestSpdmMessage {
        message: protocol::Message::GET_VERSION(protocol::version::GET_VERSION {
            SPDMVersion: 0x10,
            RequestResponseCode: 0x84,
            Param1: 0,
            Param2: 0,
        }),
        secure: 0,
    };
    let (config_info, provision_info) = create_info();
    let mut VersionNumberEntryCount = 0;
    let mut VersionNumberEntry: [u16; MAX_SPDM_VERSION_COUNT] = gen_array_clone(
        u8::from(SpdmVersion::default()) as u16,
        MAX_SPDM_VERSION_COUNT,
    );
    for (_, v) in config_info.spdm_version.iter().flatten().enumerate() {
        VersionNumberEntry[VersionNumberEntryCount] = (u8::from(*v) as u16) << 8;
        VersionNumberEntryCount += 1;
    }
    let version_msg = TestSpdmMessage {
        message: protocol::Message::VERSION(protocol::version::VERSION {
            SPDMVersion: 0x10,
            RequestResponseCode: 0x04,
            Param1: 0,
            Param2: 0,
            Reserved: 0,
            VersionNumberEntryCount: VersionNumberEntryCount as u8,
            VersionNumberEntry: VersionNumberEntry.to_vec(),
        }),
        secure: 0,
    };
    (get_version_msg, version_msg)
}
