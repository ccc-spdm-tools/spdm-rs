// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{self, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, ResponderRunner, TestCase, TestSpdmMessage};
use codec::{Codec, Writer};
use spdmlib::common::*;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{config, responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_handle_spdm_certificate() {
    use spdmlib::config::MAX_SPDM_MSG_SIZE;

    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

        context.common.provision_info.my_cert_chain = [
            Some(SpdmCertChainBuffer {
                data_size: 512u16,
                data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
            }),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
        };
        assert!(value.encode(&mut writer).is_ok());
        let certificates_req = &mut [0u8; 1024];
        let mut writer = Writer::init(certificates_req);
        let value = SpdmGetCertificateRequestPayload {
            slot_id: 0,
            offset: 0,
            length: 200,
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());
        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&certificates_req[0..1022]);

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);
        assert!(context
            .handle_spdm_certificate(bytes, None, &mut writer)
            .0
            .is_ok());

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            use codec::Reader;
            let data = context.common.runtime_info.message_b.as_ref();
            let u8_slice = &mut [0u8; 2048];
            for (i, data) in data.iter().enumerate() {
                u8_slice[i] = *data;
            }

            let mut message_header_slice = Reader::init(u8_slice);
            let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
            assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
            assert_eq!(
                spdm_message_header.request_response_code,
                SpdmRequestResponseCode::SpdmRequestGetCertificate
            );

            let spdm_struct_slice = &u8_slice[2..];
            let mut reader = Reader::init(spdm_struct_slice);
            let spdm_get_certificate_request_payload =
                SpdmGetCertificateRequestPayload::spdm_read(&mut context.common, &mut reader)
                    .unwrap();
            assert_eq!(spdm_get_certificate_request_payload.slot_id, 100);
            assert_eq!(spdm_get_certificate_request_payload.offset, 100);
            assert_eq!(spdm_get_certificate_request_payload.length, 600);

            let spdm_message_slice = &u8_slice[8..];
            let mut reader = Reader::init(spdm_message_slice);
            let spdm_message: SpdmMessage =
                SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
            assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
            assert_eq!(
                spdm_message.header.request_response_code,
                SpdmRequestResponseCode::SpdmResponseCertificate
            );
            if let SpdmMessagePayload::SpdmCertificateResponse(payload) = &spdm_message.payload {
                assert_eq!(payload.slot_id, 100);
                assert_eq!(payload.portion_length, 412);
                assert_eq!(payload.remainder_length, 0);
                for i in 0..412 {
                    assert_eq!(payload.cert_chain[i], 0u8);
                }
            }
        }
    };
    executor::block_on(future);
}

pub fn construct_certificate_positive() -> (Vec<TestSpdmMessage>, Vec<TestSpdmMessage>) {
    use crate::protocol;
    let (config_info, provision_info) = create_info();

    let mut input = Vec::new();
    let mut expected = Vec::new();
    let cert_chain = provision_info.my_cert_chain_data[0].as_ref();
    let spdm_certificate_chain = TestCase::get_certificate_chain_buffer(
        config_info.base_hash_algo,
        cert_chain.unwrap().as_ref(),
    );
    let spdm_certificate_chain_len = spdm_certificate_chain.as_ref().len();

    const PORTION_LENGTH: usize = 0x200;
    let count = (spdm_certificate_chain.as_ref().len() + PORTION_LENGTH - 1) / PORTION_LENGTH;
    for index in 0..count {
        let offset = index * PORTION_LENGTH;
        let remainder_length = spdm_certificate_chain_len - offset;
        let portion_length = if remainder_length > PORTION_LENGTH {
            PORTION_LENGTH
        } else {
            spdm_certificate_chain_len - (index * PORTION_LENGTH)
        };

        let get_certificate_msg = TestSpdmMessage {
            message: protocol::Message::GET_CERTIFICATE(protocol::certificate::GET_CERTIFICATE {
                SPDMVersion: 0x12,
                RequestResponseCode: 0x82,
                Param1: 0,
                Param2: 0,
                Offset: offset as u16,
                Length: portion_length as u16,
            }),
            secure: 0,
        };

        let certificate_msg = TestSpdmMessage {
            message: protocol::Message::CERTIFICATE(protocol::certificate::CERTIFICATE {
                SPDMVersion: 0x12,
                RequestResponseCode: 0x02,
                Param1: 0,
                Param2: 0,
                PortionLength: portion_length as u16,
                RemainderLength: (remainder_length - portion_length) as u16,
                CertChain: spdm_certificate_chain.as_ref()[offset..(offset + portion_length)]
                    .to_vec(),
            }),
            secure: 0,
        };

        input.push(get_certificate_msg);
        expected.push(certificate_msg);
    }
    (input, expected)
}

#[test]
fn test_case1_handle_spdm_certificate() {
    let mut input = Vec::new();
    let mut expected = Vec::new();

    let (get_version_msg, version_msg) = super::version_rsp::construct_version_positive();
    let (get_capabilities_msg, capabilities_msg) =
        super::capability_rsp::consturct_capability_positive();
    let (negotiate_algorithm_msg, algorithm_msg) =
        super::algorithm_rsp::consturct_algorithm_positive();

    input.push(get_version_msg);
    expected.push(version_msg);
    input.push(get_capabilities_msg);
    expected.push(capabilities_msg);
    input.push(negotiate_algorithm_msg);
    expected.push(algorithm_msg);

    let (get_certificate_msg, certificate_msg) = construct_certificate_positive();
    input.extend(get_certificate_msg);
    expected.extend(certificate_msg);

    let case = TestCase { input, expected };
    assert!(ResponderRunner::run(
        case,
        device_io::test_header_generater_callback
    ));
}
