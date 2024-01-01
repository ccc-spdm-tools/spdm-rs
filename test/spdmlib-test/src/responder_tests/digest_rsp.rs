// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{self, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, ResponderRunner, TestCase, TestSpdmMessage};
use codec::{Codec, Writer};
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{config, responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_handle_spdm_digest() {
    use spdmlib::{common::SpdmConnectionState, config::MAX_SPDM_MSG_SIZE};

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
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let bytes = &mut [0u8; 1024];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        assert!(context
            .handle_spdm_digest(bytes, None, &mut writer)
            .0
            .is_ok());
    };
    executor::block_on(future);
}

#[test]
fn test_case1_handle_spdm_digest() {
    use crate::protocol;

    let mut input = Vec::new();
    let mut expected = Vec::new();

    let (config_info, provision_info) = create_info();
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

    let get_digest_msg = TestSpdmMessage {
        message: protocol::Message::GET_DIGESTS(protocol::digest::GET_DIGESTS {
            SPDMVersion: 0x12,
            RequestResponseCode: 0x81,
            Param1: 0x0,
            Param2: 0x0,
        }),
        secure: 0,
    };

    let digest_msg = TestSpdmMessage {
        message: protocol::Message::DIGESTS(protocol::digest::DIGESTS {
            SPDMVersion: 0x12,
            RequestResponseCode: 0x01,
            Param1: 0x0,
            Param2: 0x1,
            Digest: {
                let mut digests = Vec::new();
                let cert_chain_digest = spdmlib::crypto::hash::hash_all(
                    config_info.base_hash_algo,
                    spdm_certificate_chain.as_ref(),
                )
                .expect("Must provide hash algo");
                digests.push(cert_chain_digest.as_ref().to_vec());
                digests
            },
        }),
        secure: 0,
    };

    input.push(get_digest_msg);
    expected.push(digest_msg);

    let case = TestCase { input, expected };
    assert!(ResponderRunner::run(
        case,
        device_io::test_header_generater_callback
    ));
}
