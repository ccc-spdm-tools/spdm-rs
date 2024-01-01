// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![allow(unused)]

use crate::common::crypto_callback::FAKE_RAND;
use crate::common::device_io::{self, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, ResponderRunner, TestCase, TestSpdmMessage};
use codec::{Codec, Reader, Writer};
use spdmlib::common::*;
use spdmlib::message::SpdmChallengeRequestPayload;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{config, crypto, responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_handle_spdm_challenge() {
    use spdmlib::config::MAX_SPDM_MSG_SIZE;

    use crate::common::secret_callback::SECRET_MEASUREMENT_IMPL_INSTANCE;

    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
        crypto::rand::register(FAKE_RAND.clone());

        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.provision_info.my_cert_chain = [
            Some(SpdmCertChainBuffer {
                data_size: (4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE) as u16,
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
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.runtime_info.need_measurement_summary_hash = true;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::CHAL_CAP
            | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
            | SpdmResponseCapabilityFlags::ENCRYPT_CAP
            | SpdmResponseCapabilityFlags::MAC_CAP
            | SpdmResponseCapabilityFlags::KEY_EX_CAP
            | SpdmResponseCapabilityFlags::HBEAT_CAP
            | SpdmResponseCapabilityFlags::KEY_UPD_CAP
            | SpdmResponseCapabilityFlags::ENCAP_CAP;
        context.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::ENCRYPT_CAP
            | SpdmRequestCapabilityFlags::MAC_CAP
            | SpdmRequestCapabilityFlags::KEY_EX_CAP
            | SpdmRequestCapabilityFlags::HBEAT_CAP
            | SpdmRequestCapabilityFlags::KEY_UPD_CAP
            | SpdmRequestCapabilityFlags::ENCAP_CAP;

        let spdm_message_header = &mut [0u8; 2];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let challenge = &mut [0u8; 2 + SPDM_NONCE_SIZE];
        let mut writer = Writer::init(challenge);
        let value = SpdmChallengeRequestPayload {
            slot_id: 0,
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 4 + SPDM_NONCE_SIZE];
        bytes[0..2].copy_from_slice(&spdm_message_header[0..]);
        bytes[2..4 + SPDM_NONCE_SIZE].copy_from_slice(&challenge[0..2 + SPDM_NONCE_SIZE]);

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        assert!(context.handle_spdm_challenge(bytes, &mut writer).0.is_ok());

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            let data = context.common.runtime_info.message_c.as_ref();
            let u8_slice = &mut [0u8; 4
                + SPDM_MAX_HASH_SIZE
                + SPDM_NONCE_SIZE
                + SPDM_MAX_HASH_SIZE
                + 2
                + MAX_SPDM_OPAQUE_SIZE
                + SPDM_MAX_ASYM_KEY_SIZE];
            for (i, data) in data.iter().enumerate() {
                u8_slice[i] = *data;
            }

            let mut message_header_slice = Reader::init(u8_slice);
            let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
            assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
            assert_eq!(
                spdm_message_header.request_response_code,
                SpdmRequestResponseCode::SpdmRequestChallenge
            );

            let spdm_struct_slice = &u8_slice[2..];
            let mut reader = Reader::init(spdm_struct_slice);
            let spdm_challenge_request_payload =
                SpdmChallengeRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
            assert_eq!(spdm_challenge_request_payload.slot_id, 100);
            assert_eq!(
                spdm_challenge_request_payload.measurement_summary_hash_type,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll
            );
            for i in 0..SPDM_NONCE_SIZE {
                assert_eq!(spdm_challenge_request_payload.nonce.data[i], 100u8);
            }

            let spdm_message_slice = &u8_slice[4 + SPDM_NONCE_SIZE..];
            let mut reader = Reader::init(spdm_message_slice);
            let spdm_message: SpdmMessage =
                SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
            assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
            assert_eq!(
                spdm_message.header.request_response_code,
                SpdmRequestResponseCode::SpdmResponseChallengeAuth
            );

            let cert_chain_hash = crypto::hash::hash_all(
                context.common.negotiate_info.base_hash_sel,
                context
                    .common
                    .provision_info
                    .my_cert_chain
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();

            if let SpdmMessagePayload::SpdmChallengeAuthResponse(payload) = &spdm_message.payload {
                assert_eq!(payload.slot_id, 0x0);
                assert_eq!(payload.slot_mask, 0x1);
                assert_eq!(
                    payload.challenge_auth_attribute,
                    SpdmChallengeAuthAttribute::empty()
                );
                assert_eq!(
                    payload.measurement_summary_hash.data_size,
                    SHA384_DIGEST_SIZE
                );
                assert_eq!(payload.opaque.data_size, 0);
                assert_eq!(payload.signature.data_size, SECP_384_R1_KEY_SIZE);
                for i in 0..SHA384_DIGEST_SIZE {
                    assert_eq!(payload.measurement_summary_hash.data[i], 0xaau8);
                }
                for (i, data) in cert_chain_hash.data.iter().enumerate() {
                    assert_eq!(payload.cert_chain_hash.data[i], *data);
                }
            }
        }
    };
    executor::block_on(future);
}

#[test]
fn test_case1_handle_spdm_challenge() {
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

    let challenge_msg = TestSpdmMessage {
        message: protocol::Message::CHALLENGE(protocol::challenge::CHALLENGE {
            SPDMVersion: 0x12,
            RequestResponseCode: 0x83,
            Param1: 0,
            Param2: 0,
            Nonce: [0u8; 32],
        }),
        secure: 0,
    };

    let sig_len = config_info.base_asym_algo.get_size() as usize;
    let challenge_auth_msg = TestSpdmMessage {
        message: protocol::Message::CHALLENGE_AUTH(protocol::challenge::CHALLENGE_AUTH {
            SPDMVersion: 0x12,
            RequestResponseCode: 0x3,
            Param1: 0,
            Param2: 1,
            CertChainHash: {
                let cert_chain_digest = spdmlib::crypto::hash::hash_all(
                    config_info.base_hash_algo,
                    spdm_certificate_chain.as_ref(),
                )
                .expect("Must provide hash algo");
                cert_chain_digest.as_ref().to_vec()
            },
            Nonce: [0xFF; 32],
            MeasurementSummaryHash: Vec::new(),
            OpaqueDataLength: 0,
            OpaqueData: Vec::new(),
            Signature: vec![0x5a; sig_len],
        }),
        secure: 0,
    };

    input.push(challenge_msg);
    expected.push(challenge_auth_msg);

    let case = TestCase { input, expected };
    assert!(ResponderRunner::run(
        case,
        device_io::test_header_generater_callback
    ));
}
