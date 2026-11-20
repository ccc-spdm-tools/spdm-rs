// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::opaque::*;
use spdmlib::common::{SpdmCodec, SpdmConnectionState};
use spdmlib::config::{MAX_SPDM_MSG_SIZE, MAX_SPDM_PSK_CONTEXT_SIZE, MAX_SPDM_PSK_HINT_SIZE};
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_handle_spdm_psk_exchange() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let challenge = &mut [0u8; 1024];
        let mut writer = Writer::init(challenge);
        let value = SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            req_session_id: 100u16,
            psk_hint: SpdmPskHintStruct {
                data_size: 32,
                data: [100u8; MAX_SPDM_PSK_HINT_SIZE],
            },
            psk_context: SpdmPskContextStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct::from_sm_supported_ver_list_opaque(
                &mut context.common,
                &SMSupportedVerListOpaque {
                    secured_message_version_list: SecuredMessageVersionList {
                        version_count: 2,
                        versions_list: [
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_10).unwrap(),
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_11).unwrap(),
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_12).unwrap(),
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_13).unwrap(),
                        ],
                    },
                },
            )
            .unwrap(),
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&challenge[0..1022]);
        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (_status, _send_buffer) = context.handle_spdm_psk_exchange(bytes, &mut writer);
    };
    executor::block_on(future);
}

#[test]
fn test_case1_handle_spdm_psk_exchange() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let challenge = &mut [0u8; 1024];
        let mut writer = Writer::init(challenge);
        let value = SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            req_session_id: 100u16,
            psk_hint: SpdmPskHintStruct {
                data_size: 32,
                data: [100u8; MAX_SPDM_PSK_HINT_SIZE],
            },
            psk_context: SpdmPskContextStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct::from_sm_supported_ver_list_opaque(
                &mut context.common,
                &SMSupportedVerListOpaque {
                    secured_message_version_list: SecuredMessageVersionList {
                        version_count: 2,
                        versions_list: [
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_10).unwrap(),
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_11).unwrap(),
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_12).unwrap(),
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_13).unwrap(),
                        ],
                    },
                },
            )
            .unwrap(),
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&challenge[0..1022]);
        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (_status, _send_buffer) = context.handle_spdm_psk_exchange(bytes, &mut writer);

        for session in context.common.session.iter() {
            assert_eq!(
                session.get_session_id(),
                spdmlib::common::INVALID_SESSION_ID
            );
        }
    };
    executor::block_on(future);
}

#[test]
fn test_case2_handle_spdm_psk_exchange_responder_context_is_random() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        context.common.negotiate_info.rsp_capabilities_sel |=
            SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let mut psk_hint = SpdmPskHintStruct {
            data_size: b"TestPskHint\0".len() as u16,
            data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
        };
        psk_hint.data[..psk_hint.data_size as usize].copy_from_slice(b"TestPskHint\0");

        let request = &mut [0u8; 1024];
        let mut writer = Writer::init(request);
        let header = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion11,
            request_response_code: SpdmRequestResponseCode::SpdmRequestPskExchange,
        };
        assert!(header.encode(&mut writer).is_ok());
        let payload = SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            req_session_id: 100u16,
            psk_hint,
            psk_context: SpdmPskContextStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct::from_sm_supported_ver_list_opaque(
                &mut context.common,
                &SMSupportedVerListOpaque {
                    secured_message_version_list: SecuredMessageVersionList {
                        version_count: 1,
                        versions_list: [
                            SecuredMessageVersion::try_from(DMTF_SECURE_SPDM_VERSION_11).unwrap(),
                            SecuredMessageVersion::default(),
                            SecuredMessageVersion::default(),
                            SecuredMessageVersion::default(),
                        ],
                    },
                },
            )
            .unwrap(),
        };
        assert!(payload
            .spdm_encode(&mut context.common, &mut writer)
            .is_ok());
        let request_size = writer.used();

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, response) =
            context.handle_spdm_psk_exchange(&request[..request_size], &mut writer);
        assert!(status.is_ok());
        let response = response.unwrap().to_vec();

        let mut reader = Reader::init(&response);
        let header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(
            header.request_response_code,
            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp
        );
        let psk_exchange_rsp =
            SpdmPskExchangeResponsePayload::spdm_read(&mut context.common, &mut reader).unwrap();

        // ResponderContext must be a fresh random value, not an all-zero buffer.
        assert_eq!(
            psk_exchange_rsp.psk_context.data_size as usize,
            MAX_SPDM_PSK_CONTEXT_SIZE
        );
        assert!(
            psk_exchange_rsp.psk_context.data[..MAX_SPDM_PSK_CONTEXT_SIZE]
                .iter()
                .any(|&b| b != 0)
        );
    };
    executor::block_on(future);
}

#[test]
fn test_case3_handle_spdm_psk_exchange_requires_psk_cap() {
    let future = async {
        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let mut psk_hint = SpdmPskHintStruct {
            data_size: b"TestPskHint\0".len() as u16,
            data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
        };
        psk_hint.data[..psk_hint.data_size as usize].copy_from_slice(b"TestPskHint\0");

        // A Responder that only offers KEY_EXCHANGE sessions must not answer PSK_EXCHANGE.
        let key_ex_only = SpdmResponseCapabilityFlags::KEY_EX_CAP;
        for (rsp_capabilities, psk_exchange_allowed) in [
            (key_ex_only, false),
            (
                key_ex_only | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT,
                true,
            ),
        ] {
            let (config_info, provision_info) = create_info();
            let mut context = responder::ResponderContext::new(
                Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
                    SharedBuffer::new(),
                )))),
                Arc::new(Mutex::new(PciDoeTransportEncap {})),
                config_info,
                provision_info,
            );
            context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
            context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
            context.common.negotiate_info.req_capabilities_sel =
                SpdmRequestCapabilityFlags::PSK_CAP;
            context.common.negotiate_info.rsp_capabilities_sel = rsp_capabilities;
            context
                .common
                .runtime_info
                .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

            let (config_info, provision_info) = create_info();
            let mut requester = RequesterContext::new(
                Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
                    SharedBuffer::new(),
                )))),
                Arc::new(Mutex::new(PciDoeTransportEncap {})),
                config_info,
                provision_info,
            );
            requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
            requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

            let mut request = [0u8; MAX_SPDM_MSG_SIZE];
            let request_size = requester
                .encode_spdm_psk_exchange(
                    100u16,
                    SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                    &psk_hint,
                    &mut request,
                )
                .unwrap();

            let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
            let mut writer = Writer::init(&mut response_buffer);
            let (status, response) =
                context.handle_spdm_psk_exchange(&request[..request_size], &mut writer);
            let mut reader = Reader::init(response.unwrap());
            let header = SpdmMessageHeader::read(&mut reader).unwrap();
            let session_count = context
                .common
                .session
                .iter()
                .filter(|s| s.get_session_id() != spdmlib::common::INVALID_SESSION_ID)
                .count();

            if psk_exchange_allowed {
                assert!(status.is_ok());
                assert_eq!(
                    header.request_response_code,
                    SpdmRequestResponseCode::SpdmResponsePskExchangeRsp
                );
                assert_eq!(session_count, 1);
            } else {
                assert!(status.is_err());
                assert_eq!(
                    header.request_response_code,
                    SpdmRequestResponseCode::SpdmResponseError
                );
                let error = SpdmMessageGeneralPayload::read(&mut reader).unwrap();
                assert_eq!(
                    error.param1,
                    SpdmErrorCode::SpdmErrorUnsupportedRequest.get_u8()
                );
                assert_eq!(session_count, 0);
            }
        }
    };
    executor::block_on(future);
}
