// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Writer};
use spdmlib::common::opaque;
use spdmlib::common::opaque::*;
use spdmlib::common::SpdmCodec;
use spdmlib::config::{MAX_SPDM_MSG_SIZE, MAX_SPDM_PSK_CONTEXT_SIZE, MAX_SPDM_PSK_HINT_SIZE};
use spdmlib::message::*;
use spdmlib::protocol::*;
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
        let mut value = SpdmPskExchangeRequestPayload {
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
                            SecuredMessageVersion {
                                major_version: 1,
                                minor_version: 0,
                                update_version_number: 0,
                                alpha: 0,
                            },
                            SecuredMessageVersion {
                                major_version: 1,
                                minor_version: 1,
                                update_version_number: 0,
                                alpha: 0,
                            },
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
        let (status, send_buffer) = context.handle_spdm_psk_exchange(bytes, &mut writer);
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
        let mut value = SpdmPskExchangeRequestPayload {
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
                            SecuredMessageVersion {
                                major_version: 1,
                                minor_version: 0,
                                update_version_number: 0,
                                alpha: 0,
                            },
                            SecuredMessageVersion {
                                major_version: 1,
                                minor_version: 1,
                                update_version_number: 0,
                                alpha: 0,
                            },
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
        let (status, send_buffer) = context.handle_spdm_psk_exchange(bytes, &mut writer);

        for session in context.common.session.iter() {
            assert_eq!(
                session.get_session_id(),
                spdmlib::common::INVALID_SESSION_ID
            );
        }
    };
    executor::block_on(future);
}
