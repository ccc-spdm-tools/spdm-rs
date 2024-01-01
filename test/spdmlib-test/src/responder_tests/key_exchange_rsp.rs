// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::crypto_callback::FAKE_HMAC;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use bytes::BytesMut;
use codec::{Codec, Writer};
use spdmlib::common::opaque::*;
use spdmlib::common::SpdmCodec;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{crypto, responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
#[cfg(not(feature = "hashed-transcript-data"))]
fn test_case0_handle_spdm_key_exchange() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        crypto::hmac::register(FAKE_HMAC.clone());

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

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        let _ = value.encode(&mut writer);

        let rng = ring::rand::SystemRandom::new();
        let private_key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
                .ok()
                .unwrap();
        let public_key_old = private_key.compute_public_key().ok().unwrap();
        let public_key = BytesMut::from(&public_key_old.as_ref()[1..]);

        let key_exchange: &mut [u8; 1024] = &mut [0u8; 1024];
        let mut writer = Writer::init(key_exchange);
        let mut value = SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb,
            slot_id: 100u8,
            req_session_id: 0xffu16,
            session_policy: 1,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct::from(public_key),
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
        let _ = value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&key_exchange[0..1022]);

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, send_buffer) = context.handle_spdm_key_exchange(bytes, &mut writer);
    };
    executor::block_on(future);
}

#[test]
fn test_case1_handle_spdm_key_exchange() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        crypto::hmac::register(FAKE_HMAC.clone());

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

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestKeyExchange,
        };
        let _ = value.encode(&mut writer);

        let rng = ring::rand::SystemRandom::new();
        let private_key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
                .ok()
                .unwrap();
        let public_key_old = private_key.compute_public_key().ok().unwrap();
        let public_key = BytesMut::from(&public_key_old.as_ref()[1..]);

        let key_exchange: &mut [u8; 1024] = &mut [0u8; 1024];
        let mut writer = Writer::init(key_exchange);
        let mut value = SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb,
            slot_id: 0u8,
            req_session_id: 0xffu16,
            session_policy: 1,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct::from(public_key),
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
        let _ = value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&key_exchange[0..1022]);

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, send_buffer) = context.handle_spdm_key_exchange(bytes, &mut writer);

        for session in context.common.session.iter() {
            assert_eq!(
                session.get_session_id(),
                spdmlib::common::INVALID_SESSION_ID
            );
        }
    };
    executor::block_on(future);
}
