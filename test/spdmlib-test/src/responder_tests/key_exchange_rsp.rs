// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::crypto_callback::FAKE_HMAC;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, get_rsp_cert_chain_buff};
use bytes::BytesMut;
use codec::{Codec, Reader, Writer};
use spdmlib::common::opaque::*;
use spdmlib::common::{SpdmCodec, SpdmConnectionState};
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
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
        secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
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
        let value = SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb,
            slot_id: 4,
            req_session_id: 0xffu16,
            session_policy: 1,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmReqExchangeStruct::from_dhe(SpdmDheExchangeStruct::from(public_key)),
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
        let _ = value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&key_exchange[0..1022]);

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (_status, _send_buffer) = context.handle_spdm_key_exchange(bytes, &mut writer);
    };
    executor::block_on(future);
}

#[test]
fn test_case1_handle_spdm_key_exchange() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
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
        let value = SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb,
            slot_id: 0u8,
            req_session_id: 0xffu16,
            session_policy: 1,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmReqExchangeStruct::from_dhe(SpdmDheExchangeStruct::from(public_key)),
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
        let _ = value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&key_exchange[0..1022]);

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (_status, _send_buffer) = context.handle_spdm_key_exchange(bytes, &mut writer);

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
fn test_case2_handle_spdm_key_exchange_requires_key_ex_cap() {
    let future = async {
        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

        // A Responder that only offers PSK sessions must not answer KEY_EXCHANGE.
        let psk_only = SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT;
        for (rsp_capabilities, key_exchange_allowed) in [
            (psk_only, false),
            (psk_only | SpdmResponseCapabilityFlags::KEY_EX_CAP, true),
        ] {
            let (config_info, provision_info) = create_info();
            let mut responder = responder::ResponderContext::new(
                Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
                    SharedBuffer::new(),
                )))),
                Arc::new(Mutex::new(PciDoeTransportEncap {})),
                config_info,
                provision_info,
            );
            responder.common.provision_info.my_cert_chain[0] = Some(get_rsp_cert_chain_buff());
            responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
            responder.common.negotiate_info.req_capabilities_sel =
                SpdmRequestCapabilityFlags::KEY_EX_CAP;
            responder.common.negotiate_info.rsp_capabilities_sel = rsp_capabilities;
            responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            responder.common.negotiate_info.base_asym_sel =
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
            responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
            responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
            responder.common.negotiate_info.other_params_support =
                SpdmAlgoOtherParams::OPAQUE_DATA_FMT1;
            responder.common.reset_runtime_info();
            responder
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
            requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
            requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
            requester.common.negotiate_info.other_params_support =
                SpdmAlgoOtherParams::OPAQUE_DATA_FMT1;
            requester.common.reset_runtime_info();

            let mut request = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
            let (_, _, request_size) = requester
                .init_spdm_key_exchange(
                    0,
                    SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                    &mut request,
                )
                .unwrap();

            let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
            let mut writer = Writer::init(&mut response_buffer);
            let (status, response) =
                responder.handle_spdm_key_exchange(&request[..request_size], &mut writer);
            let mut reader = Reader::init(response.unwrap());
            let header = SpdmMessageHeader::read(&mut reader).unwrap();
            let session_count = responder
                .common
                .session
                .iter()
                .filter(|s| s.get_session_id() != spdmlib::common::INVALID_SESSION_ID)
                .count();

            if key_exchange_allowed {
                assert!(status.is_ok());
                assert_eq!(
                    header.request_response_code,
                    SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp
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
