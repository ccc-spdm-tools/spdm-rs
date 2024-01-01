// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::*;
use crate::common::util::create_info;
use codec::{Codec, Writer};
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::*;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{config, responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_send_secured_message() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    let rsp_session_id = 0xffu16;
    let session_id = (0xffu32 << 16) + rsp_session_id as u32;
    context.common.session = gen_array_clone(SpdmSession::new(), 4);
    context.common.session[0].setup(session_id).unwrap();
    context.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

    let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(&mut send_buffer);
    let value = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
        },
        payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
            key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
            tag: 100u8,
        }),
    };
    assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());
    let used = writer.used();
    let status = context
        .send_secured_message(session_id, &send_buffer[0..used], false)
        .is_ok();
    assert!(status);
}
#[test]
fn test_case1_send_secured_message() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    let rsp_session_id = 0xffu16;
    let session_id = (0xffu32 << 16) + rsp_session_id as u32;

    let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(&mut send_buffer);
    let value = SpdmMessage {
        header: SpdmMessageHeader::default(),
        payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload::default()),
    };
    assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());
    let used = writer.used();
    let status = context
        .send_secured_message(session_id, &send_buffer[0..used], false)
        .is_err();
    assert!(status);
}
#[test]
fn test_case0_receive_message() {
    let receive_buffer = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
    let mut writer = Writer::init(receive_buffer);
    let value = PciDoeMessageHeader {
        vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
        data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm,
        payload_length: 100,
    };
    assert!(value.encode(&mut writer).is_ok());

    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    shared_buffer.set_buffer(receive_buffer);

    let socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    let mut receive_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
    let status = context
        .receive_message(&mut receive_buffer[..], ST1)
        .is_ok();
    assert!(status);
}
#[test]
fn test_case0_process_message() {
    let receive_buffer = &mut [0u8; 1024];
    let mut writer = Writer::init(receive_buffer);
    let value = PciDoeMessageHeader {
        vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
        data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm,
        payload_length: 100,
    };
    assert!(value.encode(&mut writer).is_ok());

    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    shared_buffer.set_buffer(receive_buffer);

    let socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    let rsp_session_id = 0xFFFEu16;
    let session_id = (0xffu32 << 16) + rsp_session_id as u32;
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.session = gen_array_clone(SpdmSession::new(), 4);
    context.common.session[0].setup(session_id).unwrap();
    context.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);

    let status = context.process_message(false, &[0]).is_err();
    assert!(status);
}
#[test]
fn test_case0_dispatch_secured_message() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

    let rsp_session_id = 0xFFFEu16;
    let session_id = (0xffu32 << 16) + rsp_session_id as u32;
    let patch_context = |context: &mut SpdmContext| {
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        context.negotiate_info.measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        context.session = gen_array_clone(SpdmSession::new(), 4);
        context.session[0].setup(session_id).unwrap();
        context.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.provision_info.my_cert_chain = [
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
    };

    let mut i = 0;
    loop {
        let (request_response_code, connection_state) = dispatch_data(i, true);
        if request_response_code == SpdmRequestResponseCode::Unknown(0) {
            break;
        }
        context
            .common
            .runtime_info
            .set_connection_state(connection_state);
        let bytes = &mut [0u8; 4];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code,
        };
        // version request will reset spdm context.
        // negotiate need be done successfully before sending some request(digest).
        // patch spdm context for it.
        patch_context(&mut context.common);
        assert!(value.encode(&mut writer).is_ok());
        let status = context.dispatch_message(bytes);
        assert!(status.is_ok());
        i += 1;
    }
    let mut i = 0;
    loop {
        let (request_response_code, connection_state) = dispatch_data(i, false);
        if request_response_code == SpdmRequestResponseCode::Unknown(0) {
            break;
        }
        context
            .common
            .runtime_info
            .set_connection_state(connection_state);
        let bytes = &mut [0u8; 4];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code,
        };
        assert!(value.encode(&mut writer).is_ok());
        let status = context.dispatch_message(bytes);
        assert!(status.is_ok());
        // TBD: check if error message is turned.
        i += 1;
    }

    let mut i = 0;
    loop {
        let (request_response_code, connection_state, session_state) =
            dispatch_secured_data(i, true);
        if request_response_code == SpdmRequestResponseCode::Unknown(0) {
            break;
        }
        context
            .common
            .runtime_info
            .set_connection_state(connection_state);
        context.common.session[0].set_session_state(session_state);
        let bytes = &mut [0u8; 4];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code,
        };
        assert!(value.encode(&mut writer).is_ok());
        let status_secured = context.dispatch_secured_message(session_id, bytes);
        assert!(status_secured.is_ok());
        i += 1;
    }
    let mut i = 0;
    loop {
        let (request_response_code, connection_state, session_state) =
            dispatch_secured_data(i, false);
        if request_response_code == SpdmRequestResponseCode::Unknown(0) {
            break;
        }
        context
            .common
            .runtime_info
            .set_connection_state(connection_state);
        context.common.session[0].set_session_state(session_state);
        let bytes = &mut [0u8; 4];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code,
        };
        assert!(value.encode(&mut writer).is_ok());
        let status_secured = context.dispatch_secured_message(session_id, bytes);
        assert!(status_secured.is_err());
        i += 1;
    }
}

fn dispatch_secured_data(
    num: usize,
    status: bool,
) -> (
    SpdmRequestResponseCode,
    SpdmConnectionState,
    SpdmSessionState,
) {
    let response_true = [
        (
            SpdmRequestResponseCode::SpdmRequestFinish,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestPskFinish,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetDigests,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetCertificate,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestHeartbeat,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestEndSession,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::Unknown(0),
            SpdmConnectionState::SpdmConnectionNotStarted,
            SpdmSessionState::SpdmSessionNotStarted,
        ),
    ];
    let response_flase = [
        (
            SpdmRequestResponseCode::SpdmRequestGetVersion,
            SpdmConnectionState::SpdmConnectionNotStarted,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            SpdmConnectionState::SpdmConnectionAfterVersion,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            SpdmConnectionState::SpdmConnectionAfterCapabilities,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestChallenge,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestKeyExchange,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestPskExchange,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetDigests,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetCertificate,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestHeartbeat,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestEndSession,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionHandshaking,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetVersion,
            SpdmConnectionState::SpdmConnectionNotStarted,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            SpdmConnectionState::SpdmConnectionAfterVersion,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            SpdmConnectionState::SpdmConnectionAfterCapabilities,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestChallenge,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestKeyExchange,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestPskExchange,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestFinish,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestPskFinish,
            SpdmConnectionState::SpdmConnectionNegotiated,
            SpdmSessionState::SpdmSessionEstablished,
        ),
        (
            SpdmRequestResponseCode::Unknown(0),
            SpdmConnectionState::SpdmConnectionNotStarted,
            SpdmSessionState::SpdmSessionNotStarted,
        ),
    ];
    if status {
        response_true[num]
    } else {
        response_flase[num]
    }
}
fn dispatch_data(num: usize, status: bool) -> (SpdmRequestResponseCode, SpdmConnectionState) {
    let response_true = [
        (
            SpdmRequestResponseCode::SpdmRequestGetVersion,
            SpdmConnectionState::SpdmConnectionNotStarted,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            SpdmConnectionState::SpdmConnectionAfterVersion,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            SpdmConnectionState::SpdmConnectionAfterCapabilities,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetDigests,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetCertificate,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestChallenge,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestKeyExchange,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestPskExchange,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::Unknown(0),
            SpdmConnectionState::SpdmConnectionNotStarted,
        ),
    ];
    let response_flase = [
        (
            SpdmRequestResponseCode::SpdmRequestFinish,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestPskFinish,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestHeartbeat,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::SpdmRequestEndSession,
            SpdmConnectionState::SpdmConnectionNegotiated,
        ),
        (
            SpdmRequestResponseCode::Unknown(0),
            SpdmConnectionState::SpdmConnectionNotStarted,
        ),
    ];
    if status {
        response_true[num]
    } else {
        response_flase[num]
    }
}
