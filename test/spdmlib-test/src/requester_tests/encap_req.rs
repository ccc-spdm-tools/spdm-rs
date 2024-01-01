// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::crypto_callback::FAKE_HMAC;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::session::{self, SpdmSession};
use spdmlib::common::{
    SpdmCodec, SpdmConfigInfo, SpdmConnectionState, SpdmDeviceIo, SpdmProvisionInfo,
    SpdmTransportEncap,
};
use spdmlib::config;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{crypto, message::*, secret};

use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

const SESSION_ID: u32 = 4294901758;
const CERT_PORTION_LEN: usize = 512;

#[test]
fn test_send_get_encapsulated_request() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = PciDoeTransportEncap {};
        let pcidoe_transport_encap = Arc::new(Mutex::new(pcidoe_transport_encap));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let mut context = setup_test_context_and_session(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        assert!(context
            .send_get_encapsulated_request(SESSION_ID)
            .await
            .is_ok());

        // Get data sent by requester and decode the secured message
        let receive: &mut [u8] = &mut [0u8; config::MAX_SPDM_MSG_SIZE];

        let receive_size = {
            let mut device_io = context.common.device_io.lock();
            let device_io = device_io.deref_mut();
            device_io
                .receive(Arc::new(Mutex::new(receive)), 0)
                .await
                .unwrap()
        };

        let request = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let size = context
            .common
            .decode_secured_message(SESSION_ID, &receive[..receive_size], request)
            .await
            .unwrap();

        let mut reader = Reader::init(&request[..size]);
        let header = SpdmMessageHeader::read(&mut reader).unwrap();
        let payload =
            SpdmGetEncapsulatedRequestPayload::spdm_read(&mut context.common, &mut reader);
        assert_eq!(header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest
        );
        assert!(payload.is_some());
    };
    executor::block_on(future);
}

#[test]
fn test_receive_encapsulated_request() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let mut context = setup_test_context_and_session(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        // Encode the spdm message sent by responder
        let response = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(response);
        let header = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmResponseEncapsulatedRequest,
        };
        assert!(header.encode(&mut writer).is_ok());
        let payload = SpdmEncapsulatedRequestPayload { request_id: 0xa };
        assert!(payload
            .spdm_encode(&mut context.common, &mut writer)
            .is_ok());
        let encap_header = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestGetDigests,
        };
        assert!(encap_header.encode(&mut writer).is_ok());
        let encap_payload = SpdmGetDigestsRequestPayload {};
        assert!(encap_payload
            .spdm_encode(&mut context.common, &mut writer)
            .is_ok());

        // Set the data from responder to device io and encode as secured message
        let send = &mut [0u8; config::SENDER_BUFFER_SIZE];
        let size = context
            .common
            .encode_secured_message(SESSION_ID, writer.used_slice(), send, true, false)
            .await
            .unwrap();

        {
            let mut device_io = context.common.device_io.lock();
            let device_io = device_io.deref_mut();
            assert!(device_io.send(Arc::new(&send[..size])).await.is_ok());
        }

        assert!(context
            .receive_encapsulated_request(SESSION_ID)
            .await
            .is_ok());

        // Get data sent by requester and decode the secured message
        let receive: &mut [u8] = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let receive_size = {
            let mut device_io = context.common.device_io.lock();
            let device_io = device_io.deref_mut();
            device_io
                .receive(Arc::new(Mutex::new(receive)), 0)
                .await
                .unwrap()
        };

        let request = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let size = context
            .common
            .decode_secured_message(SESSION_ID, &receive[..receive_size], request)
            .await
            .unwrap();

        // Verify the message sent by requester
        let mut reader = Reader::init(&request[..size]);
        let header = SpdmMessageHeader::read(&mut reader).unwrap();
        let payload =
            SpdmDeliverEncapsulatedResponsePayload::spdm_read(&mut context.common, &mut reader)
                .unwrap();
        assert_eq!(header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestDeliverEncapsulatedResponse
        );
        assert_eq!(payload.request_id, 0xa);

        let encap_header = SpdmMessageHeader::read(&mut reader).unwrap();
        let encap_payload = SpdmDigestsResponsePayload::spdm_read(&mut context.common, &mut reader);
        assert_eq!(encap_header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            encap_header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseDigests
        );
        assert!(encap_payload.is_some());
    };
    executor::block_on(future);
}

#[test]
fn test_receive_encapsulated_response_ack() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let mut context = setup_test_context_and_session(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        assert!(context.common.construct_my_cert_chain().is_ok());

        // Encode the spdm message sent by responder
        let response = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(response);
        let header = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmResponseEncapsulatedResponseAck,
        };
        assert!(header.encode(&mut writer).is_ok());
        let payload = SpdmEncapsulatedResponseAckPayload {
            request_id: 0xa,
            payload_type: SpdmEncapsulatedResponseAckPayloadType::Present,
            ack_request_id: 0xa,
        };
        assert!(payload
            .spdm_encode(&mut context.common, &mut writer)
            .is_ok());
        let encap_header = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
        };
        assert!(encap_header.encode(&mut writer).is_ok());
        let encap_payload = SpdmGetCertificateRequestPayload {
            slot_id: 0,
            offset: 0,
            length: CERT_PORTION_LEN as u16,
        };
        assert!(encap_payload
            .spdm_encode(&mut context.common, &mut writer)
            .is_ok());

        // Set the data from responder to device io and encode as secured message
        let send = &mut [0u8; config::SENDER_BUFFER_SIZE];
        let size = context
            .common
            .encode_secured_message(SESSION_ID, writer.used_slice(), send, true, false)
            .await
            .unwrap();

        {
            let mut device_io = context.common.device_io.lock();
            let device_io = device_io.deref_mut();
            assert!(device_io.send(Arc::new(&send[..size])).await.is_ok());
        }

        assert!(context
            .receive_encapsulated_response_ack(SESSION_ID)
            .await
            .is_ok());

        // Get data sent by requester and decode the secured message
        let receive: &mut [u8] = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let receive_size = {
            let mut device_io = context.common.device_io.lock();
            let device_io = device_io.deref_mut();
            device_io
                .receive(Arc::new(Mutex::new(receive)), 0)
                .await
                .unwrap()
        };
        let request = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let size = context
            .common
            .decode_secured_message(SESSION_ID, &receive[..receive_size], request)
            .await
            .unwrap();

        // Verify the message sent by requester
        let mut reader = Reader::init(&request[..size]);
        let header = SpdmMessageHeader::read(&mut reader).unwrap();
        let payload =
            SpdmDeliverEncapsulatedResponsePayload::spdm_read(&mut context.common, &mut reader)
                .unwrap();
        assert_eq!(header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestDeliverEncapsulatedResponse
        );
        assert_eq!(payload.request_id, 0xa);

        let encap_header = SpdmMessageHeader::read(&mut reader).unwrap();
        let encap_payload =
            SpdmCertificateResponsePayload::spdm_read(&mut context.common, &mut reader);
        assert_eq!(encap_header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            encap_header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseCertificate
        );
        assert!(encap_payload.is_some());
    };
    executor::block_on(future);
}

fn setup_test_context_and_session(
    device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    config_info: SpdmConfigInfo,
    provision_info: SpdmProvisionInfo,
) -> RequesterContext {
    let mut context =
        RequesterContext::new(device_io, transport_encap, config_info, provision_info);

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    crypto::hmac::register(FAKE_HMAC.clone());

    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.req_capabilities_sel =
        SpdmRequestCapabilityFlags::ENCAP_CAP | SpdmRequestCapabilityFlags::CERT_CAP;
    context.common.negotiate_info.rsp_capabilities_sel =
        SpdmResponseCapabilityFlags::ENCAP_CAP | SpdmResponseCapabilityFlags::CERT_CAP;

    context
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCertificate);

    context.common.session = gen_array_clone(SpdmSession::new(), 4);
    context.common.session[0].setup(SESSION_ID).unwrap();
    context.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    context.common.session[0].set_session_state(session::SpdmSessionState::SpdmSessionEstablished);

    context
}
