// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::crypto_callback::FAKE_HMAC;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::{
    SpdmCodec, SpdmConfigInfo, SpdmConnectionState, SpdmDeviceIo, SpdmProvisionInfo,
    SpdmTransportEncap,
};
use spdmlib::config::{self, MAX_SPDM_MSG_SIZE};
use spdmlib::error::{SpdmResult, SPDM_STATUS_BUFFER_FULL};
use spdmlib::protocol::*;
use spdmlib::responder::ResponderContext;
use spdmlib::{crypto, message::*, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

const CERT_PORTION_LEN: usize = 512;
const SESSION_ID: u32 = 4294901758;

#[test]
fn test_handle_get_encapsulated_request() {
    let task = async {
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

        let request = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(request);
        let header = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest,
        };
        assert!(header.encode(&mut writer).is_ok());

        let payload = SpdmGetEncapsulatedRequestPayload {};
        assert!(payload
            .spdm_encode(&mut context.common, &mut writer)
            .is_ok());

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, send_buffer) = context.handle_get_encapsulated_request(request, &mut writer);
        assert!(status.is_ok());
        assert!(send_buffer.is_some());

        assert!(context
            .send_message(Some(SESSION_ID), send_buffer.unwrap(), false)
            .await
            .is_ok());

        let receive = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let receive_size = {
            let mut device_io = context.common.device_io.lock();
            let device_io = device_io.deref_mut();
            device_io
                .receive(Arc::new(Mutex::new(receive)), 0)
                .await
                .unwrap()
        };

        let response = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
        let size = context
            .common
            .decode_secured_message(SESSION_ID, &receive[..receive_size], response)
            .await
            .unwrap();

        assert_eq!(size, 8); // Encapsulated Request + Get Digest

        let mut reader = Reader::init(&response[..size]);
        let header = SpdmMessageHeader::read(&mut reader).unwrap();
        let payload = SpdmEncapsulatedRequestPayload::spdm_read(&mut context.common, &mut reader);
        assert_eq!(header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseEncapsulatedRequest
        );
        assert!(payload.is_some());

        let encap_header = SpdmMessageHeader::read(&mut reader).unwrap();
        let encap_payload =
            SpdmGetDigestsRequestPayload::spdm_read(&mut context.common, &mut reader);
        assert_eq!(encap_header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            encap_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetDigests
        );
        assert!(encap_payload.is_some());
    };

    executor::block_on(task);
}

#[test]
fn test_handle_deliver_encapsulated_reponse_digest() {
    let task = async {
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

        let request = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(request);
        let header = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestDeliverEncapsulatedResponse,
        };
        assert!(header.encode(&mut writer).is_ok());

        let payload = SpdmDeliverEncapsulatedResponsePayload { request_id: 0xa };
        assert!(payload
            .spdm_encode(&mut context.common, &mut writer)
            .is_ok());

        assert!(write_spdm_get_digest_response(&mut context, &mut writer).is_ok());

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, send_buffer) =
            context.handle_deliver_encapsulated_reponse(request, &mut writer);
        assert!(status.is_ok());
        assert!(send_buffer.is_some());

        assert!(context
            .send_message(Some(SESSION_ID), send_buffer.unwrap(), false)
            .await
            .is_ok());

        // Get data sent by responder and decode the secured message
        let receive = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let receive_size = {
            let mut device_io = context.common.device_io.lock();
            let device_io = device_io.deref_mut();

            device_io
                .receive(Arc::new(Mutex::new(receive)), 0)
                .await
                .unwrap()
        };

        let response = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
        let size = context
            .common
            .decode_secured_message(SESSION_ID, &receive[..receive_size], response)
            .await
            .unwrap();

        // Verify the message sent by responder
        let mut reader = Reader::init(&response[..size]);
        let header = SpdmMessageHeader::read(&mut reader).unwrap();
        let payload =
            SpdmEncapsulatedResponseAckPayload::spdm_read(&mut context.common, &mut reader)
                .unwrap();
        assert_eq!(header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseEncapsulatedResponseAck
        );
        assert_eq!(payload.ack_request_id, 0xa);

        let encap_header = SpdmMessageHeader::read(&mut reader).unwrap();
        let encap_payload = SpdmDigestsResponsePayload::spdm_read(&mut context.common, &mut reader);
        assert_eq!(encap_header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            encap_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetCertificate
        );
        assert!(encap_payload.is_some());
    };

    executor::block_on(task);
}

#[test]
fn test_handle_deliver_encapsulated_reponse_cert() {
    let task = async {
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
        if context.common.peer_info.peer_cert_chain_temp.is_none() {
            context.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());
        }

        let request = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(request);
        let header = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestDeliverEncapsulatedResponse,
        };
        assert!(header.encode(&mut writer).is_ok());

        let payload = SpdmDeliverEncapsulatedResponsePayload { request_id: 0xa };
        assert!(payload
            .spdm_encode(&mut context.common, &mut writer)
            .is_ok());

        assert!(write_spdm_get_certificate_response(&mut context, &mut writer).is_ok());

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, send_buffer) =
            context.handle_deliver_encapsulated_reponse(request, &mut writer);
        assert!(status.is_ok());
        assert!(send_buffer.is_some());

        assert!(context
            .send_message(Some(SESSION_ID), send_buffer.unwrap(), false)
            .await
            .is_ok());

        let receive: &mut [u8] = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let receive_size = {
            let mut device_io = context.common.device_io.lock();
            let device_io = device_io.deref_mut();

            device_io
                .receive(Arc::new(Mutex::new(receive)), 0)
                .await
                .unwrap()
        };

        let mut response = [0u8; config::MAX_SPDM_MSG_SIZE];
        let size = context
            .common
            .decode_secured_message(SESSION_ID, &receive[..receive_size], &mut response)
            .await
            .unwrap();

        // Verify the message sent by responder
        let mut reader = Reader::init(&response[..size]);
        let header = SpdmMessageHeader::read(&mut reader).unwrap();
        let payload =
            SpdmEncapsulatedResponseAckPayload::spdm_read(&mut context.common, &mut reader)
                .unwrap();
        assert_eq!(header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseEncapsulatedResponseAck
        );
        assert_eq!(payload.ack_request_id, 0xa);

        let encap_header = SpdmMessageHeader::read(&mut reader).unwrap();
        let encap_payload = SpdmDigestsResponsePayload::spdm_read(&mut context.common, &mut reader);
        assert_eq!(encap_header.version, SpdmVersion::SpdmVersion12);
        assert_eq!(
            encap_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetCertificate
        );
        assert!(encap_payload.is_some());
    };

    executor::block_on(task);
}

fn setup_test_context_and_session(
    device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    config_info: SpdmConfigInfo,
    provision_info: SpdmProvisionInfo,
) -> ResponderContext {
    let mut context =
        ResponderContext::new(device_io, transport_encap, config_info, provision_info);

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    crypto::hmac::register(FAKE_HMAC.clone());

    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::ENCAP_CAP;
    context.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::ENCAP_CAP;

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
    context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

    context
}

fn write_spdm_get_digest_response(
    context: &mut ResponderContext,
    writer: &mut Writer,
) -> SpdmResult {
    let digest_size = context.common.negotiate_info.base_hash_sel.get_size();
    let slot_mask = 1;

    let response = SpdmMessage {
        header: SpdmMessageHeader {
            version: context.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmResponseDigests,
        },
        payload: SpdmMessagePayload::SpdmDigestsResponse(SpdmDigestsResponsePayload {
            slot_mask,
            digests: gen_array_clone(
                SpdmDigestStruct {
                    data_size: digest_size,
                    data: Box::new([0xffu8; SPDM_MAX_HASH_SIZE]),
                },
                SPDM_MAX_SLOT_NUMBER,
            ),
        }),
    };
    let _ = response
        .spdm_encode(&mut context.common, writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    Ok(())
}

fn write_spdm_get_certificate_response(
    context: &mut ResponderContext,
    writer: &mut Writer,
) -> SpdmResult {
    let response = SpdmMessage {
        header: SpdmMessageHeader {
            version: context.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmResponseCertificate,
        },
        payload: SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
            slot_id: 0,
            portion_length: CERT_PORTION_LEN as u16,
            remainder_length: 0x200,
            cert_chain: [0xffu8; CERT_PORTION_LEN],
        }),
    };
    let _ = response
        .spdm_encode(&mut context.common, writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    Ok(())
}
