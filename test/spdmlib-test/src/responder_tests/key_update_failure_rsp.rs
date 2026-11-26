// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// A key update that fails on the Responder ends the session, after the error
// response is sent.

use crate::common::algo;
use crate::common::crypto_callback::FAKE_HMAC;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::Writer;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::SpdmCodec;
use spdmlib::config::{self, RECEIVER_BUFFER_SIZE};
use spdmlib::error::SPDM_STATUS_CRYPTO_ERROR;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::responder::ResponderContext;
use spdmlib::{crypto, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

const SESSION_ID: u32 = 0xFFFE_FFFE;

// Without the request data secret, deriving the updated keys fails. The application keys are
// valid either way.
fn new_context_with_session(with_data_secret: bool) -> ResponderContext {
    let (config_info, provision_info) = create_info();
    let transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        SharedBuffer::new(),
    ))));
    let mut context =
        ResponderContext::new(device_io, transport_encap, config_info, provision_info);

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
    crypto::hmac::register(FAKE_HMAC.clone());

    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.session = gen_array_clone(SpdmSession::new(), 4);
    let session = &mut context.common.session[0];
    session.setup(SESSION_ID).unwrap();
    session.set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        algo::dhe_algo(),
        algo::kem_algo(),
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    session.set_session_state(SpdmSessionState::SpdmSessionEstablished);
    let shared_secret = SpdmSharedSecretFinalKeyStruct {
        data_size: 48,
        data: Box::new([0; SPDM_MAX_SHARED_SECRET_SIZE]),
    };
    let _ = session.set_shared_secret(SpdmVersion::SpdmVersion12, shared_secret);
    let th = SpdmDigestStruct {
        data_size: 48,
        data: Box::new([0; SPDM_MAX_HASH_SIZE]),
    };
    let _ = session.generate_handshake_secret(SpdmVersion::SpdmVersion12, &th);
    // The application keys are valid, so that the secured messages can be encoded and decoded.
    session
        .generate_data_secret(SpdmVersion::SpdmVersion12, &th)
        .unwrap();
    // Without the request data secret, which the updated request keys come from, a key update
    // fails. Nothing else does.
    if !with_data_secret {
        let mut application_secret = session.get_application_secret();
        application_secret.request_data_secret = SpdmDirectionDataSecretStruct::default();
        session.set_application_secret(application_secret);
    }
    context
}

fn key_update_request(
    context: &mut ResponderContext,
    operation: SpdmKeyUpdateOperation,
) -> Vec<u8> {
    let mut buffer = [0u8; 16];
    let mut writer = Writer::init(&mut buffer);
    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
        },
        payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
            key_update_operation: operation,
            tag: 1,
        }),
    };
    let used = request
        .spdm_encode(&mut context.common, &mut writer)
        .unwrap();
    buffer[..used].to_vec()
}

// Send a secured KEY_UPDATE request, encoded with the Requester direction keys of a
// fresh session so that the sequence number is 0, to the responder under test.
async fn send_key_update(
    context: &mut ResponderContext,
    encoder: &mut ResponderContext,
    operation: SpdmKeyUpdateOperation,
) -> Result<spdmlib::error::SpdmResult, usize> {
    let request = key_update_request(encoder, operation);
    let mut packet = [0u8; config::SENDER_BUFFER_SIZE];
    let size = encoder
        .common
        .encode_secured_message(SESSION_ID, &request, &mut packet, true, false)
        .await
        .unwrap();
    {
        let mut device_io = context.common.device_io.lock();
        let device_io = device_io.deref_mut();
        device_io.send(Arc::new(&packet[..size])).await.unwrap();
    }
    let mut raw_packet = [0u8; RECEIVER_BUFFER_SIZE];
    context.process_message(false, 0, &mut raw_packet).await
}

// Receive the response the responder sent and decode it with the encoder's keys.
async fn receive_response(
    context: &mut ResponderContext,
    encoder: &mut ResponderContext,
) -> Vec<u8> {
    let mut receive = [0u8; RECEIVER_BUFFER_SIZE];
    let size = {
        let mut device_io = context.common.device_io.lock();
        let device_io = device_io.deref_mut();
        device_io
            .receive(Arc::new(Mutex::new(&mut receive[..])), 0)
            .await
            .unwrap()
    };
    let mut response = [0u8; config::MAX_SPDM_MSG_SIZE];
    let size = encoder
        .common
        .decode_secured_message(SESSION_ID, &receive[..size], &mut response)
        .await
        .unwrap();
    response[..size].to_vec()
}

#[test]
fn test_key_update_failure_gets_error_and_ends_session() {
    let task = async {
        let mut context = new_context_with_session(false);
        let mut encoder = new_context_with_session(false);

        let result = send_key_update(
            &mut context,
            &mut encoder,
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey,
        )
        .await;
        assert_eq!(result, Ok(Err(SPDM_STATUS_CRYPTO_ERROR)));

        // The session is gone.
        assert!(context.common.get_session_via_id(SESSION_ID).is_none());

        // The error was sent before the session was torn down, so the peer can
        // decode it with the keys it still has.
        let response = receive_response(&mut context, &mut encoder).await;
        assert_eq!(
            response[1],
            SpdmRequestResponseCode::SpdmResponseError.get_u8()
        );
        assert_eq!(response[2], SpdmErrorCode::SpdmErrorUnspecified.get_u8());
    };
    executor::block_on(task);
}

#[test]
fn test_key_update_success_keeps_session() {
    let task = async {
        let mut context = new_context_with_session(true);
        let mut encoder = new_context_with_session(true);

        let result = send_key_update(
            &mut context,
            &mut encoder,
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey,
        )
        .await;
        assert_eq!(result, Ok(Ok(())));
        assert!(context.common.get_session_via_id(SESSION_ID).is_some());
    };
    executor::block_on(task);
}

#[test]
fn test_invalid_key_update_request_keeps_session() {
    let task = async {
        let mut context = new_context_with_session(true);
        let mut encoder = new_context_with_session(true);

        // An unknown operation gets an error response and the session stays open.
        let result = send_key_update(
            &mut context,
            &mut encoder,
            SpdmKeyUpdateOperation::Unknown(0),
        )
        .await;
        assert!(matches!(result, Ok(Err(_))));
        assert!(context.common.get_session_via_id(SESSION_ID).is_some());
        let response = receive_response(&mut context, &mut encoder).await;
        assert_eq!(response[2], SpdmErrorCode::SpdmErrorInvalidRequest.get_u8());
    };
    executor::block_on(task);
}
