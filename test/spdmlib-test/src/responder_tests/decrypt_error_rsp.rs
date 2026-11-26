// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// Only an AEAD decrypt failure on a secured message ends the session: the
// responder sends DecryptError and tears the session down. A decode error, such
// as a bad length, is dropped and the session stays open.

use crate::common::algo;
use crate::common::crypto_callback::FAKE_HMAC;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader};
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::config::{self, RECEIVER_BUFFER_SIZE};
use spdmlib::error::SPDM_STATUS_SESSION_MSG_ERROR;
use spdmlib::protocol::*;
use spdmlib::responder::ResponderContext;
use spdmlib::{crypto, message::*, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

const SESSION_ID: u32 = 0xFFFE_FFFE;
// The body is not parsed unless decryption succeeds.
const BODY: [u8; 4] = [0x12, 0xE8, 0x00, 0x00];

fn new_context_with_session() -> ResponderContext {
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
    context.common.session[0].setup(SESSION_ID).unwrap();
    context.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        algo::dhe_algo(),
        algo::kem_algo(),
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
    context
}

fn body_position(packet: &[u8]) -> usize {
    packet.windows(BODY.len()).position(|w| w == BODY).unwrap()
}

// The test AEAD (FAKE_AEAD) leaves the tag zeroed and fails on any other tag, and
// its ciphertext is the plaintext, so the tag follows the body.
fn corrupt_tag(packet: &mut [u8]) {
    let pos = body_position(packet) + BODY.len();
    packet[pos] ^= 0xFF;
}

// The inner length precedes the body. decode_msg validates it after decryption, so
// this is a decode error and not an AEAD failure.
fn corrupt_inner_length(packet: &mut [u8]) {
    let pos = body_position(packet);
    packet[pos - 2] = 0xFF;
    packet[pos - 1] = 0xFF;
}

// Encode a secured request with the Requester direction keys of a fresh session,
// so the sequence number is 0, which is what the responder under test expects.
async fn encode_secured_request(encoder: &mut ResponderContext, packet: &mut [u8]) -> usize {
    encoder
        .common
        .encode_secured_message(SESSION_ID, &BODY, packet, true, false)
        .await
        .unwrap()
}

async fn feed(context: &mut ResponderContext, packet: &[u8]) {
    let mut device_io = context.common.device_io.lock();
    let device_io = device_io.deref_mut();
    device_io.send(Arc::new(packet)).await.unwrap();
}

async fn receive_size(context: &mut ResponderContext, receive: &mut [u8]) -> usize {
    let mut device_io = context.common.device_io.lock();
    let device_io = device_io.deref_mut();
    device_io
        .receive(Arc::new(Mutex::new(receive)), 0)
        .await
        .unwrap()
}

#[test]
fn test_aead_failure_gets_decrypt_error_and_ends_session() {
    let task = async {
        let mut context = new_context_with_session();
        let mut encoder = new_context_with_session();

        let mut packet = [0u8; config::SENDER_BUFFER_SIZE];
        let size = encode_secured_request(&mut encoder, &mut packet).await;
        corrupt_tag(&mut packet[..size]);
        feed(&mut context, &packet[..size]).await;

        let mut raw_packet = [0u8; RECEIVER_BUFFER_SIZE];
        let result = context.process_message(false, 0, &mut raw_packet).await;
        assert_eq!(result, Ok(Err(SPDM_STATUS_SESSION_MSG_ERROR)));

        // The session is gone.
        assert!(context.common.get_session_via_id(SESSION_ID).is_none());

        // The DecryptError was sent before the session was torn down, so it is
        // encrypted and the peer can decode it.
        let mut receive = [0u8; RECEIVER_BUFFER_SIZE];
        let size = receive_size(&mut context, &mut receive).await;
        let mut response = [0u8; config::MAX_SPDM_MSG_SIZE];
        let size = encoder
            .common
            .decode_secured_message(SESSION_ID, &receive[..size], &mut response)
            .await
            .unwrap();
        let mut reader = Reader::init(&response[..size]);
        let header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(
            header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseError
        );
        assert_eq!(response[2], SpdmErrorCode::SpdmErrorDecryptError.get_u8());
    };
    executor::block_on(task);
}

#[test]
fn test_decode_error_keeps_session() {
    let task = async {
        let mut context = new_context_with_session();
        let mut encoder = new_context_with_session();

        let mut packet = [0u8; config::SENDER_BUFFER_SIZE];
        let size = encode_secured_request(&mut encoder, &mut packet).await;
        corrupt_inner_length(&mut packet[..size]);
        feed(&mut context, &packet[..size]).await;

        let mut raw_packet = [0u8; RECEIVER_BUFFER_SIZE];
        let result = context.process_message(false, 0, &mut raw_packet).await;
        // The message is dropped: no response, no teardown.
        assert!(result.is_err());
        assert!(context.common.get_session_via_id(SESSION_ID).is_some());
        let mut receive = [0u8; RECEIVER_BUFFER_SIZE];
        assert_eq!(receive_size(&mut context, &mut receive).await, 0);
    };
    executor::block_on(task);
}

#[test]
fn test_valid_request_keeps_session() {
    let task = async {
        let mut context = new_context_with_session();
        let mut encoder = new_context_with_session();

        let mut packet = [0u8; config::SENDER_BUFFER_SIZE];
        let size = encode_secured_request(&mut encoder, &mut packet).await;
        feed(&mut context, &packet[..size]).await;

        let mut raw_packet = [0u8; RECEIVER_BUFFER_SIZE];
        let result = context.process_message(false, 0, &mut raw_packet).await;
        assert_ne!(result, Ok(Err(SPDM_STATUS_SESSION_MSG_ERROR)));
        assert!(context.common.get_session_via_id(SESSION_ID).is_some());
    };
    executor::block_on(task);
}
