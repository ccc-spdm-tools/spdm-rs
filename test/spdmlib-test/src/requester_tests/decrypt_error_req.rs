// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// Only an AEAD decrypt failure on a secured response ends the session on the
// Requester. A decode error, such as a bad length, leaves it open.

use crate::common::crypto_callback::FAKE_HMAC;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::config;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{crypto, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

const SESSION_ID: u32 = 0xFFFE_FFFE;
// The body is not parsed unless decryption succeeds.
const BODY: [u8; 4] = [0x12, 0x7F, 0x06, 0x00];

fn new_context_with_session() -> RequesterContext {
    let (config_info, provision_info) = create_info();
    let transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        SharedBuffer::new(),
    ))));
    let mut context =
        RequesterContext::new(device_io, transport_encap, config_info, provision_info);

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
    crypto::hmac::register(FAKE_HMAC.clone());

    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.session = gen_array_clone(SpdmSession::new(), 4);
    context.common.session[0].setup(SESSION_ID).unwrap();
    context.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmKemAlgo::empty(),
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

// Encode a secured response with the Responder direction keys of a fresh session.
async fn encode_secured_response(packet: &mut [u8]) -> usize {
    let mut encoder = new_context_with_session();
    encoder
        .common
        .encode_secured_message(SESSION_ID, &BODY, packet, false, false)
        .await
        .unwrap()
}

#[test]
fn test_aead_failure_ends_session() {
    let task = async {
        let mut context = new_context_with_session();
        let mut packet = [0u8; config::SENDER_BUFFER_SIZE];
        let size = encode_secured_response(&mut packet).await;
        corrupt_tag(&mut packet[..size]);

        let mut out = [0u8; config::MAX_SPDM_MSG_SIZE];
        let result = context
            .common
            .decode_secured_message(SESSION_ID, &packet[..size], &mut out)
            .await;
        assert!(result.is_err());
        assert!(context.common.get_session_via_id(SESSION_ID).is_none());
    };
    executor::block_on(task);
}

#[test]
fn test_decode_error_keeps_session() {
    let task = async {
        let mut context = new_context_with_session();
        let mut packet = [0u8; config::SENDER_BUFFER_SIZE];
        let size = encode_secured_response(&mut packet).await;
        corrupt_inner_length(&mut packet[..size]);

        let mut out = [0u8; config::MAX_SPDM_MSG_SIZE];
        let result = context
            .common
            .decode_secured_message(SESSION_ID, &packet[..size], &mut out)
            .await;
        assert!(result.is_err());
        assert!(context.common.get_session_via_id(SESSION_ID).is_some());
    };
    executor::block_on(task);
}

#[test]
fn test_valid_response_keeps_session() {
    let task = async {
        let mut context = new_context_with_session();
        let mut packet = [0u8; config::SENDER_BUFFER_SIZE];
        let size = encode_secured_response(&mut packet).await;

        let mut out = [0u8; config::MAX_SPDM_MSG_SIZE];
        let result = context
            .common
            .decode_secured_message(SESSION_ID, &packet[..size], &mut out)
            .await;
        assert!(result.is_ok());
        assert!(context.common.get_session_via_id(SESSION_ID).is_some());
    };
    executor::block_on(task);
}
