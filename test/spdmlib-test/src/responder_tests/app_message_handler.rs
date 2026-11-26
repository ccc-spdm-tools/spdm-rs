// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::algo;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::Writer;
use core::sync::atomic::{AtomicBool, Ordering};
use spdmlib::common::session::{SpdmSession, SpdmSessionApplicationSecret, SpdmSessionState};
use spdmlib::common::SpdmConnectionState;
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::error::SpdmResult;
use spdmlib::protocol::*;
use spdmlib::responder;
use spdmlib::responder::app_message_handler::{
    dispatch_secured_app_message_cb, register, SpdmAppMessageHandler,
};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

static APP_HANDLER_CALLED: AtomicBool = AtomicBool::new(false);

fn app_handler<'a>(
    _ctx: &mut responder::ResponderContext,
    _session_id: u32,
    _app_buffer: &[u8],
    _app_handle: usize,
    writer: &'a mut Writer,
) -> (SpdmResult, Option<&'a [u8]>) {
    APP_HANDLER_CALLED.store(true, Ordering::SeqCst);
    let _ = writer.extend_from_slice(&[0xAA]);
    (Ok(()), Some(writer.used_slice()))
}

#[test]
fn test_case0_app_message_requires_established_session() {
    register(SpdmAppMessageHandler {
        dispatch_secured_app_message_cb: app_handler,
    });

    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
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

    let session_id = 0xFFFE_FFFEu32;
    context.common.session = gen_array_clone(SpdmSession::new(), 4);
    context.common.session[0].setup(session_id).unwrap();
    context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);

    let app_message = [0x01u8, 0x02, 0x03];
    let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];

    // Handshake phase: FINISH / PSK_FINISH has not been processed yet.
    APP_HANDLER_CALLED.store(false, Ordering::SeqCst);
    let mut writer = Writer::init(&mut response_buffer);
    let (status, send_buffer) =
        dispatch_secured_app_message_cb(&mut context, session_id, &app_message, 0, &mut writer);
    assert!(status.is_err());
    assert!(send_buffer.is_none());
    assert!(!APP_HANDLER_CALLED.load(Ordering::SeqCst));

    // Unknown session.
    let mut writer = Writer::init(&mut response_buffer);
    let (status, send_buffer) =
        dispatch_secured_app_message_cb(&mut context, 0x1234_5678, &app_message, 0, &mut writer);
    assert!(status.is_err());
    assert!(send_buffer.is_none());
    assert!(!APP_HANDLER_CALLED.load(Ordering::SeqCst));

    // Application phase.
    context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
    let mut writer = Writer::init(&mut response_buffer);
    let (status, send_buffer) =
        dispatch_secured_app_message_cb(&mut context, session_id, &app_message, 0, &mut writer);
    assert!(status.is_ok());
    assert_eq!(send_buffer, Some(&[0xAAu8][..]));
    assert!(APP_HANDLER_CALLED.load(Ordering::SeqCst));
}

#[test]
fn test_case1_app_message_does_not_change_spdm_state() {
    let task = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
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

        let session_id = 0xFFFE_FFFEu32;
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);
        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            algo::dhe_algo(),
            algo::kem_algo(),
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        let mut application_secret = SpdmSessionApplicationSecret::default();
        application_secret
            .response_direction
            .encryption_key
            .data_size = SpdmAeadAlgo::AES_256_GCM.get_key_size();
        application_secret.response_direction.salt.data_size =
            SpdmAeadAlgo::AES_256_GCM.get_iv_size();
        context.common.session[0].set_application_secret(application_secret);
        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

        // The second byte of these application responses equals the VERSION,
        // CHALLENGE_AUTH and END_SESSION_ACK response codes.
        for app_response in [[0x00u8, 0x04], [0x00, 0x03], [0x00, 0x6C]] {
            assert!(context
                .send_message(Some(session_id), &app_response, true)
                .await
                .is_ok());
            assert_eq!(
                context.common.runtime_info.get_connection_state(),
                SpdmConnectionState::SpdmConnectionNegotiated
            );
            let session = context
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();
            assert_eq!(
                session.get_session_state(),
                SpdmSessionState::SpdmSessionEstablished
            );
        }
    };

    executor::block_on(task);
}
