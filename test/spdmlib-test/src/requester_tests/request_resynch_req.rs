// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::SpdmConnectionState;
use spdmlib::error::{SPDM_STATUS_RESYNCH_PEER, SPDM_STATUS_SESSION_MSG_ERROR};
use spdmlib::message::SpdmRequestResponseCode;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

const SESSION_ID: u32 = 0xFFFE_FFFE;
const REQUEST_SEQ: u64 = 7;
const RESPONSE_SEQ: u64 = 5;
const ERROR_REQUEST_RESYNCH: [u8; 4] = [0x12, 0x7F, 0x43, 0x00];
const ERROR_DECRYPT_ERROR: [u8; 4] = [0x12, 0x7F, 0x06, 0x00];

fn new_context_with_session() -> RequesterContext {
    let (config_info, provision_info) = create_info();
    let transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        SharedBuffer::new(),
    ))));
    let mut context =
        RequesterContext::new(device_io, transport_encap, config_info, provision_info);

    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionAuthenticated);
    context.common.session = gen_array_clone(SpdmSession::new(), 4);
    let session = &mut context.common.session[0];
    session.setup(SESSION_ID).unwrap();
    session.set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmKemAlgo::empty(),
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    session.set_session_state(SpdmSessionState::SpdmSessionEstablished);
    session.set_request_direction_sequence_number(REQUEST_SEQ);
    session.set_response_direction_sequence_number(RESPONSE_SEQ);
    context
}

fn handle_error(context: &mut RequesterContext, response: &[u8]) -> spdmlib::error::SpdmResult {
    context.spdm_handle_error_response_main(
        Some(SESSION_ID),
        response,
        SpdmRequestResponseCode::SpdmRequestHeartbeat,
        SpdmRequestResponseCode::SpdmResponseHeartbeatAck,
    )
}

#[test]
fn test_request_resynch_keeps_session() {
    let mut context = new_context_with_session();

    let status = handle_error(&mut context, &ERROR_REQUEST_RESYNCH).unwrap_err();
    assert_eq!(status, SPDM_STATUS_RESYNCH_PEER);
    let error_data = status.error_data.unwrap();
    assert_eq!(
        &error_data.data[..error_data.length],
        &ERROR_REQUEST_RESYNCH
    );
    assert_eq!(
        context.common.runtime_info.get_connection_state(),
        SpdmConnectionState::SpdmConnectionNotStarted
    );

    let session = context.common.get_session_via_id(SESSION_ID).unwrap();
    assert_eq!(
        session.get_session_state(),
        SpdmSessionState::SpdmSessionEstablished
    );
    assert_eq!(session.get_request_direction_sequence_number(), REQUEST_SEQ);
    assert_eq!(
        session.get_response_direction_sequence_number(),
        RESPONSE_SEQ
    );
}

#[test]
fn test_request_resynch_outside_session_resets_connection() {
    let mut context = new_context_with_session();

    let status = context
        .spdm_handle_error_response_main(
            None,
            &ERROR_REQUEST_RESYNCH,
            SpdmRequestResponseCode::SpdmRequestGetDigests,
            SpdmRequestResponseCode::SpdmResponseDigests,
        )
        .unwrap_err();
    assert_eq!(status, SPDM_STATUS_RESYNCH_PEER);
    assert_eq!(
        context.common.runtime_info.get_connection_state(),
        SpdmConnectionState::SpdmConnectionNotStarted
    );
    assert!(context.common.get_session_via_id(SESSION_ID).is_some());
}

#[test]
fn test_decrypt_error_still_ends_session() {
    let mut context = new_context_with_session();

    let status = handle_error(&mut context, &ERROR_DECRYPT_ERROR).unwrap_err();
    assert_eq!(status, SPDM_STATUS_SESSION_MSG_ERROR);
    assert!(context.common.get_session_via_id(SESSION_ID).is_none());
}
