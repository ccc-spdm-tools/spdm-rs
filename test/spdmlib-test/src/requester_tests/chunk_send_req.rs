// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{TestSpdmDeviceIo, TestTransportEncap};
use crate::common::util::create_info;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spin::Mutex;
extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;

/// Frame one transport message for `TestSpdmDeviceIo` + `TestTransportEncap`:
/// `[u32 LE length][secure flag][spdm bytes]`.
fn framed(spdm: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(((spdm.len() + 1) as u32).to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(spdm);
    out
}

/// Drive the requester into `send_large_request` and feed it a CHUNK_SEND_ACK
/// with EARLY_ERROR_DETECTED whose attached "response to large request" is
/// `trailer`. Returns the result of `send_message`.
fn chunk_send_with_early_error_trailer(trailer: &[u8]) -> spdmlib::error::SpdmResult {
    let mut ack = vec![
        0x12, // SPDM 1.2
        0x05, // CHUNK_SEND_ACK
        0x01, // Param1: EARLY_ERROR_DETECTED
        0x01, // Param2: handle (first chunk_req_handle after overflowing_add from 0)
        0x00, 0x00, // ChunkSeqNo = 0
    ];
    ack.extend_from_slice(trailer);

    let rx = Arc::new(Mutex::new(VecDeque::from(framed(&ack))));
    let tx = Arc::new(Mutex::new(VecDeque::<u8>::new()));

    let future = async {
        let (config_info, provision_info) = create_info();
        let mut requester = RequesterContext::new(
            Arc::new(Mutex::new(TestSpdmDeviceIo::new(rx, tx))),
            Arc::new(Mutex::new(TestTransportEncap)),
            config_info,
            provision_info,
        );
        requester.common.reset_runtime_info();
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::CHUNK_CAP;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CHUNK_CAP;
        // Smallest DataTransferSize a responder may advertise, forcing any
        // ordinary request to be chunked.
        requester.common.negotiate_info.rsp_data_transfer_size_sel = 42;
        requester.common.negotiate_info.rsp_max_spdm_msg_size_sel = 0;

        let request = [0x12u8; 100];
        requester.send_message(None, &request, false).await
    };
    executor::block_on(future)
}

/// A device may set EARLY_ERROR_DETECTED and attach a 2-byte trailer that
/// parses as an SPDM ERROR header with no error payload. This used to hit an
/// `unwrap()` on the missing payload and panic the requester; in `no_std`
/// firmware that halts the TPA for every tenant.
#[test]
fn test_chunk_send_ack_early_error_truncated_payload_is_rejected() {
    // Header only: version + ERROR code, zero payload bytes.
    assert!(chunk_send_with_early_error_trailer(&[0x12, 0x7F]).is_err());
    // Header + one payload byte (needs two).
    assert!(chunk_send_with_early_error_trailer(&[0x12, 0x7F, 0x01]).is_err());
}

/// A complete ERROR trailer that is not LargeResponse is accepted as an early
/// error and stops chunking without failing the send.
#[test]
fn test_chunk_send_ack_early_error_complete_payload_is_accepted() {
    // ERROR(Busy=0x03, 0x00).
    assert!(chunk_send_with_early_error_trailer(&[0x12, 0x7F, 0x03, 0x00]).is_ok());
}
