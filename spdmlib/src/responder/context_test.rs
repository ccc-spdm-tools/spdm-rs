// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Session-binding tests for the chunked-transfer handlers: a CHUNK_GET /
//! CHUNK_SEND that arrives on a session different from the one the transfer was
//! staged for must be rejected with ERROR/UnexpectedRequest.

use super::ResponderContext;
use crate::common::{
    SpdmChunkStatus, SpdmCodec, SpdmConfigInfo, SpdmConnectionState, SpdmDeviceIo,
    SpdmProvisionInfo, SpdmTransportEncap,
};
use crate::config;
use crate::message::*;
use crate::protocol::{SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion};
use codec::{Codec, Reader, Writer};
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

#[path = "../message/mod_test.common.inc.rs"]
mod testlib;

fn new_responder() -> ResponderContext {
    let transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>> =
        Arc::new(Mutex::new(testlib::TransportEncap {}));
    let device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>> =
        Arc::new(Mutex::new(testlib::DeviceIO {}));
    let mut ctx = ResponderContext::new(
        device_io,
        transport_encap,
        SpdmConfigInfo::default(),
        SpdmProvisionInfo::default(),
    );
    ctx.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    ctx.common.negotiate_info.req_capabilities_sel |= SpdmRequestCapabilityFlags::CHUNK_CAP;
    ctx.common.negotiate_info.rsp_capabilities_sel |= SpdmResponseCapabilityFlags::CHUNK_CAP;
    ctx.common.negotiate_info.req_data_transfer_size_sel =
        config::SPDM_SENDER_DATA_TRANSFER_SIZE as u32;
    ctx.common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);
    ctx
}

/// Stage a large response for retrieval bound to `session_id`.
fn stage_get(ctx: &mut ResponderContext, session_id: Option<u32>) {
    ctx.common.chunk_rsp_handle = 7;
    ctx.common.chunk_context.chunk_status = SpdmChunkStatus::ChunkGetAndResponse;
    ctx.common.chunk_context.chunk_seq_num = 0;
    ctx.common.chunk_context.chunk_message_size = 64;
    ctx.common.chunk_context.transferred_size = 0;
    ctx.common.chunk_context.session_id = session_id;
}

/// Stage an in-progress large-request reassembly bound to `session_id`.
fn stage_send(ctx: &mut ResponderContext, session_id: Option<u32>) {
    ctx.common.chunk_req_handle = 0;
    ctx.common.chunk_context.chunk_status = SpdmChunkStatus::ChunkSendAndAck;
    ctx.common.chunk_context.chunk_seq_num = 0;
    ctx.common.chunk_context.chunk_message_size = 64;
    ctx.common.chunk_context.transferred_size = 0;
    ctx.common.chunk_context.session_id = session_id;
}

fn encode_chunk_get(handle: u8, seq: u32) -> Vec<u8> {
    let mut enc = new_responder();
    let msg = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChunkGet,
        },
        payload: SpdmMessagePayload::SpdmChunkGetRequest(SpdmChunkGetRequestPayload {
            handle,
            chunk_seq_num: seq,
        }),
    };
    let mut buf = [0u8; 64];
    let mut w = Writer::init(&mut buf);
    let used = msg.spdm_encode(&mut enc.common, &mut w).unwrap();
    buf[..used].to_vec()
}

fn encode_chunk_send(handle: u8, seq: u32, chunk_size: u32) -> Vec<u8> {
    // Encode with a throwaway context primed with chunk data so the encoder can
    // emit `chunk_size` payload bytes; its chunk_context mutation is harmless.
    let mut enc = new_responder();
    enc.common.chunk_context.chunk_message_size = config::MAX_SPDM_MSG_SIZE;
    enc.common.chunk_context.transferred_size = 0;
    let large_message_size = if seq == 0 { Some(64u32) } else { None };
    let msg = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChunkSend,
        },
        payload: SpdmMessagePayload::SpdmChunkSendRequest(SpdmChunkSendRequestPayload {
            chunk_sender_attributes: SpdmChunkSenderAttributes::default(),
            handle,
            chunk_seq_num: seq,
            chunk_size,
            large_message_size,
        }),
    };
    let mut buf = [0u8; 128];
    let mut w = Writer::init(&mut buf);
    let used = msg.spdm_encode(&mut enc.common, &mut w).unwrap();
    buf[..used].to_vec()
}

/// Whether `resp` is an ERROR/UnexpectedRequest message (the session-mismatch
/// rejection). Byte layout: [version, ResponseError, error_code, error_data].
fn is_unexpected_request(resp: &[u8]) -> bool {
    let mut r = Reader::init(resp);
    match SpdmMessageHeader::read(&mut r) {
        Some(h) if h.request_response_code == SpdmRequestResponseCode::SpdmResponseError => {
            resp.get(2).copied() == Some(SpdmErrorCode::SpdmErrorUnexpectedRequest.get_u8())
        }
        _ => false,
    }
}

// ── CHUNK_GET / CHUNK_RESPONSE ──

#[test]
fn chunk_get_matching_session_is_served() {
    let mut ctx = new_responder();
    stage_get(&mut ctx, Some(0x1234));
    let req = encode_chunk_get(7, 0);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (_res, resp) = ctx.write_spdm_chunk_get_response(Some(0x1234), &req, &mut w);
    assert!(!is_unexpected_request(resp.unwrap()));
}

#[test]
fn chunk_get_different_session_is_rejected() {
    let mut ctx = new_responder();
    stage_get(&mut ctx, Some(0x1234));
    let req = encode_chunk_get(7, 0);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (res, resp) = ctx.write_spdm_chunk_get_response(Some(0x9999), &req, &mut w);
    assert!(res.is_err());
    assert!(is_unexpected_request(resp.unwrap()));
}

#[test]
fn chunk_get_unsecured_for_session_response_is_rejected() {
    let mut ctx = new_responder();
    stage_get(&mut ctx, Some(0x1234));
    let req = encode_chunk_get(7, 0);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (res, resp) = ctx.write_spdm_chunk_get_response(None, &req, &mut w);
    assert!(res.is_err());
    assert!(is_unexpected_request(resp.unwrap()));
}

#[test]
fn chunk_get_secured_for_unsecured_response_is_rejected() {
    let mut ctx = new_responder();
    stage_get(&mut ctx, None);
    let req = encode_chunk_get(7, 0);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (res, resp) = ctx.write_spdm_chunk_get_response(Some(0x1234), &req, &mut w);
    assert!(res.is_err());
    assert!(is_unexpected_request(resp.unwrap()));
}

#[test]
fn chunk_get_unsecured_matching_is_served() {
    let mut ctx = new_responder();
    stage_get(&mut ctx, None);
    let req = encode_chunk_get(7, 0);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (_res, resp) = ctx.write_spdm_chunk_get_response(None, &req, &mut w);
    assert!(!is_unexpected_request(resp.unwrap()));
}

// ── CHUNK_SEND / CHUNK_SEND_ACK ──

#[test]
fn chunk_send_matching_session_passes() {
    let mut ctx = new_responder();
    stage_send(&mut ctx, Some(0x1234));
    let req = encode_chunk_send(0, 1, 4);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (_res, resp) = ctx.write_spdm_chunk_send_response(Some(0x1234), &req, &mut w);
    assert!(!is_unexpected_request(resp.unwrap()));
}

#[test]
fn chunk_send_different_session_is_rejected() {
    let mut ctx = new_responder();
    stage_send(&mut ctx, Some(0x1234));
    let req = encode_chunk_send(0, 1, 4);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (res, resp) = ctx.write_spdm_chunk_send_response(Some(0x9999), &req, &mut w);
    assert!(res.is_err());
    assert!(is_unexpected_request(resp.unwrap()));
}

#[test]
fn chunk_send_unsecured_for_session_request_is_rejected() {
    let mut ctx = new_responder();
    stage_send(&mut ctx, Some(0x1234));
    let req = encode_chunk_send(0, 1, 4);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (res, resp) = ctx.write_spdm_chunk_send_response(None, &req, &mut w);
    assert!(res.is_err());
    assert!(is_unexpected_request(resp.unwrap()));
}

#[test]
fn chunk_send_secured_for_unsecured_request_is_rejected() {
    let mut ctx = new_responder();
    stage_send(&mut ctx, None);
    let req = encode_chunk_send(0, 1, 4);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (res, resp) = ctx.write_spdm_chunk_send_response(Some(0x1234), &req, &mut w);
    assert!(res.is_err());
    assert!(is_unexpected_request(resp.unwrap()));
}

#[test]
fn chunk_send_unsecured_matching_passes() {
    let mut ctx = new_responder();
    stage_send(&mut ctx, None);
    let req = encode_chunk_send(0, 1, 4);
    let mut buf = [0u8; 1024];
    let mut w = Writer::init(&mut buf);
    let (_res, resp) = ctx.write_spdm_chunk_send_response(None, &req, &mut w);
    assert!(!is_unexpected_request(resp.unwrap()));
}
