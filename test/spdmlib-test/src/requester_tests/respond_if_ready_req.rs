// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use async_trait::async_trait;
use spdmlib::common::{SpdmDeviceIo, SpdmRespondIfReadyContext, SpdmTransportEncap};
use spdmlib::config;
use spdmlib::error::{
    SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_MSG_SIZE,
    SPDM_STATUS_NOT_READY_PEER,
};
use spdmlib::message::SpdmRequestResponseCode;
use spdmlib::protocol::SpdmVersion;
use spdmlib::requester::{RequesterContext, MAX_RESPOND_IF_READY_RETRY_COUNT};
use spdmlib::time::SpdmTime;
use spin::Mutex;
use std::cell::RefCell;
use std::collections::VecDeque;
extern crate alloc;
use alloc::sync::Arc;

const GET_DIGESTS: u8 = 0x81;
const GET_CAPABILITIES: u8 = 0xE1;
const TOKEN: u8 = 0x07;
const DIGESTS: [u8; 4] = [0x12, 0x01, 0x00, 0x01];
const GET_CAPABILITIES_REQUEST: [u8; 4] = [0x12, GET_CAPABILITIES, 0x00, 0x00];
// SPDM 1.2 CAPABILITIES: CERT_CAP | CHAL_CAP, DataTransferSize = MaxSPDMmsgSize = 0x1000.
const CAPABILITIES: [u8; 20] = [
    0x12, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00,
];

thread_local! {
    static SLEEPS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

fn record_sleep(us: usize) {
    SLEEPS.with(|s| s.borrow_mut().push(us));
}

fn take_sleeps() -> Vec<usize> {
    SLEEPS.with(|s| s.borrow_mut().split_off(0))
}

fn not_ready(rdt_exponent: u8, request_code: u8, token: u8, rdtm: u8) -> Vec<u8> {
    vec![
        0x12,
        0x7F,
        0x42,
        0x00,
        rdt_exponent,
        request_code,
        token,
        rdtm,
    ]
}

struct ScriptedDeviceIo {
    responses: VecDeque<Vec<u8>>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl SpdmDeviceIo for ScriptedDeviceIo {
    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        let mut spdm = [0u8; config::RECEIVER_BUFFER_SIZE];
        let (used, _) = PciDoeTransportEncap {}
            .decap(buffer, Arc::new(Mutex::new(&mut spdm[..])))
            .await?;
        self.sent.lock().push(spdm[..used].to_vec());
        Ok(())
    }

    async fn receive(
        &mut self,
        buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let response = self.responses.pop_front().ok_or(0usize)?;
        PciDoeTransportEncap {}
            .encap(Arc::new(&response[..]), buffer, false)
            .await
            .map_err(|_| 0usize)
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

struct Outcome {
    result: SpdmResult<usize>,
    response: Vec<u8>,
    sent: Vec<Vec<u8>>,
    sleeps: Vec<usize>,
}

// The device answers each request with the next entry of `responses`.
fn new_context(responses: &[Vec<u8>]) -> (RequesterContext, Arc<Mutex<Vec<Vec<u8>>>>) {
    spdmlib::time::register(SpdmTime {
        sleep_cb: record_sleep,
    });
    take_sleeps();

    let sent = Arc::new(Mutex::new(Vec::new()));
    let device_io = Arc::new(Mutex::new(ScriptedDeviceIo {
        responses: responses.iter().cloned().collect(),
        sent: sent.clone(),
    }));
    let transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let (config_info, provision_info) = create_info();
    let mut context =
        RequesterContext::new(device_io, transport_encap, config_info, provision_info);
    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    (context, sent)
}

// The Responder first answered GET_DIGESTS with `first_response`, then answers
// each RESPOND_IF_READY with the next entry of `responses`.
fn run(first_response: &[u8], responses: &[Vec<u8>]) -> Outcome {
    let (mut context, sent) = new_context(responses);

    let first_response = first_response.to_vec();
    let (result, response) = executor::block_on(async move {
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        receive_buffer[..first_response.len()].copy_from_slice(&first_response);
        let result = context
            .spdm_handle_response_not_ready(
                None,
                SpdmRequestResponseCode::SpdmRequestGetDigests,
                &mut receive_buffer,
                first_response.len(),
                false,
            )
            .await;
        let used = *result.as_ref().unwrap_or(&0);
        (result, receive_buffer[..used].to_vec())
    });
    let sent = sent.lock().clone();
    Outcome {
        result,
        response,
        sent,
        sleeps: take_sleeps(),
    }
}

#[test]
fn test_other_response_is_returned_unchanged() {
    let outcome = run(&DIGESTS, &[]);
    assert_eq!(outcome.result.unwrap(), DIGESTS.len());
    assert_eq!(outcome.response, DIGESTS);
    assert!(outcome.sent.is_empty());
    assert!(outcome.sleeps.is_empty());
}

#[test]
fn test_waits_rdt_then_sends_respond_if_ready() {
    let outcome = run(&not_ready(4, GET_DIGESTS, TOKEN, 2), &[DIGESTS.to_vec()]);
    assert_eq!(outcome.result.unwrap(), DIGESTS.len());
    assert_eq!(outcome.response, DIGESTS);
    assert_eq!(outcome.sleeps, [1 << 4]);
    assert_eq!(outcome.sent, [vec![0x12, 0xFF, GET_DIGESTS, TOKEN]]);
}

#[test]
fn test_each_not_ready_sets_its_own_wait() {
    let outcome = run(
        &not_ready(4, GET_DIGESTS, TOKEN, 2),
        &[not_ready(10, GET_DIGESTS, TOKEN, 2), DIGESTS.to_vec()],
    );
    assert_eq!(outcome.result.unwrap(), DIGESTS.len());
    assert_eq!(outcome.response, DIGESTS);
    assert_eq!(outcome.sleeps, [1 << 4, 1 << 10]);
    assert_eq!(outcome.sent.len(), 2);
}

#[test]
fn test_max_rdt_exponent_waits_full_rdt() {
    let outcome = run(&not_ready(31, GET_DIGESTS, TOKEN, 2), &[DIGESTS.to_vec()]);
    assert!(outcome.result.is_ok());
    assert_eq!(outcome.sleeps, [1 << 31]);
}

#[test]
fn test_gives_up_after_max_retries() {
    let still_not_ready = not_ready(0, GET_DIGESTS, TOKEN, 2);
    let outcome = run(
        &still_not_ready,
        &[
            still_not_ready.clone(),
            still_not_ready.clone(),
            still_not_ready.clone(),
        ],
    );
    let status = outcome.result.unwrap_err();
    assert_eq!(status, SPDM_STATUS_NOT_READY_PEER);
    let error_data = status.error_data.unwrap();
    assert_eq!(&error_data.data[..error_data.length], &still_not_ready[..]);
    assert_eq!(outcome.sent.len(), 3);
    assert_eq!(outcome.sleeps.len(), 3);
}

#[test]
fn test_rejects_invalid_ext_data_without_waiting() {
    for response in [
        not_ready(4, 0x84, TOKEN, 2),         // RequestCode is not GET_DIGESTS
        not_ready(32, GET_DIGESTS, TOKEN, 2), // RDTExponent too large
        not_ready(4, GET_DIGESTS, TOKEN, 1),  // RDTM shall be greater than 1
        vec![0x11, 0x7F, 0x42, 0x00, 4, GET_DIGESTS, TOKEN, 2], // wrong SPDMVersion
    ] {
        let outcome = run(&response, &[]);
        assert_eq!(outcome.result.unwrap_err(), SPDM_STATUS_INVALID_MSG_FIELD);
        assert!(outcome.sent.is_empty());
        assert!(outcome.sleeps.is_empty());
    }
}

#[test]
fn test_rejects_missing_ext_data() {
    let outcome = run(&[0x12, 0x7F, 0x42, 0x00], &[]);
    assert_eq!(outcome.result.unwrap_err(), SPDM_STATUS_INVALID_MSG_SIZE);
    assert!(outcome.sent.is_empty());
}

#[test]
fn test_rejects_changed_token() {
    let outcome = run(
        &not_ready(4, GET_DIGESTS, TOKEN, 2),
        &[not_ready(4, GET_DIGESTS, TOKEN + 1, 2)],
    );
    assert_eq!(outcome.result.unwrap_err(), SPDM_STATUS_INVALID_MSG_FIELD);
    assert_eq!(outcome.sleeps, [1 << 4]);
}

#[test]
fn test_capabilities_transcript_excludes_respond_if_ready() {
    let (mut context, sent) = new_context(&[
        not_ready(4, GET_CAPABILITIES, TOKEN, 2),
        CAPABILITIES.to_vec(),
    ]);

    let message_a = executor::block_on(async move {
        context
            .receive_spdm_capability(&GET_CAPABILITIES_REQUEST)
            .await
            .unwrap();
        context.common.runtime_info.message_a.as_ref().to_vec()
    });

    assert_eq!(
        message_a,
        [&GET_CAPABILITIES_REQUEST[..], &CAPABILITIES[..]].concat()
    );
    assert_eq!(*sent.lock(), [vec![0x12, 0xFF, GET_CAPABILITIES, TOKEN]]);
    assert_eq!(take_sleeps(), [1 << 4]);
}

// Export the context after RESPOND_IF_READY is sent but before its response arrives.
fn checkpoint_with_respond_if_ready_pending() -> Vec<u8> {
    let (mut context, sent) = new_context(&[not_ready(4, GET_CAPABILITIES, TOKEN, 2)]);
    let checkpoint = executor::block_on(async move {
        assert!(context
            .receive_spdm_capability(&GET_CAPABILITIES_REQUEST)
            .await
            .is_err());
        assert_eq!(
            context.common.respond_if_ready,
            Some(SpdmRespondIfReadyContext {
                request_code: GET_CAPABILITIES,
                token: TOKEN,
                retry_count: 1,
                session_id: None,
            })
        );
        context.common.export().unwrap()
    });
    assert_eq!(*sent.lock(), [vec![0x12, 0xFF, GET_CAPABILITIES, TOKEN]]);
    checkpoint
}

fn restore_and_receive_capabilities(
    checkpoint: Vec<u8>,
    responses: &[Vec<u8>],
) -> (SpdmResult, RequesterContext, Vec<Vec<u8>>) {
    let (mut context, sent) = new_context(responses);
    let (result, context) = executor::block_on(async move {
        context.common.import(&checkpoint).unwrap();
        let result = context
            .receive_spdm_capability(&GET_CAPABILITIES_REQUEST)
            .await;
        (result, context)
    });
    let sent = sent.lock().clone();
    (result, context, sent)
}

#[test]
fn test_restore_receives_respond_if_ready_response() {
    let checkpoint = checkpoint_with_respond_if_ready_pending();

    let (result, context, sent) =
        restore_and_receive_capabilities(checkpoint, &[CAPABILITIES.to_vec()]);

    result.unwrap();
    assert_eq!(
        context.common.runtime_info.message_a.as_ref(),
        [&GET_CAPABILITIES_REQUEST[..], &CAPABILITIES[..]].concat()
    );
    assert!(context.common.respond_if_ready.is_none());
    assert!(sent.is_empty());
    assert!(take_sleeps().is_empty());
}

#[test]
fn test_restore_keeps_token_and_retry_count() {
    let checkpoint = checkpoint_with_respond_if_ready_pending();
    let (result, _, sent) = restore_and_receive_capabilities(
        checkpoint.clone(),
        &[not_ready(4, GET_CAPABILITIES, TOKEN + 1, 2)],
    );
    assert_eq!(result.unwrap_err(), SPDM_STATUS_INVALID_MSG_FIELD);
    assert!(sent.is_empty());

    let (result, context, sent) = restore_and_receive_capabilities(
        checkpoint,
        &[
            not_ready(4, GET_CAPABILITIES, TOKEN, 2),
            not_ready(4, GET_CAPABILITIES, TOKEN, 2),
            not_ready(4, GET_CAPABILITIES, TOKEN, 2),
        ],
    );
    assert_eq!(result.unwrap_err(), SPDM_STATUS_NOT_READY_PEER);
    // One RESPOND_IF_READY was sent before the checkpoint.
    assert_eq!(sent.len(), MAX_RESPOND_IF_READY_RETRY_COUNT - 1);
    assert!(context.common.respond_if_ready.is_none());
}

#[test]
fn test_import_of_checkpoint_without_respond_if_ready() {
    let (context, _) = new_context(&[]);
    let checkpoint = context.common.export().unwrap();
    let (mut restored, _) = new_context(&[]);
    restored.common.respond_if_ready = Some(SpdmRespondIfReadyContext::default());
    // Checkpoints from before RESPOND_IF_READY support lack the last byte.
    restored
        .common
        .import(&checkpoint[..checkpoint.len() - 1])
        .unwrap();
    assert!(restored.common.respond_if_ready.is_none());
}

#[test]
fn test_new_request_drops_respond_if_ready() {
    let (mut context, _) = new_context(&[]);
    context.common.respond_if_ready = Some(SpdmRespondIfReadyContext {
        request_code: GET_CAPABILITIES,
        token: TOKEN,
        retry_count: 1,
        session_id: None,
    });
    let context = executor::block_on(async move {
        context
            .send_message(None, &GET_CAPABILITIES_REQUEST, false)
            .await
            .unwrap();
        context
    });
    assert!(context.common.respond_if_ready.is_none());
}
