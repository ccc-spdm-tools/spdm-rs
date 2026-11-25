// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// A failed key update ends the session on the Requester.

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use async_trait::async_trait;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::{SpdmDeviceIo, SpdmTransportEncap};
use spdmlib::config::RECEIVER_BUFFER_SIZE;
use spdmlib::error::{SpdmResult, SpdmStatus, SPDM_STATUS_BUSY_PEER, SPDM_STATUS_NOT_READY_PEER};
use spdmlib::message::key_update::SpdmKeyUpdateOperation;
use spdmlib::message::{SpdmErrorCode, SpdmRequestResponseCode};
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

const SESSION_ID: u32 = (0xffu32 << 16) + 0xFFFEu32;

fn setup_session(session: &mut SpdmSession, with_data_secret: bool) {
    session.setup(SESSION_ID).unwrap();
    session.set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmKemAlgo::empty(),
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
}

// A device that answers the first request with an encrypted ERROR response, as a Responder that is
// Busy or NotReady does, without running the request. Every other request goes to the Responder.
struct ErrorOnceDeviceIo {
    inner: FakeSpdmDeviceIo,
    responder: Arc<Mutex<responder::ResponderContext>>,
    error: Option<(u8, Vec<u8>)>,
}

#[async_trait]
impl SpdmDeviceIo for ErrorOnceDeviceIo {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        timeout: usize,
    ) -> Result<usize, usize> {
        self.inner.receive(read_buffer, timeout).await
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        let Some((code, extended_data)) = self.error.take() else {
            return self.inner.send(buffer).await;
        };
        let mut responder = self.responder.lock();
        let responder = responder.deref_mut();

        // Take the request, so that the sequence number of the Responder moves on.
        let mut spdm_buffer = [0u8; RECEIVER_BUFFER_SIZE];
        let (used, secured) = PciDoeTransportEncap {}
            .decap(buffer.clone(), Arc::new(Mutex::new(&mut spdm_buffer[..])))
            .await?;
        assert!(secured);
        let mut request = [0u8; RECEIVER_BUFFER_SIZE];
        responder
            .common
            .get_session_via_id(SESSION_ID)
            .unwrap()
            .decode_spdm_secured_message(&spdm_buffer[..used], &mut request, true)?;

        let mut error = vec![
            u8::from(responder.common.negotiate_info.spdm_version_sel),
            SpdmRequestResponseCode::SpdmResponseError.get_u8(),
            code,
            0,
        ];
        error.extend_from_slice(&extended_data);
        let mut transport_buffer = [0u8; RECEIVER_BUFFER_SIZE];
        let used = responder
            .common
            .encode_secured_message(SESSION_ID, &error, &mut transport_buffer, false, false)
            .await?;
        let mut device_io = responder.common.device_io.lock();
        device_io
            .deref_mut()
            .send(Arc::new(&transport_buffer[..used]))
            .await
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

// A Requester connected to a Responder, both with an established session. The
// Requester can derive updated keys only if with_data_secret is set.
fn new_requester(with_data_secret: bool) -> RequesterContext {
    new_requester_with_error(with_data_secret, None)
}

// The Responder answers the first request with this ERROR code and extended data, if any.
fn new_requester_with_error(
    with_data_secret: bool,
    error: Option<(u8, Vec<u8>)>,
) -> RequesterContext {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let (req_config_info, req_provision_info) = create_info();

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

    let mut responder = responder::ResponderContext::new(
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            SharedBuffer::new(),
        )))),
        Arc::new(Mutex::new(PciDoeTransportEncap {})),
        rsp_config_info,
        rsp_provision_info,
    );
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    setup_session(&mut responder.common.session[0], true);

    let responder = Arc::new(Mutex::new(responder));
    let mut requester = RequesterContext::new(
        Arc::new(Mutex::new(ErrorOnceDeviceIo {
            inner: FakeSpdmDeviceIo::new(Arc::new(SharedBuffer::new()), responder.clone()),
            responder,
            error,
        })),
        Arc::new(Mutex::new(PciDoeTransportEncap {})),
        req_config_info,
        req_provision_info,
    );
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.session = gen_array_clone(SpdmSession::new(), 4);
    setup_session(&mut requester.common.session[0], with_data_secret);
    requester
}

#[test]
fn test_key_update_failure_ends_session() {
    let task = async {
        // The Requester cannot derive the updated keys.
        let mut requester = new_requester(false);

        let result = requester
            .send_receive_spdm_key_update(SESSION_ID, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .await;
        assert!(result.is_err());
        assert!(requester.common.get_session_via_id(SESSION_ID).is_none());
    };
    executor::block_on(task);
}

#[test]
fn test_key_update_success_keeps_session() {
    let task = async {
        let mut requester = new_requester(true);

        let result = requester
            .send_receive_spdm_key_update(SESSION_ID, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .await;
        assert!(result.is_ok());
        assert!(requester.common.get_session_via_id(SESSION_ID).is_some());
    };
    executor::block_on(task);
}

#[test]
fn test_key_update_invalid_operation_keeps_session() {
    let task = async {
        let mut requester = new_requester(true);

        // Rejected before anything is sent, so there is nothing to recover from.
        let result = requester
            .send_receive_spdm_key_update(SESSION_ID, SpdmKeyUpdateOperation::Unknown(0))
            .await;
        assert!(result.is_err());
        assert!(requester.common.get_session_via_id(SESSION_ID).is_some());
    };
    executor::block_on(task);
}

// A Responder that is Busy or NotReady has not failed. The session stays, with the keys and the
// sequence numbers it had, and the Requester can send the key update again.
fn key_update_retry_after(code: u8, extended_data: Vec<u8>, expected: SpdmStatus) {
    let task = async move {
        let mut requester = new_requester_with_error(true, Some((code, extended_data)));
        let session = requester.common.get_session_via_id(SESSION_ID).unwrap();
        let keys = session.get_application_secret();

        let result = requester
            .send_receive_spdm_key_update(SESSION_ID, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .await;
        assert_eq!(result, Err(expected));
        let session = requester.common.get_session_via_id(SESSION_ID).unwrap();
        assert_eq!(
            session.get_session_state(),
            SpdmSessionState::SpdmSessionEstablished
        );
        // The updated keys were dropped. The messages sent and received moved the sequence
        // numbers on.
        let kept = session.get_application_secret();
        assert_eq!(kept.request_data_secret, keys.request_data_secret);
        assert_eq!(kept.response_data_secret, keys.response_data_secret);
        assert_eq!(
            kept.request_direction.encryption_key,
            keys.request_direction.encryption_key
        );
        assert_eq!(
            kept.response_direction.encryption_key,
            keys.response_direction.encryption_key
        );

        // The retry works with the old keys, and then updates them.
        let result = requester
            .send_receive_spdm_key_update(SESSION_ID, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .await;
        assert!(result.is_ok());
        let session = requester.common.get_session_via_id(SESSION_ID).unwrap();
        assert_ne!(
            session.get_application_secret().request_data_secret,
            keys.request_data_secret
        );
    };
    executor::block_on(task);
}

#[test]
fn test_key_update_busy_keeps_session_and_can_retry() {
    key_update_retry_after(
        SpdmErrorCode::SpdmErrorBusy.get_u8(),
        Vec::new(),
        SPDM_STATUS_BUSY_PEER,
    );
}

#[test]
fn test_key_update_response_not_ready_keeps_session_and_can_retry() {
    // rd_exponent, request code, token, rdtm
    let extended_data = vec![
        1,
        SpdmRequestResponseCode::SpdmRequestKeyUpdate.get_u8(),
        1,
        1,
    ];
    key_update_retry_after(
        SpdmErrorCode::SpdmErrorResponseNotReady.get_u8(),
        extended_data,
        SPDM_STATUS_NOT_READY_PEER,
    );
}
