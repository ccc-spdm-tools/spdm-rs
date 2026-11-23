// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// A failed key update ends the session on the Requester.

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::message::key_update::SpdmKeyUpdateOperation;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

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

// A Requester connected to a Responder, both with an established session. The
// Requester can derive updated keys only if with_data_secret is set.
fn new_requester(with_data_secret: bool) -> RequesterContext {
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

    let mut requester = RequesterContext::new(
        Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(SharedBuffer::new()),
            Arc::new(Mutex::new(responder)),
        ))),
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
