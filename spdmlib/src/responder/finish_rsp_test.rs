// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM 1.1 mutual-auth FINISH: the Requester signature has to cover the
//! session transcript, so a signature over any other message is rejected.

use super::ResponderContext;
use crate::common::session::{SpdmSession, SpdmSessionState};
use crate::common::{SpdmConfigInfo, SpdmDeviceIo, SpdmProvisionInfo, SpdmTransportEncap};
use crate::crypto;
use crate::message::*;
use crate::protocol::*;
use codec::Writer;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use spin::Mutex;

#[path = "../message/mod_test.common.inc.rs"]
mod testlib;

const SESSION_ID: u32 = 0xFFFE_FFFE;

fn spdm_cert_chain(der: &[u8]) -> SpdmCertChainBuffer {
    let (root_begin, root_end) = crypto::cert_operation::get_cert_from_cert_chain(der, 0).unwrap();
    let root_hash = crypto::hash::hash_all(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        &der[root_begin..root_end],
    )
    .unwrap();
    SpdmCertChainBuffer::new(der, root_hash.as_ref()).unwrap()
}

fn requester_sign(data: &[u8]) -> SpdmSignatureStruct {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        include_bytes!("../../../test_key/ecp384/end_requester.key.p8"),
        &rng,
    )
    .unwrap();
    let signature = key_pair.sign(&rng, data).unwrap();
    let mut sig = SpdmSignatureStruct {
        data_size: signature.as_ref().len() as u16,
        ..Default::default()
    };
    sig.data[..signature.as_ref().len()].copy_from_slice(signature.as_ref());
    sig
}

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

    ctx.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
    ctx.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    ctx.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    ctx.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    ctx.common.negotiate_info.req_capabilities_sel =
        SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
    ctx.common.negotiate_info.rsp_capabilities_sel =
        SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
    ctx.common.provision_info.my_cert_chain[0] = Some(spdm_cert_chain(include_bytes!(
        "../../../test_key/ecp384/bundle_responder.certchain.der"
    )));
    ctx.common.peer_info.peer_cert_chain[0] = Some(spdm_cert_chain(include_bytes!(
        "../../../test_key/ecp384/bundle_requester.certchain.der"
    )));
    ctx.common.runtime_info.set_peer_used_cert_chain_slot_id(0);

    ctx.common.session[0] = SpdmSession::new();
    let session = &mut ctx.common.session[0];
    session.setup(SESSION_ID).unwrap();
    session.set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmKemAlgo::empty(),
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    session.set_mut_auth_requested(SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ);
    session
        .set_shared_secret(
            SpdmVersion::SpdmVersion11,
            SpdmSharedSecretFinalKeyStruct {
                data_size: 48,
                data: Box::new([0x11; SPDM_MAX_SHARED_SECRET_SIZE]),
            },
        )
        .unwrap();
    session
        .generate_handshake_secret(
            SpdmVersion::SpdmVersion11,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0x22; SPDM_MAX_HASH_SIZE]),
            },
        )
        .unwrap();
    session.set_session_state(SpdmSessionState::SpdmSessionHandshaking);
    ctx.common
        .append_message_k(SESSION_ID, &[0x11, 0xe4, 0x00, 0x00])
        .unwrap();
    ctx
}

/// Build a FINISH request carrying `signature` and a valid RequesterVerifyData.
fn finish_request(ctx: &ResponderContext, signature: &SpdmSignatureStruct) -> ([u8; 512], usize) {
    let header = [0x11, 0xe5, 0x01, 0x00]; // SIGNATURE_INCLUDED, ReqSlotID 0
    let sig = &signature.data[..signature.data_size as usize];

    let session = ctx.common.get_immutable_session_via_id(SESSION_ID).unwrap();
    let mut message_f = session.runtime_info.message_f.clone();
    message_f.append_message(&header).unwrap();
    message_f.append_message(sig).unwrap();
    let th = ctx
        .common
        .calc_rsp_transcript_data(
            false,
            true,
            &session.runtime_info.message_k,
            Some(&message_f),
            None,
        )
        .unwrap();
    let th_hash = crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_384, th.as_ref()).unwrap();
    let verify_data = session
        .generate_hmac_with_request_finished_key(th_hash.as_ref())
        .unwrap();

    let mut bytes = [0u8; 512];
    let mut writer = Writer::init(&mut bytes);
    writer.extend_from_slice(&header).unwrap();
    writer.extend_from_slice(sig).unwrap();
    writer.extend_from_slice(verify_data.as_ref()).unwrap();
    let used = writer.used();
    (bytes, used)
}

/// The transcript a Requester signs in SPDM 1.1 FINISH: message_a, both
/// certificate chain hashes, message_k and the FINISH header.
fn finish_transcript(ctx: &ResponderContext) -> alloc::vec::Vec<u8> {
    let session = ctx.common.get_immutable_session_via_id(SESSION_ID).unwrap();
    let mut message_f = session.runtime_info.message_f.clone();
    message_f.append_message(&[0x11, 0xe5, 0x01, 0x00]).unwrap();
    ctx.common
        .calc_rsp_transcript_data(
            false,
            true,
            &session.runtime_info.message_k,
            Some(&message_f),
            None,
        )
        .unwrap()
        .as_ref()
        .to_vec()
}

#[test]
fn spdm11_finish_rejects_signature_not_over_transcript() {
    let mut ctx = new_responder();
    let signature = requester_sign(&[]);
    let (bytes, used) = finish_request(&ctx, &signature);

    let mut rsp = [0u8; 512];
    let mut writer = Writer::init(&mut rsp);
    let (status, rsp) = ctx.handle_spdm_finish(SESSION_ID, &bytes[..used], &mut writer);
    assert!(status.is_err());
    let rsp = rsp.unwrap();
    assert_eq!(rsp[1], SpdmRequestResponseCode::SpdmResponseError.get_u8());
    assert_eq!(rsp[2], SpdmErrorCode::SpdmErrorDecryptError.get_u8());
}

#[test]
fn spdm11_finish_accepts_signature_over_transcript() {
    let mut ctx = new_responder();
    let signature = requester_sign(&finish_transcript(&ctx));
    let (bytes, used) = finish_request(&ctx, &signature);

    let mut rsp = [0u8; 512];
    let mut writer = Writer::init(&mut rsp);
    let (status, rsp) = ctx.handle_spdm_finish(SESSION_ID, &bytes[..used], &mut writer);
    assert!(status.is_ok());
    assert_eq!(
        rsp.unwrap()[1],
        SpdmRequestResponseCode::SpdmResponseFinishRsp.get_u8()
    );
}
