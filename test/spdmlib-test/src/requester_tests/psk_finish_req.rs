// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::crypto_callback::*;
use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::session::{self, SpdmSession};
use spdmlib::config::MAX_SPDM_PSK_HINT_SIZE;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{crypto, responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_send_receive_spdm_psk_finish() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
        crypto::hmac::register(FAKE_HMAC.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;

        // let rsp_session_id = 0x11u16;
        // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(4294901758).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0].set_use_psk(true);
        responder.common.session[0].runtime_info.psk_hint = Some(SpdmPskHintStruct {
            data_size: 5,
            data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
        });
        responder.common.session[0]
            .set_session_state(session::SpdmSessionState::SpdmSessionHandshaking);
        responder.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let _ = responder.common.session[0].generate_handshake_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 5,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            },
        );
        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;

        // let rsp_session_id = 0x11u16;
        // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(4294901758).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0].set_use_psk(true);
        requester.common.session[0].runtime_info.psk_hint = Some(SpdmPskHintStruct {
            data_size: 5,
            data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
        });
        requester.common.session[0]
            .set_session_state(session::SpdmSessionState::SpdmSessionHandshaking);
        requester.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let _ = requester.common.session[0].generate_handshake_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 5,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            },
        );

        let status = requester.send_receive_spdm_psk_finish(4294901758).await;
        assert!(status.is_ok());
    };
    executor::block_on(future);
}

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case1_send_receive_spdm_psk_finish() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
        crypto::hmac::register(FAKE_HMAC.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;

        // let rsp_session_id = 0x11u16;
        // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(4294901758).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0].set_use_psk(true);
        responder.common.session[0].runtime_info.psk_hint = Some(SpdmPskHintStruct {
            data_size: 5,
            data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
        });
        responder.common.session[0]
            .set_session_state(session::SpdmSessionState::SpdmSessionHandshaking);
        responder.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let _ = responder.common.session[0].generate_handshake_secret(
            // different handshake will cause psk finish fail
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 5,
                data: Box::new([1u8; SPDM_MAX_HASH_SIZE]),
            },
        );
        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;

        // let rsp_session_id = 0x11u16;
        // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(4294901758).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0].set_use_psk(true);
        requester.common.session[0].runtime_info.psk_hint = Some(SpdmPskHintStruct {
            data_size: 5,
            data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
        });
        requester.common.session[0]
            .set_session_state(session::SpdmSessionState::SpdmSessionHandshaking);
        requester.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let _ = requester.common.session[0].generate_handshake_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 5,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            },
        );

        let status = requester
            .send_receive_spdm_psk_finish(4294901758)
            .await
            .is_ok();
        assert_eq!(status, false);

        for session in requester.common.session.iter() {
            assert_eq!(
                session.get_session_id(),
                spdmlib::common::INVALID_SESSION_ID
            );
        }
    };
    executor::block_on(future);
}
