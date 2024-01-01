// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    spdmlib::message::SpdmKeyExchangeMutAuthAttributes,
    *,
};
use spdmlib::protocol::*;
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn fuzz_handle_spdm_finish(data: Arc<Vec<u8>>) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::crypto::hmac::register(FAKE_HMAC.clone());
    spdmlib::crypto::hkdf::register(FAKE_HKDF.clone());
    spdmlib::crypto::asym_verify::register(FAKE_ASYM_VERIFY.clone());

    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle finish request'
    // - description: '<p>Respond finish rsp to complete the handshake, with HANDSHAKE_IN_THE_CLEAR_CAP.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
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
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        context.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );

        #[cfg(feature = "hashed-transcript-data")]
        {
            let mut dhe_secret = SpdmDheFinalKeyStruct::default();
            dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
            context.common.session[0]
                .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
                .unwrap();
            context.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        context
            .common
            .runtime_info
            .set_last_session_id(Some(4294836221));

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = codec::Writer::init(&mut response_buffer);
        let _ = context.handle_spdm_finish(4294836221, &data, &mut writer);
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle finish request'
    // - description: '<p>Respond finish rsp to complete the handshake, with KEY_UPD_CAP.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
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
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
        context.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::KEY_UPD_CAP;

        context.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );

        #[cfg(feature = "hashed-transcript-data")]
        {
            let mut dhe_secret = SpdmDheFinalKeyStruct::default();
            dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
            context.common.session[0]
                .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
                .unwrap();
            context.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        context
            .common
            .runtime_info
            .set_last_session_id(Some(4294836221));

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = codec::Writer::init(&mut response_buffer);
        let _ = context.handle_spdm_finish(4294836221, &data, &mut writer);
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle finish request'
    // - description: '<p>Respond finish rsp to complete the handshake, but fail to verify hmac.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
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
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        context.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        context.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );

        #[cfg(feature = "hashed-transcript-data")]
        {
            let mut dhe_secret = SpdmDheFinalKeyStruct::default();
            dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
            context.common.session[0]
                .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
                .unwrap();
            context.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        context
            .common
            .runtime_info
            .set_last_session_id(Some(4294836221));

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = codec::Writer::init(&mut response_buffer);
        let _ = context.handle_spdm_finish(4294836221, &data, &mut writer);
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle finish request'
    // - description: '<p>Respond finish rsp to complete the handshake, with message_a set.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
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
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        context.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );

        #[cfg(feature = "hashed-transcript-data")]
        {
            let mut dhe_secret = SpdmDheFinalKeyStruct::default();
            dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
            context.common.session[0]
                .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
                .unwrap();
            context.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        context
            .common
            .runtime_info
            .message_a
            .append_message(&[1u8; config::MAX_SPDM_MSG_SIZE - 103]);
        context
            .common
            .runtime_info
            .set_last_session_id(Some(4294836221));

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = codec::Writer::init(&mut response_buffer);
        let _ = context.handle_spdm_finish(4294836221, &data, &mut writer);
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle finish request'
    // - description: '<p>Respond finish rsp to complete the handshake, with mut auth requested.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
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
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
        context.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::KEY_UPD_CAP;
        context.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
        context.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );

        #[cfg(feature = "hashed-transcript-data")]
        {
            let mut dhe_secret = SpdmDheFinalKeyStruct::default();
            dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
            context.common.session[0]
                .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
                .unwrap();
            context.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        context.common.session[0].set_mut_auth_requested(
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS,
        );
        context
            .common
            .runtime_info
            .set_last_session_id(Some(4294836221));

        let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let mut writer = codec::Writer::init(&mut response_buffer);
        let _ = context.handle_spdm_finish(4294836221, &data, &mut writer);
    }
}
fn main() {
    #[cfg(all(feature = "fuzzlogfile", feature = "fuzz"))]
    flexi_logger::Logger::try_with_str("info")
        .unwrap()
        .log_to_file(
            FileSpec::default()
                .directory("traces")
                .basename("foo")
                .discriminant("Sample4711A")
                .suffix("trc"),
        )
        .print_message()
        .create_symlink("current_run")
        .start()
        .unwrap();

    #[cfg(not(feature = "fuzz"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = vec![
                0x11, 0xe5, 0x0, 0x0, 0xd4, 0xab, 0xc, 0x98, 0x44, 0x6, 0xc1, 0x77, 0xe4, 0x37,
                0x79, 0x78, 0x26, 0xd4, 0x4c, 0x9b, 0x38, 0x30, 0xb2, 0xa3, 0xa, 0x5c, 0xa4, 0xd9,
                0x7b, 0x12, 0xe1, 0xd6, 0x38, 0xcb, 0xe0, 0xfb, 0xaa, 0x1c, 0xeb, 0xc5, 0xcb, 0x35,
                0x9b, 0xf8, 0x21, 0x9c, 0x7c, 0xd4, 0x33, 0x49, 0xdc, 0x61,
            ];
            executor::block_on(fuzz_handle_spdm_finish(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_handle_spdm_finish(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_handle_spdm_finish(Arc::new(data.to_vec())));
    });
}
