// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Writer;
use fuzzlib::spdmlib::message::SpdmKeyExchangeMutAuthAttributes;
use fuzzlib::*;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::protocol::*;
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn fuzz_encap_handle_get_digest(fuzzdata: Arc<Vec<u8>>) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::crypto::aead::register(FAKE_AEAD.clone());
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle encap get digest'
    // - description: '<p>Requester process encapsulated GET_DIGEST request and write send buffer.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let mut requester = requester::RequesterContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.req_capabilities_sel =
            requester.common.negotiate_info.req_capabilities_sel
                | SpdmRequestCapabilityFlags::ENCAP_CAP
                | SpdmRequestCapabilityFlags::CERT_CAP;
        requester.common.negotiate_info.rsp_capabilities_sel =
            requester.common.negotiate_info.rsp_capabilities_sel
                | SpdmResponseCapabilityFlags::ENCAP_CAP;

        requester.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        requester.common.session[0] = SpdmSession::new();
        requester.common.session[0].setup(4294836221).unwrap();
        requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0].set_mut_auth_requested(
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS,
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        requester.encap_handle_get_digest(&fuzzdata, &mut writer)
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle encap get digest'
    // - description: '<p>Requester process encapsulated GET_DIGEST request failed due to no CERT_CAP.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let mut requester = requester::RequesterContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.req_capabilities_sel =
            requester.common.negotiate_info.req_capabilities_sel
                | SpdmRequestCapabilityFlags::ENCAP_CAP;
        requester.common.negotiate_info.rsp_capabilities_sel =
            requester.common.negotiate_info.rsp_capabilities_sel
                | SpdmResponseCapabilityFlags::ENCAP_CAP;

        requester.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        requester.common.session[0] = SpdmSession::new();
        requester.common.session[0].setup(4294836221).unwrap();
        requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0].set_mut_auth_requested(
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS,
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        requester.encap_handle_get_digest(&fuzzdata, &mut writer)
    }
}

#[cfg(not(feature = "use_libfuzzer"))]
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
            let fuzzdata = vec![1, 0, 1, 0, 48, 0, 0, 0, 17, 2, 255, 1, 127, 0, 0, 0];
            executor::block_on(fuzz_encap_handle_get_digest(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_encap_handle_get_digest(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_encap_handle_get_digest(Arc::new(data.to_vec())));
    });
}
