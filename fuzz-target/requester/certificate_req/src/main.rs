// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::*;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::protocol::*;
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn fuzz_send_receive_spdm_certificate(fuzzdata: Arc<Vec<u8>>) {
    spdmlib::crypto::aead::register(FAKE_AEAD.clone());
    spdmlib::crypto::cert_operation::register(FAKE_CERT_OPERATION.clone());
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle certificate response'
    // - description: '<p>Request certificate and receive partial certificate.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();
        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        let _ = requester
            .send_receive_spdm_certificate(None, 0)
            .await
            .is_err();
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle certificate response'
    // - description: '<p>Requester receives certificate and pass the verification of provisioned root cert.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();
        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());

        // to pass the verification of provisioned root cert with fake cert_operation
        let mut fake_root = SpdmCertChainData::default();
        // range [68..101] of seed `certificate_req.raw` is fake root cert
        fake_root.data_size = 33;
        let start_index = 68;
        let end_index = start_index + fake_root.data_size as usize;
        if fuzzdata.len() >= end_index {
            fake_root.data[0..fake_root.data_size as usize]
                .copy_from_slice(&fuzzdata[start_index..end_index]);
        }

        let mut peer_root_cert_data_list =
            gen_array_clone(None, spdmlib::config::MAX_ROOT_CERT_SUPPORT);
        peer_root_cert_data_list[0] = Some(fake_root);

        requester.common.provision_info.peer_root_cert_data = peer_root_cert_data_list;
        let _ = requester
            .send_receive_spdm_certificate(None, 0)
            .await
            .is_err();
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle certificate response'
    // - description: '<p>Request certificate and receive partial certificate in session.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();
        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        requester.common.session[0] = SpdmSession::new();
        requester.common.session[0].setup(4294836221).unwrap();
        requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );

        let _ = requester
            .send_receive_spdm_certificate(Some(4294836221), 0)
            .await
            .is_err();
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
            let fuzzdata = vec![
                1, 0, 1, 0, 48, 0, 0, 0, 17, 2, 255, 1, 127, 0, 0, 0, 0, 17, 3, 0, 1, 40, 175, 112,
                39, 188, 132, 74, 57, 59, 221, 138, 200, 158, 146, 216, 163, 112, 23, 18, 131, 155,
                102, 225, 58, 58, 49, 11, 42, 205, 113, 132, 74, 251, 185, 250, 222, 111, 123, 34,
                132, 180, 134, 168, 183, 103, 238, 4, 45, 255, 255, 255, 127, 198, 199, 61, 112,
                123, 231, 0, 206, 47, 251, 131, 40, 175, 112, 39, 188, 132, 74, 190, 105, 0, 64,
                36, 157, 254, 244, 68, 221, 19, 51, 22, 40, 110, 235, 82, 62, 86, 193, 20, 43, 245,
                230, 18, 193, 240, 192, 137, 158, 145, 137, 119, 25, 53, 131, 79, 219, 238, 133,
                74, 194, 76, 145, 125, 17, 153, 210, 123, 49, 221, 151, 25, 130, 110, 134, 159,
                182, 154, 251, 94,
            ];
            executor::block_on(fuzz_send_receive_spdm_certificate(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_send_receive_spdm_certificate(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_send_receive_spdm_certificate(Arc::new(data.to_vec())));
    });
}
