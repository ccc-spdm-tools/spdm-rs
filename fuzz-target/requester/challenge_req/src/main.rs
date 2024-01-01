// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::*;
use spdmlib::protocol::*;
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn fuzz_send_receive_spdm_challenge(fuzzdata: Arc<Vec<u8>>) {
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
    spdmlib::crypto::rand::register(FAKE_RAND.clone());

    let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
    device_io_requester.set_rx(&fuzzdata);
    let device_io_requester = Arc::new(Mutex::new(device_io_requester));

    let mut requester = requester::RequesterContext::new(
        device_io_requester,
        pcidoe_transport_encap,
        req_config_info,
        req_provision_info,
    );
    requester.common.reset_runtime_info();

    requester
        .common
        .negotiate_info
        .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

    requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    requester.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());

    let _ = requester
        .send_receive_spdm_challenge(
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .await
        .is_err();
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
                0x1, 0x0, 0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x11, 0x3, 0x0, 0x1, 0x28, 0xaf, 0x70,
                0x27, 0xbc, 0x2d, 0x95, 0xb5, 0xa0, 0xe4, 0x26, 0x4, 0xc5, 0x8c, 0x5c, 0x3c, 0xbf,
                0xa2, 0xc8, 0x24, 0xa6, 0x30, 0xca, 0x2f, 0xf, 0x4a, 0x79, 0x35, 0x57, 0xfb, 0x39,
                0x3b, 0xdd, 0x8a, 0xc8, 0x8a, 0x92, 0xd8, 0xa3, 0x70, 0x17, 0x12, 0x83, 0x9b, 0x66,
                0xe1, 0x3a, 0x3a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x3, 0x76, 0xd, 0x57, 0x9b,
                0xaf, 0xe9, 0x6f, 0xc2, 0x5c, 0x2f, 0x3a, 0xfb, 0x81, 0xb, 0x4f, 0xa4, 0x5a, 0x65,
                0x4a, 0xc8, 0x64, 0x38, 0x91, 0xb1, 0x89, 0x8d, 0x42, 0xe9, 0xff, 0x55, 0xb, 0xfd,
                0xb1, 0xe1, 0x3c, 0x19, 0x1f, 0x1e, 0x8, 0xa2, 0x78, 0xd, 0xf3, 0x6, 0x6a, 0xfa,
                0xe, 0xee, 0xde, 0x27, 0x9, 0xb3, 0x20, 0xa1, 0xf5, 0x8d, 0x6e, 0xfc, 0x8a, 0x30,
                0x91, 0x5, 0x80, 0xae, 0x89, 0xb4, 0xee, 0x38, 0xcc, 0x92, 0x8e, 0x5e, 0x5b, 0x25,
                0x10, 0xdb, 0xd8, 0x32, 0x11, 0xd7, 0xf8, 0x23, 0x76, 0x49, 0x3d, 0x96, 0x7e, 0xb3,
                0x22, 0x4c, 0x5d, 0x50, 0x79, 0x71, 0x98, 0x0, 0x0,
            ];
            executor::block_on(fuzz_send_receive_spdm_challenge(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_send_receive_spdm_challenge(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_send_receive_spdm_challenge(Arc::new(data.to_vec())));
    });
}
