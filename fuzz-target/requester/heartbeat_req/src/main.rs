// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::protocol::*;

use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    *,
};

use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn fuzz_send_receive_spdm_heartbeat(fuzzdata: Arc<Vec<u8>>) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::crypto::aead::register(FAKE_AEAD.clone());

    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
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
    requester.common.session[0] = SpdmSession::new();
    requester.common.session[0].setup(4294836221).unwrap();
    requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
    requester.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );

    let _ = requester.send_receive_spdm_heartbeat(4294836221).await;
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
                0x1, 0x0, 0x2, 0x0, 0x9, 0x0, 0x0, 0x0, 0xfe, 0xff, 0xfe, 0xff, 0x16, 0x0, 0xca,
                0xa7, 0x51, 0x55, 0x4d, 0x60, 0xe6, 0x39, 0x1d, 0xa0, 0xb2, 0x1e, 0x4e, 0x4a, 0x5c,
                0x0, 0x61, 0xf, 0xd3, 0x4b, 0xbe, 0xc,
            ];

            new_logger_from_env().init().unwrap();
            executor::block_on(fuzz_send_receive_spdm_heartbeat(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_send_receive_spdm_heartbeat(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    {
        afl::fuzz!(|data: &[u8]| {
            let fuzzdata = [
                0x1, 0x0, 0x2, 0x0, 0x9, 0x0, 0x0, 0x0, 0xfe, 0xff, 0xfe, 0xff, 0x16, 0x0, 0xca,
                0xa7, 0x51, 0x55, 0x4d, 0x60, 0xe6, 0x39, 0x1d, 0xa0, 0xb2, 0x1e, 0x4e, 0x4a, 0x5c,
                0x0, 0x61, 0xf, 0xd3, 0x4b, 0xbe, 0xc,
            ];
            let mut buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
            buffer[..fuzzdata.len()].copy_from_slice(&fuzzdata);
            let left = buffer.len() - fuzzdata.len();
            let data_len = data.len();
            match data_len > left {
                true => buffer[fuzzdata.len()..].copy_from_slice(&data[..left]),
                false => buffer[fuzzdata.len()..data_len + fuzzdata.len()].copy_from_slice(data),
            }
            executor::block_on(fuzz_send_receive_spdm_heartbeat(Arc::new(data.to_vec())));
        });
    }
}
