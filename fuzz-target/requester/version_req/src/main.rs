// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::{
    fake_device_io::{self, FakeSpdmDeviceIo},
    req_create_info, spdmlib,
    spdmlib::protocol::MAX_SPDM_VERSION_COUNT,
    spdmlib::{protocol::SpdmVersion, requester::RequesterContext},
    time::SPDM_TIME_IMPL,
    PciDoeTransportEncap, SharedBuffer, SECRET_ASYM_IMPL_INSTANCE,
};

#[allow(unused)]
use fuzzlib::flexi_logger;

use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn fuzz_send_receive_spdm_version(fuzzdata: Arc<Vec<u8>>) {
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle version response'
    // - description: '<p>Version can be negotiated.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();
        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        let _ = requester.send_receive_spdm_version().await.is_err();
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle version response'
    // - description: '<p>Version can not be negotiated.</p>'
    // -
    {
        let (mut req_config_info, req_provision_info) = req_create_info();
        for i in 0..MAX_SPDM_VERSION_COUNT {
            req_config_info.spdm_version[i] = Some(SpdmVersion::default());
        }

        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        let _ = requester.send_receive_spdm_version().await.is_err();
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

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::time::register(SPDM_TIME_IMPL.clone());

    #[cfg(not(feature = "fuzz"))]
    {
        flexi_logger::Logger::try_with_env()
            .unwrap()
            .start()
            .unwrap();
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = vec![17, 4, 0, 0, 0, 2, 0, 16, 0, 17];
            executor::block_on(fuzz_send_receive_spdm_version(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_send_receive_spdm_version(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_send_receive_spdm_version(Arc::new(data.to_vec())));
    });
}
