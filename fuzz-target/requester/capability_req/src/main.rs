// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::{spdmlib::protocol::SpdmVersion, *};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

async fn fuzz_send_receive_spdm_capability(fuzzdata: Arc<Vec<u8>>) {
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

    let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
    device_io_requester.set_rx(&fuzzdata);
    let device_io_requester = Arc::new(Mutex::new(device_io_requester));

    let mut requester = requester::RequesterContext::new(
        device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );
    requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    let _ = requester.send_receive_spdm_capability().await;
}

#[cfg(not(feature = "use_libfuzzer"))]
fn main() {
    #[cfg(all(feature = "fuzzlogfile", feature = "fuzz"))]
    fuzzlib::init_file_logger();

    #[cfg(not(feature = "fuzz"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = vec![17, 224, 0, 0];
            executor::block_on(fuzz_send_receive_spdm_capability(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_send_receive_spdm_capability(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_send_receive_spdm_capability(Arc::new(data.to_vec())));
    });
}
