// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::*;
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn fuzz_handle_spdm_version(data: Arc<Vec<u8>>) {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    let mut response_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
    let mut writer = codec::Writer::init(&mut response_buffer);
    let _ = context.handle_spdm_version(&data, &mut writer);

    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
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
            let fuzzdata = vec![17, 46, 43, 0];
            executor::block_on(fuzz_handle_spdm_version(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_handle_spdm_version(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_handle_spdm_version(Arc::new(data.to_vec())));
    });
}
