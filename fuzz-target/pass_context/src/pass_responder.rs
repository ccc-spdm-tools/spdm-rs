// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::*;
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

pub async fn pass_rsp_handle_spdm_version() {
    let (config_info, provision_info) = rsp_create_info();

    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    context
        .handle_spdm_version(&[00, 00, 00, 00])
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}

pub async fn pass_rsp_handle_spdm_capability() {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    // context.handle_spdm_capability(&[0x10, 0x84, 00,00, 0x11, 0xE1, 00, 00, 00, 00, 00, 00, 00,00,00,0x0C]);
    context
        .handle_spdm_capability(&[17, 225, 0, 0, 0, 0, 0, 0, 198, 118, 0, 0])
        .await
        .unwrap();
    let mut req_buf = [0u8; 512];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}

pub async fn pass_rsp_handle_spdm_algorithm() {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    context
        .handle_spdm_algorithm(&[
            17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
        ])
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}

pub async fn pass_rsp_handle_spdm_digest() {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    context
        .handle_spdm_algorithm(&[
            17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
        ])
        .await
        .unwrap();

    context
        .handle_spdm_digest(&[17, 129, 0, 0], None)
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}

pub async fn pass_rsp_handle_spdm_certificate() {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context
        .handle_spdm_algorithm(&[
            17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_digest(&[17, 129, 0, 0], None)
        .await
        .unwrap();
    context
        .handle_spdm_certificate(&[17, 130, 0, 0, 0, 0, 0, 2], None)
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}

pub async fn pass_rsp_handle_spdm_challenge() {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context
        .handle_spdm_algorithm(&[
            17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_digest(&[17, 129, 0, 0], None)
        .await
        .unwrap();
    context
        .handle_spdm_certificate(&[17, 130, 0, 0, 0, 0, 0, 2], None)
        .await
        .unwrap();
    context
        .handle_spdm_challenge(&[
            17, 131, 0, 0, 96, 98, 50, 80, 166, 189, 68, 2, 27, 142, 255, 200, 180, 230, 76, 45,
            12, 178, 253, 70, 242, 202, 83, 171, 115, 148, 32, 249, 52, 170, 141, 122,
        ])
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}

pub async fn pass_rsp_handle_spdm_measurement() {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context
        .handle_spdm_algorithm(&[
            17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_digest(&[17, 129, 0, 0], None)
        .await
        .unwrap();
    context
        .handle_spdm_certificate(&[17, 130, 0, 0, 0, 0, 0, 2], None)
        .await
        .unwrap();
    context
        .handle_spdm_challenge(&[
            17, 131, 0, 0, 96, 98, 50, 80, 166, 189, 68, 2, 27, 142, 255, 200, 180, 230, 76, 45,
            12, 178, 253, 70, 242, 202, 83, 171, 115, 148, 32, 249, 52, 170, 141, 122,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_measurement(None, &[17, 224, 0, 0])
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}

pub async fn pass_rsp_handle_spdm_key_exchange() {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    context
        .handle_spdm_algorithm(&[
            17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_digest(&[17, 129, 0, 0], None)
        .await
        .unwrap();
    context
        .handle_spdm_certificate(&[17, 130, 0, 0, 0, 0, 0, 2], None)
        .await
        .unwrap();
    context
        .handle_spdm_challenge(&[
            17, 131, 0, 0, 96, 98, 50, 80, 166, 189, 68, 2, 27, 142, 255, 200, 180, 230, 76, 45,
            12, 178, 253, 70, 242, 202, 83, 171, 115, 148, 32, 249, 52, 170, 141, 122,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_measurement(None, &[17, 224, 0, 0])
        .await
        .unwrap();
    context
        .handle_spdm_key_exchange(&[
            17, 228, 0, 0, 254, 255, 0, 0, 227, 11, 91, 150, 99, 148, 85, 82, 35, 135, 88, 241,
            249, 244, 105, 233, 225, 89, 237, 166, 13, 142, 13, 115, 102, 29, 108, 90, 113, 211,
            174, 92, 16, 14, 136, 6, 200, 113, 5, 174, 212, 211, 70, 68, 204, 188, 78, 228, 190,
            118, 132, 77, 185, 118, 93, 140, 122, 16, 249, 41, 82, 143, 79, 77, 248, 113, 230, 73,
            72, 135, 132, 15, 32, 138, 130, 163, 95, 80, 59, 109, 65, 92, 6, 36, 29, 182, 124, 73,
            92, 173, 125, 81, 95, 136, 251, 177, 48, 95, 136, 77, 252, 72, 31, 208, 25, 145, 113,
            245, 11, 229, 125, 252, 154, 63, 97, 36, 64, 150, 86, 131, 90, 36, 64, 150, 86, 131,
            90, 36, 93, 181, 85, 154, 164, 34, 20, 0, 70, 84, 77, 68, 1, 1, 0, 0, 0, 0, 5, 0, 1, 1,
            1, 0, 17, 0, 0, 0, 0, 0,
        ])
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}

pub async fn pass_rsp_handle_spdm_psk_exchange() {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let socket_io_transport: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let mut context = responder::ResponderContext::new(
        socket_io_transport.clone(),
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context
        .handle_spdm_algorithm(&[
            17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_digest(&[17, 129, 0, 0], None)
        .await
        .unwrap();
    context
        .handle_spdm_certificate(&[17, 130, 0, 0, 0, 0, 0, 2], None)
        .await
        .unwrap();
    context
        .handle_spdm_challenge(&[
            17, 131, 0, 0, 96, 98, 50, 80, 166, 189, 68, 2, 27, 142, 255, 200, 180, 230, 76, 45,
            12, 178, 253, 70, 242, 202, 83, 171, 115, 148, 32, 249, 52, 170, 141, 122,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_measurement(None, &[17, 224, 0, 0])
        .await
        .unwrap();
    context
        .handle_spdm_key_exchange(&[
            17, 228, 0, 0, 254, 255, 0, 0, 227, 11, 91, 150, 99, 148, 85, 82, 35, 135, 88, 241,
            249, 244, 105, 233, 225, 89, 237, 166, 13, 142, 13, 115, 102, 29, 108, 90, 113, 211,
            174, 92, 16, 14, 136, 6, 200, 113, 5, 174, 212, 211, 70, 68, 204, 188, 78, 228, 190,
            118, 132, 77, 185, 118, 93, 140, 122, 16, 249, 41, 82, 143, 79, 77, 248, 113, 230, 73,
            72, 135, 132, 15, 32, 138, 130, 163, 95, 80, 59, 109, 65, 92, 6, 36, 29, 182, 124, 73,
            92, 173, 125, 81, 95, 136, 251, 177, 48, 95, 136, 77, 252, 72, 31, 208, 25, 145, 113,
            245, 11, 229, 125, 252, 154, 63, 97, 36, 64, 150, 86, 131, 90, 36, 64, 150, 86, 131,
            90, 36, 93, 181, 85, 154, 164, 34, 20, 0, 70, 84, 77, 68, 1, 1, 0, 0, 0, 0, 5, 0, 1, 1,
            1, 0, 17, 0, 0, 0, 0, 0,
        ])
        .await
        .unwrap();
    context
        .handle_spdm_psk_exchange(&[
            17, 230, 0, 0, 253, 255, 0, 0, 48, 0, 20, 0, 61, 242, 81, 71, 115, 174, 43, 116, 19,
            203, 159, 205, 247, 38, 95, 20, 209, 170, 249, 97, 98, 89, 160, 168, 4, 8, 69, 184, 51,
            15, 78, 178, 208, 229, 109, 184, 239, 207, 44, 98, 13, 141, 223, 116, 114, 42, 39, 215,
            70, 84, 77, 68, 1, 10, 0, 0, 0, 5, 0, 1, 1, 1, 0, 17, 0, 0, 0,
        ])
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let mut socket_io_transport = socket_io_transport.lock();
    let socket_io_transport = socket_io_transport.deref_mut();
    socket_io_transport
        .receive(Arc::new(Mutex::new(&mut req_buf)), 60)
        .await
        .unwrap();
    println!("Received: {:?}", req_buf);
}
