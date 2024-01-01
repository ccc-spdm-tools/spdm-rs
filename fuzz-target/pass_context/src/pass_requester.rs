// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::*;
use spdmlib::protocol::SpdmMeasurementSummaryHashType;
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

pub async fn fuzz_total_requesters() {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder: Arc<Mutex<(dyn fuzzlib::SpdmDeviceIo + Send + Sync + 'static)>> =
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

    let pcidoe_transport_encap: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let responder = responder::ResponderContext::new(
        device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    let shared_buffer = SharedBuffer::new();
    let pcidoe_transport_encap2: Arc<
        Mutex<(dyn fuzzlib::SpdmTransportEncap + Send + Sync + 'static)>,
    > = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let device_io_requester = Arc::new(Mutex::new(fake_device_io::FakeSpdmDeviceIo::new(
        Arc::new(shared_buffer),
    )));

    let mut requester = requester::RequesterContext::new(
        device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    let mut transcript_vca = None;
    if requester
        .init_connection(&mut transcript_vca)
        .await
        .is_err()
    {
        return;
    }

    if requester.send_receive_spdm_digest(None).await.is_err() {
        return;
    }

    if requester
        .send_receive_spdm_certificate(None, 0)
        .await
        .is_err()
    {
        return;
    }

    let result = requester
        .start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .await;
    if let Ok(session_id) = result {
        log::info!(
            "\nSession established ... session_id is {:0x?}\n",
            session_id
        );
        log::info!("Key Information ...\n");

        let session = requester.common.get_session_via_id(session_id).unwrap();
        let (request_direction, response_direction) = session.export_keys();
        log::info!(
            "equest_direction.encryption_key {:0x?}\n",
            request_direction.encryption_key.as_ref()
        );
        log::info!(
            "equest_direction.salt {:0x?}\n",
            request_direction.salt.as_ref()
        );
        log::info!(
            "esponse_direction.encryption_key {:0x?}\n",
            response_direction.encryption_key.as_ref()
        );
        log::info!(
            "esponse_direction.salt {:0x?}\n",
            response_direction.salt.as_ref()
        );
    } else {
        log::info!("\nSession session_id not got ????? \n");
    }
}
