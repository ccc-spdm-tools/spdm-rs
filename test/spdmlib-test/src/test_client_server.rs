// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{get_rsp_cert_chain_buff, req_create_info, rsp_create_info};
use crate::watchdog_impl_sample::init_watchdog;
use spdmlib::protocol::{
    SpdmMeasurementSummaryHashType, SpdmReqAsymAlgo, SpdmRequestCapabilityFlags,
    SpdmResponseCapabilityFlags,
};
use spdmlib::requester;
use spdmlib::responder;
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn intergration_client_server() {
    let future = async {
        spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        init_watchdog();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let transport_encap_responder = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        let (config_info, provision_info) = rsp_create_info();
        let mut responder_context = responder::ResponderContext::new(
            device_io_responder,
            transport_encap_responder,
            config_info,
            provision_info,
        );

        #[cfg(feature = "mut-auth")]
        {
            responder_context.common.negotiate_info.rsp_capabilities_sel |=
                SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
            responder_context.common.negotiate_info.req_capabilities_sel |=
                SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
        }

        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder_context)),
        )));
        let transport_encap_requester = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        let (config_info, provision_info) = req_create_info();
        let mut requester_context = requester::RequesterContext::new(
            device_io_requester,
            transport_encap_requester,
            config_info,
            provision_info,
        );

        let mut transcript_vca = None;
        assert!(!requester_context
            .init_connection(&mut transcript_vca)
            .await
            .is_err());

        assert!(!requester_context
            .send_receive_spdm_digest(None)
            .await
            .is_err());

        assert!(!requester_context
            .send_receive_spdm_certificate(None, 0)
            .await
            .is_err());

        #[cfg(feature = "mut-auth")]
        {
            requester_context.common.negotiate_info.rsp_capabilities_sel |=
                SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
            requester_context.common.negotiate_info.req_capabilities_sel |=
                SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
            requester_context.common.negotiate_info.req_asym_sel =
                SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
            requester_context.common.provision_info.my_cert_chain = [
                Some(get_rsp_cert_chain_buff()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ];
        }

        let result = requester_context
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await;
        assert!(result.is_ok());
        if let Ok(session_id) = result {
            log::info!(
                "\nSession established ... session_id is {:0x?}\n",
                session_id
            );
            log::info!("Key Information ...\n");

            let session = requester_context
                .common
                .get_session_via_id(session_id)
                .expect("get session failed!");
            let (request_direction, response_direction) = session.export_keys();
            log::info!(
                "request_direction.encryption_key {:0x?}\n",
                request_direction.encryption_key.as_ref()
            );
            log::info!(
                "request_direction.salt {:0x?}\n",
                request_direction.salt.as_ref()
            );
            log::info!(
                "response_direction.encryption_key {:0x?}\n",
                response_direction.encryption_key.as_ref()
            );
            log::info!(
                "response_direction.salt {:0x?}\n",
                response_direction.salt.as_ref()
            );
        } else {
            log::info!("\nSession session_id not got ????? \n");
        }
    };
    executor::block_on(future);
}
