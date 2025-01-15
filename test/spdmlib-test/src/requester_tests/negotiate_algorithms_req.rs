// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::SpdmConnectionState;
use spdmlib::protocol::{
    SpdmAlgoOtherParams, SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion,
};
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_send_receive_spdm_algorithm() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);

        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        let status = requester.send_receive_spdm_algorithm().await.is_ok();
        assert!(status);
    };
    executor::block_on(future);
}

#[test]
fn test_case1_send_receive_spdm_algorithm() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;
        responder
            .common
            .negotiate_info
            .rsp_capabilities_sel
            .insert(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY);

        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;
        requester
            .common
            .negotiate_info
            .rsp_capabilities_sel
            .insert(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY);

        let status = requester.send_receive_spdm_algorithm().await.is_ok();
        assert!(status);
        assert_eq!(requester.common.negotiate_info.multi_key_conn_req, true);
        assert_eq!(requester.common.negotiate_info.multi_key_conn_rsp, true);
    };
    executor::block_on(future);
}

#[test]
fn test_case2_send_receive_spdm_algorithm() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;
        responder
            .common
            .negotiate_info
            .rsp_capabilities_sel
            .insert(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_CONN_SEL);
        responder
            .common
            .config_info
            .other_params_support
            .remove(SpdmAlgoOtherParams::MULTI_KEY_CONN);
        responder
            .common
            .config_info
            .rsp_capabilities
            .remove(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY);
        responder
            .common
            .config_info
            .rsp_capabilities
            .insert(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_CONN_SEL);

        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;
        requester
            .common
            .negotiate_info
            .rsp_capabilities_sel
            .insert(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_CONN_SEL);
        requester
            .common
            .config_info
            .other_params_support
            .remove(SpdmAlgoOtherParams::MULTI_KEY_CONN);
        requester
            .common
            .config_info
            .req_capabilities
            .remove(SpdmRequestCapabilityFlags::MULTI_KEY_CAP_ONLY);
        requester
            .common
            .config_info
            .req_capabilities
            .insert(SpdmRequestCapabilityFlags::MULTI_KEY_CAP_CONN_SEL);

        let status = requester.send_receive_spdm_algorithm().await.is_ok();
        assert!(status);
        assert_eq!(requester.common.negotiate_info.multi_key_conn_req, false);
        assert_eq!(requester.common.negotiate_info.multi_key_conn_rsp, false);
    };
    executor::block_on(future);
}
