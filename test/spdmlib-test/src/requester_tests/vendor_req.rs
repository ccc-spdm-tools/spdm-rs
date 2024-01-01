// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::message::{
    RegistryOrStandardsBodyID, VendorDefinedReqPayloadStruct, VendorIDStruct,
    MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN,
};
use spdmlib::requester::RequesterContext;
use spdmlib::responder::ResponderContext;
use spdmlib::{config, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_send_spdm_vendor_defined_request() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let responder = ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

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

        let session_id: u32 = 0xff;
        let standard_id: RegistryOrStandardsBodyID = RegistryOrStandardsBodyID::DMTF;
        let vendor_idstruct: VendorIDStruct = VendorIDStruct {
            len: 0,
            vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
        };
        let req_payload_struct: VendorDefinedReqPayloadStruct = VendorDefinedReqPayloadStruct {
            req_length: 0,
            vendor_defined_req_payload: [0u8; config::MAX_SPDM_MSG_SIZE - 7 - 2],
        };

        let status = requester
            .send_spdm_vendor_defined_request(
                Some(session_id),
                standard_id,
                vendor_idstruct,
                req_payload_struct,
            )
            .await
            .is_ok();
        assert_eq!(status, false); //since vendor defined response payload is not implemented, so false is expected here.
    };
    executor::block_on(future);
}
