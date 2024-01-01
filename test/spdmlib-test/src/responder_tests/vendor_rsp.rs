// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::error::SpdmResult;
use spdmlib::message::VendorDefinedReqPayloadStruct;
use spdmlib::message::*;
use spdmlib::responder::ResponderContext;
use spdmlib::{config, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_handle_spdm_vendor_defined_request() {
    let (rsp_config_info, rsp_provision_info) = create_info();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let mut responder = ResponderContext::new(
        device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    let req = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0; config::MAX_SPDM_MSG_SIZE - 7 - 2],
    };

    let vendor_defined_func: for<'r> fn(
        usize,
        &VendorIDStruct,
        &'r vendor::VendorDefinedReqPayloadStruct,
    ) -> Result<_, _> = |_: usize,
                         _: &VendorIDStruct,
                         _vendor_defined_req_payload_struct|
     -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut vendor_defined_res_payload_struct = VendorDefinedRspPayloadStruct {
            rsp_length: 0,
            vendor_defined_rsp_payload: [0; config::MAX_SPDM_MSG_SIZE - 7 - 2],
        };
        vendor_defined_res_payload_struct.rsp_length = 8;
        vendor_defined_res_payload_struct.vendor_defined_rsp_payload[0..8]
            .clone_from_slice(b"deadbeef");
        Ok(vendor_defined_res_payload_struct)
    };

    register_vendor_defined_struct(VendorDefinedStruct {
        vendor_defined_request_handler: vendor_defined_func,
        vdm_handle: 0,
    });

    if let Ok(vendor_defined_res_payload_struct) = responder.respond_to_vendor_defined_request(
        &req,
        &VendorIDStruct::default(),
        vendor_defined_request_handler,
    ) {
        assert_eq!(vendor_defined_res_payload_struct.rsp_length, 8);
        assert_eq!(
            vendor_defined_res_payload_struct.vendor_defined_rsp_payload[0],
            b'd'
        );
    } else {
        assert!(false, "Not expected result!");
    }
}
