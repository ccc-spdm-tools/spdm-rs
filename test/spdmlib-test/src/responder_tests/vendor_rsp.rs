// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::Writer;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::SpdmCodec;
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::error::SpdmResult;
use spdmlib::message::*;
use spdmlib::message::{VendorDefinedReqPayloadStruct, MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE};
use spdmlib::protocol::*;
use spdmlib::responder::ResponderContext;
use spdmlib::secret;
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

// Session id seen by the last vendor_defined_func call, Some(None) for no session.
static LAST_SESSION_ID: Mutex<Option<Option<u32>>> = Mutex::new(None);

fn vendor_defined_func(
    _vdm_handle: usize,
    session_id: Option<u32>,
    _vendor_id_struct: &VendorIDStruct,
    _vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    *LAST_SESSION_ID.lock() = Some(session_id);
    let mut vendor_defined_res_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 0,
        vendor_defined_rsp_payload: [0; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };
    vendor_defined_res_payload_struct.rsp_length = 8;
    vendor_defined_res_payload_struct.vendor_defined_rsp_payload[0..8]
        .clone_from_slice(b"deadbeef");
    Ok(vendor_defined_res_payload_struct)
}

#[test]
fn test_case0_handle_spdm_vendor_defined_request() {
    let (rsp_config_info, rsp_provision_info) = create_info();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

    let mut responder = ResponderContext::new(
        device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    let req = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    register_vendor_defined_struct(VendorDefinedStruct {
        vendor_defined_request_handler: vendor_defined_func,
        vdm_handle: 0,
    });

    if let Ok(vendor_defined_res_payload_struct) = responder.respond_to_vendor_defined_request(
        &req,
        None,
        &VendorIDStruct::default(),
        vendor_defined_request_handler,
    ) {
        assert_eq!(vendor_defined_res_payload_struct.rsp_length, 8);
        assert_eq!(
            vendor_defined_res_payload_struct.vendor_defined_rsp_payload[0],
            b'd'
        );
    } else {
        panic!("Not expected result!");
    }
}

#[test]
fn test_case1_vendor_defined_request_reports_established_session_only() {
    let (rsp_config_info, rsp_provision_info) = create_info();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    let mut responder = ResponderContext::new(
        device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    register_vendor_defined_struct(VendorDefinedStruct {
        vendor_defined_request_handler: vendor_defined_func,
        vdm_handle: 0,
    });

    let session_id = 0xFFFE_FFFEu32;
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    responder.common.session[0].setup(session_id).unwrap();

    let mut request_buffer = [0u8; MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(&mut request_buffer);
    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
        },
        payload: SpdmMessagePayload::SpdmVendorDefinedRequest(SpdmVendorDefinedRequestPayload {
            standard_id: RegistryOrStandardsBodyID::PCISIG,
            vendor_id: VendorIDStruct::default(),
            req_payload: VendorDefinedReqPayloadStruct {
                req_length: 2,
                vendor_defined_req_payload: [0; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
            },
        }),
    };
    let used = request
        .spdm_encode(&mut responder.common, &mut writer)
        .unwrap();
    let request = &request_buffer[..used];

    fn handle(
        responder: &mut ResponderContext,
        session: Option<u32>,
        request: &[u8],
    ) -> Option<Option<u32>> {
        *LAST_SESSION_ID.lock() = None;
        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, _) =
            responder.handle_spdm_vendor_defined_request(session, request, &mut writer);
        assert!(status.is_ok());
        LAST_SESSION_ID.lock().take()
    }

    // Outside any session.
    assert_eq!(handle(&mut responder, None, request), Some(None));

    // During the session handshake, before FINISH / PSK_FINISH.
    responder.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
    assert_eq!(
        handle(&mut responder, Some(session_id), request),
        Some(None)
    );

    // Established session.
    responder.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
    assert_eq!(
        handle(&mut responder, Some(session_id), request),
        Some(Some(session_id))
    );
}
