// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::error::SPDM_STATUS_INVALID_PARAMETER;
use spdmlib::message::VendorDefinedRspPayloadStruct;
use spdmlib::{
    error::SpdmResult, message::VendorDefinedReqPayloadStruct, requester::RequesterContext,
};

use crate::pci_tdisp::vendor_id;
use crate::pci_tdisp::STANDARD_ID;
use crate::pci_tdisp::TDISP_PROTOCOL_ID;

#[maybe_async::maybe_async]
pub async fn pci_tdisp_req_vdm_request(
    // IN
    spdm_requester: &mut RequesterContext,
    session_id: u32,
    vendor_defined_req_payload_struct: VendorDefinedReqPayloadStruct,
    // OUT
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    if vendor_defined_req_payload_struct.req_length < 1
        || vendor_defined_req_payload_struct.vendor_defined_req_payload[0] != TDISP_PROTOCOL_ID
    {
        Err(SPDM_STATUS_INVALID_PARAMETER)
    } else {
        spdm_requester
            .send_spdm_vendor_defined_request(
                Some(session_id),
                STANDARD_ID,
                vendor_id(),
                vendor_defined_req_payload_struct,
            )
            .await
    }
}
