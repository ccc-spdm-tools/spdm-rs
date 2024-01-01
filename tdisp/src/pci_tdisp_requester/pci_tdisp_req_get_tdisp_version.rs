// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;
use codec::Writer;
use spdmlib::error::SPDM_STATUS_BUFFER_FULL;
use spdmlib::error::SPDM_STATUS_INVALID_MSG_FIELD;
use spdmlib::{
    error::SpdmResult,
    message::{VendorDefinedReqPayloadStruct, MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE},
    requester::RequesterContext,
};

use crate::pci_tdisp::vendor_id;
use crate::pci_tdisp::RspTdispVersion;
use crate::pci_tdisp::STANDARD_ID;
use crate::pci_tdisp::{ReqGetTdispVersion, TdispVersion};
use crate::pci_tdisp_requester::InterfaceId;

#[maybe_async::maybe_async]
pub async fn pci_tdisp_req_get_tdisp_version(
    // IN
    spdm_requester: &mut RequesterContext,
    session_id: u32,
    interface_id: InterfaceId,
) -> SpdmResult {
    let mut vendor_defined_req_payload_struct = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let mut writer =
        Writer::init(&mut vendor_defined_req_payload_struct.vendor_defined_req_payload);

    vendor_defined_req_payload_struct.req_length = ReqGetTdispVersion { interface_id }
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?
        as u16;

    let vendor_defined_rsp_payload_struct = spdm_requester
        .send_spdm_vendor_defined_request(
            Some(session_id),
            STANDARD_ID,
            vendor_id(),
            vendor_defined_req_payload_struct,
        )
        .await?;

    let rsp_tdisp_version = RspTdispVersion::read_bytes(
        &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
            [..vendor_defined_rsp_payload_struct.rsp_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    if rsp_tdisp_version.interface_id != interface_id {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    if rsp_tdisp_version.version_num_count == 1
        && rsp_tdisp_version.version_num_entry[0]
            == (TdispVersion {
                major_version: 1,
                minor_version: 0,
            })
    {
        Ok(())
    } else {
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    }
}
