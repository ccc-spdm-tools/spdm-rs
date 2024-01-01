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
use crate::pci_tdisp::InterfaceId;
use crate::pci_tdisp::LockInterfaceFlag;
use crate::pci_tdisp::ReqGetTdispCapabilities;
use crate::pci_tdisp::RspTdispCapabilities;
use crate::pci_tdisp::TdispMessageHeader;
use crate::pci_tdisp::TdispRequestResponseCode;
use crate::pci_tdisp::TdispVersion;
use crate::pci_tdisp::STANDARD_ID;

#[maybe_async::maybe_async]
#[allow(clippy::too_many_arguments)]
pub async fn pci_tdisp_req_get_tdisp_capabilities(
    // IN
    spdm_requester: &mut RequesterContext,
    session_id: u32,
    tsm_caps: u32,
    interface_id: InterfaceId,
    // OUT
    dsm_caps: &mut u32,
    lock_interface_flags_supported: &mut LockInterfaceFlag,
    dev_addr_width: &mut u8,
    num_req_this: &mut u8,
    num_req_all: &mut u8,
    req_msgs_supported: &mut [u8; 16],
) -> SpdmResult {
    let mut vendor_defined_req_payload_struct = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let mut writer =
        Writer::init(&mut vendor_defined_req_payload_struct.vendor_defined_req_payload);

    vendor_defined_req_payload_struct.req_length = ReqGetTdispCapabilities {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::GET_TDISP_CAPABILITIES,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
        tsm_caps,
    }
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

    let rsp_tdisp_capabilities = RspTdispCapabilities::read_bytes(
        &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
            [..vendor_defined_rsp_payload_struct.rsp_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    if rsp_tdisp_capabilities.message_header.tdisp_version
        != (TdispVersion {
            major_version: 1,
            minor_version: 0,
        })
        || rsp_tdisp_capabilities.message_header.message_type
            != TdispRequestResponseCode::TDISP_CAPABILITIES
        || rsp_tdisp_capabilities.message_header.interface_id != interface_id
    {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    *dsm_caps = rsp_tdisp_capabilities.dsm_caps;
    req_msgs_supported.copy_from_slice(&rsp_tdisp_capabilities.req_msgs_supported);
    *lock_interface_flags_supported = rsp_tdisp_capabilities.lock_interface_flags_supported;
    *lock_interface_flags_supported = rsp_tdisp_capabilities.lock_interface_flags_supported;
    *dev_addr_width = rsp_tdisp_capabilities.dev_addr_width;
    *num_req_this = rsp_tdisp_capabilities.num_req_this;
    *num_req_all = rsp_tdisp_capabilities.num_req_all;

    Ok(())
}
