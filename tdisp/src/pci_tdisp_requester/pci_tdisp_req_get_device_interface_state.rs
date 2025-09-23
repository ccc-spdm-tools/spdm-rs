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
use crate::pci_tdisp::ReqGetDeviceInterfaceState;
use crate::pci_tdisp::RspDeviceInterfaceState;
use crate::pci_tdisp::TdiState;
use crate::pci_tdisp::TdispMessageHeader;
use crate::pci_tdisp::TdispRequestResponseCode;
use crate::pci_tdisp::TdispVersion;
use crate::pci_tdisp::STANDARD_ID;

#[maybe_async::maybe_async]
pub async fn pci_tdisp_req_get_device_interface_state(
    // IN
    spdm_requester: &mut RequesterContext,
    session_id: u32,
    interface_id: InterfaceId,
    // OUT
    tdi_state: &mut TdiState,
) -> SpdmResult {
    let mut vendor_defined_req_payload_struct = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let mut writer =
        Writer::init(&mut vendor_defined_req_payload_struct.vendor_defined_req_payload);

    vendor_defined_req_payload_struct.req_length = ReqGetDeviceInterfaceState {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::GET_DEVICE_INTERFACE_STATE,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
    }
    .encode(&mut writer)
    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?
        as u32;

    let vendor_defined_rsp_payload_struct = spdm_requester
        .send_spdm_vendor_defined_request(
            Some(session_id),
            STANDARD_ID,
            vendor_id(),
            vendor_defined_req_payload_struct,
        )
        .await?;

    let rsp_device_interface_state = RspDeviceInterfaceState::read_bytes(
        &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
            [..vendor_defined_rsp_payload_struct.rsp_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    if rsp_device_interface_state.message_header.tdisp_version
        != (TdispVersion {
            major_version: 1,
            minor_version: 0,
        })
        || rsp_device_interface_state.message_header.message_type
            != TdispRequestResponseCode::DEVICE_INTERFACE_STATE
        || rsp_device_interface_state.message_header.interface_id != interface_id
    {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    *tdi_state = rsp_device_interface_state.tdi_state;

    Ok(())
}
