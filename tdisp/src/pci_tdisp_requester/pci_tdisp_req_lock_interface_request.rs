// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;
use codec::Writer;
use spdmlib::error::SPDM_STATUS_BUFFER_FULL;
use spdmlib::error::SPDM_STATUS_ERROR_PEER;
use spdmlib::error::SPDM_STATUS_INVALID_MSG_FIELD;
use spdmlib::{
    error::SpdmResult,
    message::{VendorDefinedReqPayloadStruct, MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE},
    requester::RequesterContext,
};

use crate::pci_tdisp::vendor_id;
use crate::pci_tdisp::InterfaceId;
use crate::pci_tdisp::LockInterfaceFlag;
use crate::pci_tdisp::ReqLockInterfaceRequest;
use crate::pci_tdisp::RspLockInterfaceResponse;
use crate::pci_tdisp::RspTdispError;
use crate::pci_tdisp::TdispErrorCode;
use crate::pci_tdisp::TdispMessageHeader;
use crate::pci_tdisp::TdispRequestResponseCode;
use crate::pci_tdisp::STANDARD_ID;
use crate::pci_tdisp::START_INTERFACE_NONCE_LEN;
use crate::pci_tdisp_requester::TdispVersion;

#[allow(clippy::too_many_arguments)]
#[maybe_async::maybe_async]
pub async fn pci_tdisp_req_lock_interface_request(
    // IN
    spdm_requester: &mut RequesterContext,
    session_id: u32,
    interface_id: InterfaceId,
    flags: LockInterfaceFlag,
    default_stream_id: u8,
    mmio_reporting_offset: u64,
    bind_p2p_address_mask: u64,
    // OUT
    start_interface_nonce: &mut [u8; START_INTERFACE_NONCE_LEN],
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let mut vendor_defined_req_payload_struct = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let mut writer =
        Writer::init(&mut vendor_defined_req_payload_struct.vendor_defined_req_payload);

    vendor_defined_req_payload_struct.req_length = ReqLockInterfaceRequest {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::LOCK_INTERFACE_REQUEST,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
        flags,
        default_stream_id,
        mmio_reporting_offset,
        bind_p2p_address_mask,
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

    if let Ok(tdisp_error) = RspTdispError::read_bytes(
        &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
            [..vendor_defined_rsp_payload_struct.rsp_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)
    {
        *tdisp_error_code = Some(tdisp_error.error_code);
        return Err(SPDM_STATUS_ERROR_PEER);
    }

    let rsp_lock_interface_response = RspLockInterfaceResponse::read_bytes(
        &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
            [..vendor_defined_rsp_payload_struct.rsp_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    if rsp_lock_interface_response.message_header.tdisp_version
        != (TdispVersion {
            major_version: 1,
            minor_version: 0,
        })
        || rsp_lock_interface_response.message_header.message_type
            != TdispRequestResponseCode::LOCK_INTERFACE_RESPONSE
        || rsp_lock_interface_response.message_header.interface_id != interface_id
    {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    start_interface_nonce.copy_from_slice(&rsp_lock_interface_response.start_interface_nonce);

    Ok(())
}
