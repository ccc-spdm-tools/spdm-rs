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
use crate::pci_tdisp::RspBindP2PStreamResponse;
use crate::pci_tdisp::RspTdispError;
use crate::pci_tdisp::TdispVersion;
use crate::pci_tdisp::STANDARD_ID;
use crate::pci_tdisp::{
    InterfaceId, ReqBindP2PStreamRequest, TdispErrorCode, TdispMessageHeader,
    TdispRequestResponseCode,
};

#[maybe_async::maybe_async]
pub async fn pci_tdisp_req_bind_p2p_stream_request(
    // IN
    spdm_requester: &mut RequesterContext,
    session_id: u32,
    interface_id: InterfaceId,
    p2p_stream_id: u8,
    // OUT
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let mut vendor_defined_req_payload_struct = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let mut writer =
        Writer::init(&mut vendor_defined_req_payload_struct.vendor_defined_req_payload);

    vendor_defined_req_payload_struct.req_length = ReqBindP2PStreamRequest {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::BIND_P2P_STREAM_REQUEST,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
        p2p_stream_id,
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

    let rsp_bind_p2_pstream_response = RspBindP2PStreamResponse::read_bytes(
        &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
            [..vendor_defined_rsp_payload_struct.rsp_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    if rsp_bind_p2_pstream_response.message_header.tdisp_version
        != (TdispVersion {
            major_version: 1,
            minor_version: 0,
        })
        || rsp_bind_p2_pstream_response.message_header.message_type
            != TdispRequestResponseCode::BIND_P2P_STREAM_RESPONSE
        || rsp_bind_p2_pstream_response.message_header.interface_id != interface_id
    {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    Ok(())
}
