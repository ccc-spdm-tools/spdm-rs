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
use crate::pci_tdisp::ReqGetDeviceInterfaceReport;
use crate::pci_tdisp::RspDeviceInterfaceReport;
use crate::pci_tdisp::RspTdispError;
use crate::pci_tdisp::TdispErrorCode;
use crate::pci_tdisp::TdispMessageHeader;
use crate::pci_tdisp::TdispRequestResponseCode;
use crate::pci_tdisp::MAX_DEVICE_REPORT_BUFFER;
use crate::pci_tdisp::MAX_PORTION_LENGTH;
use crate::pci_tdisp::STANDARD_ID;
use crate::pci_tdisp_requester::TdispVersion;

#[maybe_async::maybe_async]
pub async fn pci_tdisp_req_get_device_interface_report(
    // IN
    spdm_requester: &mut RequesterContext,
    session_id: u32,
    interface_id: InterfaceId,
    // OUT
    report: &mut [u8; MAX_DEVICE_REPORT_BUFFER],
    report_size: &mut usize,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let mut offset = 0u16;
    let length = MAX_PORTION_LENGTH as u16;
    let mut report_buffer_walker = 0usize;
    *report_size = 0;

    loop {
        let mut vendor_defined_req_payload_struct = VendorDefinedReqPayloadStruct {
            req_length: 0,
            vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
        };

        let mut writer =
            Writer::init(&mut vendor_defined_req_payload_struct.vendor_defined_req_payload);

        vendor_defined_req_payload_struct.req_length = ReqGetDeviceInterfaceReport {
            message_header: TdispMessageHeader {
                interface_id,
                message_type: TdispRequestResponseCode::GET_DEVICE_INTERFACE_REPORT,
                tdisp_version: TdispVersion {
                    major_version: 1,
                    minor_version: 0,
                },
            },
            offset,
            length,
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

        let rsp_device_interface_report = RspDeviceInterfaceReport::read_bytes(
            &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
                [..vendor_defined_rsp_payload_struct.rsp_length as usize],
        )
        .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

        if rsp_device_interface_report.message_header.tdisp_version
            != (TdispVersion {
                major_version: 1,
                minor_version: 0,
            })
            || rsp_device_interface_report.message_header.message_type
                != TdispRequestResponseCode::DEVICE_INTERFACE_REPORT
            || rsp_device_interface_report.message_header.interface_id != interface_id
        {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        if report_buffer_walker
            + rsp_device_interface_report.portion_length as usize
            + rsp_device_interface_report.remainder_length as usize
            > MAX_DEVICE_REPORT_BUFFER
        {
            return Err(SPDM_STATUS_BUFFER_FULL);
        }

        report[report_buffer_walker
            ..report_buffer_walker + rsp_device_interface_report.portion_length as usize]
            .copy_from_slice(
                &rsp_device_interface_report.report
                    [..rsp_device_interface_report.portion_length as usize],
            );
        report_buffer_walker += rsp_device_interface_report.portion_length as usize;

        if rsp_device_interface_report.remainder_length != 0 {
            offset += rsp_device_interface_report.portion_length;
            continue;
        } else {
            *report_size = report_buffer_walker;
            break;
        }
    }

    Ok(())
}
