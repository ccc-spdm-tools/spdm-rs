// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Writer};
use conquer_once::spin::OnceCell;
use spdmlib::{
    error::{
        SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_MSG_FIELD,
        SPDM_STATUS_INVALID_STATE_LOCAL,
    },
    message::{
        VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct,
        MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE,
    },
};

use crate::pci_tdisp::{
    InterfaceId, ReqGetDeviceInterfaceReport, RspDeviceInterfaceReport, TdispErrorCode,
    TdispMessageHeader, TdispRequestResponseCode, TdispVersion, MAX_DEVICE_REPORT_BUFFER,
    MAX_PORTION_LENGTH,
};

use super::pci_tdisp_rsp_tdisp_error::write_error;

static PCI_TDISP_DEVICE_INTERFACE_REPORT_INSTANCE: OnceCell<PciTdispDeviceInterfaceReport> =
    OnceCell::uninit();

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct PciTdispDeviceInterfaceReport {
    pub pci_tdisp_device_interface_report_cb: fn(
        // IN
        vdm_handle: usize,
        // OUT
        interface_id: &mut InterfaceId,
        tdi_report: &mut [u8; MAX_DEVICE_REPORT_BUFFER],
        tdi_report_size: &mut usize,
        tdisp_error_code: &mut Option<TdispErrorCode>,
    ) -> SpdmResult,
}

pub fn register(context: PciTdispDeviceInterfaceReport) -> bool {
    PCI_TDISP_DEVICE_INTERFACE_REPORT_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceInterfaceReport = PciTdispDeviceInterfaceReport {
    pci_tdisp_device_interface_report_cb: |_: usize,
                                           _: &mut InterfaceId,
                                           _: &mut [u8; MAX_DEVICE_REPORT_BUFFER],
                                           _: &mut usize,
                                           _: &mut Option<TdispErrorCode>|
     -> SpdmResult { unimplemented!() },
};

pub(crate) fn pci_tdisp_device_interface_report(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
    tdi_report: &mut [u8; MAX_DEVICE_REPORT_BUFFER],
    tdi_report_size: &mut usize,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    (PCI_TDISP_DEVICE_INTERFACE_REPORT_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_interface_report_cb)(
        vdm_handle,
        interface_id,
        tdi_report,
        tdi_report_size,
        tdisp_error_code,
    )
}

pub(crate) fn pci_tdisp_rsp_interface_report(
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let req_get_device_interface_report = ReqGetDeviceInterfaceReport::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut interface_id = InterfaceId::default();
    let mut tdi_report = [0u8; MAX_DEVICE_REPORT_BUFFER];
    let mut tdi_report_size = 0usize;
    let mut tdisp_error_code_code = None;

    // device need to check tdi state
    pci_tdisp_device_interface_report(
        vdm_handle,
        &mut interface_id,
        &mut tdi_report,
        &mut tdi_report_size,
        &mut tdisp_error_code_code,
    )?;

    let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 0,
        vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    if let Some(tdisp_error_code_code) = tdisp_error_code_code {
        let len = write_error(
            vdm_handle,
            tdisp_error_code_code,
            0,
            &[],
            &mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload,
        )?;
        vendor_defined_rsp_payload_struct.rsp_length = len as u16;
        return Ok(vendor_defined_rsp_payload_struct);
    }

    let portion_length = if req_get_device_interface_report.length as usize > MAX_PORTION_LENGTH {
        MAX_PORTION_LENGTH as u16
    } else {
        req_get_device_interface_report.length
    };

    let portion_length = if req_get_device_interface_report.offset as usize
        + portion_length as usize
        > tdi_report_size
    {
        let remainder = (tdi_report_size - req_get_device_interface_report.offset as usize) as u16;
        if remainder > portion_length {
            portion_length
        } else {
            remainder
        }
    } else {
        portion_length
    };

    let remainder_length = if tdi_report_size
        > req_get_device_interface_report.offset as usize + portion_length as usize
    {
        (tdi_report_size
            - req_get_device_interface_report.offset as usize
            - portion_length as usize) as u16
    } else {
        0
    };

    let mut writer =
        Writer::init(&mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload);

    let mut report = [0u8; MAX_PORTION_LENGTH];
    report[..portion_length as usize].copy_from_slice(
        &tdi_report[req_get_device_interface_report.offset as usize
            ..req_get_device_interface_report.offset as usize + portion_length as usize],
    );

    let cnt = RspDeviceInterfaceReport {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::DEVICE_INTERFACE_REPORT,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
        portion_length,
        remainder_length,
        report,
    }
    .encode(&mut writer)
    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    if cnt > u16::MAX as usize {
        Err(SPDM_STATUS_INVALID_STATE_LOCAL)
    } else {
        vendor_defined_rsp_payload_struct.rsp_length = cnt as u16;
        Ok(vendor_defined_rsp_payload_struct)
    }
}
