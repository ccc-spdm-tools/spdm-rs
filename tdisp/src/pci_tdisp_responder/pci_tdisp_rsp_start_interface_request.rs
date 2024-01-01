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
    InterfaceId, ReqStartInterfaceRequest, RspStartInterfaceResponse, TdispErrorCode,
    TdispMessageHeader, TdispRequestResponseCode, TdispVersion, START_INTERFACE_NONCE_LEN,
};

use super::pci_tdisp_rsp_tdisp_error::write_error;

static PCI_TDISP_DEVICE_START_INTERFACE_INSTANCE: OnceCell<PciTdispDeviceStartInterface> =
    OnceCell::uninit();

#[derive(Clone)]
pub struct PciTdispDeviceStartInterface {
    pub pci_tdisp_device_start_interface_cb: fn(
        //IN
        vdm_handle: usize,
        start_interface_nonce: &[u8; START_INTERFACE_NONCE_LEN],
        //OUT
        interface_id: &mut InterfaceId,
        tdisp_error_code: &mut Option<TdispErrorCode>,
    ) -> SpdmResult,
}

pub fn register(context: PciTdispDeviceStartInterface) -> bool {
    PCI_TDISP_DEVICE_START_INTERFACE_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceStartInterface = PciTdispDeviceStartInterface {
    pci_tdisp_device_start_interface_cb:
        |//IN
         _vdm_handle: usize,
         _start_interface_nonce: &[u8; START_INTERFACE_NONCE_LEN],
         //OUT
         _interface_id: &mut InterfaceId,
         _tdisp_error_code: &mut Option<TdispErrorCode>|
         -> SpdmResult { unimplemented!() },
};

pub(crate) fn pci_tdisp_device_start_interface(
    //IN
    vdm_handle: usize,
    start_interface_nonce: &[u8; START_INTERFACE_NONCE_LEN],
    //OUT
    interface_id: &mut InterfaceId,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    (PCI_TDISP_DEVICE_START_INTERFACE_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_start_interface_cb)(
        vdm_handle,
        start_interface_nonce,
        interface_id,
        tdisp_error_code,
    )
}

pub(crate) fn pci_tdisp_rsp_start_interface(
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let req_start_interface_request = ReqStartInterfaceRequest::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut interface_id = InterfaceId::default();
    let mut tdisp_error_code = None;

    pci_tdisp_device_start_interface(
        vdm_handle,
        &req_start_interface_request.start_interface_nonce,
        &mut interface_id,
        &mut tdisp_error_code,
    )?;

    let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 0,
        vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    if let Some(tdisp_error_code) = tdisp_error_code {
        let len = write_error(
            vdm_handle,
            tdisp_error_code,
            0,
            &[],
            &mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload,
        )?;
        vendor_defined_rsp_payload_struct.rsp_length = len as u16;
        return Ok(vendor_defined_rsp_payload_struct);
    }

    let mut writer =
        Writer::init(&mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload);

    let cnt = RspStartInterfaceResponse {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::START_INTERFACE_RESPONSE,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
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
