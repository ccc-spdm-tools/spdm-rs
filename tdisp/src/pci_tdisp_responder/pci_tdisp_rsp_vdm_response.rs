// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use conquer_once::spin::OnceCell;
use spdmlib::{
    error::{SpdmResult, SPDM_STATUS_INVALID_STATE_LOCAL},
    message::{VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct},
};

static PCI_TDISP_DEVICE_VDM_RESPONSE_INSTANCE: OnceCell<PciTdispDeviceVdmResponse> =
    OnceCell::uninit();

#[derive(Clone)]
pub struct PciTdispDeviceVdmResponse {
    pub pci_tdisp_device_vdm_response_cb: fn(
        //IN
        vdm_handle: usize,
        vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct>,
}

pub fn register(context: PciTdispDeviceVdmResponse) -> bool {
    PCI_TDISP_DEVICE_VDM_RESPONSE_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceVdmResponse = PciTdispDeviceVdmResponse {
    pci_tdisp_device_vdm_response_cb:
        |//IN
         _vdm_handle: usize,
         _vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct|
         -> SpdmResult<VendorDefinedRspPayloadStruct> { unimplemented!() },
};

pub(crate) fn pci_tdisp_device_vdm_response(
    //IN
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    (PCI_TDISP_DEVICE_VDM_RESPONSE_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_vdm_response_cb)(vdm_handle, vendor_defined_req_payload_struct)
}

pub(crate) fn pci_tdisp_rsp_vdm_response(
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    pci_tdisp_device_vdm_response(vdm_handle, vendor_defined_req_payload_struct)
}
