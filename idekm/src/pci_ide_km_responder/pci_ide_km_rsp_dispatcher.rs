// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::{
    pci_ide_km_rsp_key_prog, pci_ide_km_rsp_key_set_go, pci_ide_km_rsp_key_set_stop,
    pci_ide_km_rsp_query,
};
use crate::pci_idekm::{
    vendor_id, IDEKM_PROTOCOL_ID, KEY_PROG_OBJECT_ID, K_SET_GO_OBJECT_ID, K_SET_STOP_OBJECT_ID,
    QUERY_OBJECT_ID,
};
use spdmlib::{
    error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD},
    message::{
        VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct, VendorDefinedStruct,
        VendorIDStruct,
    },
};

pub const PCI_IDE_KM_INSTANCE: VendorDefinedStruct = VendorDefinedStruct {
    vendor_defined_request_handler: pci_ide_km_rsp_dispatcher,
    vdm_handle: 0,
};

pub fn pci_ide_km_rsp_dispatcher(
    _vdm_handle: usize,
    vendor_id_struct: &VendorIDStruct,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    if vendor_defined_req_payload_struct.req_length < 2
        || vendor_id_struct != &vendor_id()
        || vendor_defined_req_payload_struct.vendor_defined_req_payload[0] != IDEKM_PROTOCOL_ID
    {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    match vendor_defined_req_payload_struct.vendor_defined_req_payload[1] {
        QUERY_OBJECT_ID => {
            pci_ide_km_rsp_query::pci_ide_km_rsp_query(vendor_defined_req_payload_struct)
        }
        KEY_PROG_OBJECT_ID => {
            pci_ide_km_rsp_key_prog::pci_ide_km_rsp_key_prog(vendor_defined_req_payload_struct)
        }
        K_SET_GO_OBJECT_ID => {
            pci_ide_km_rsp_key_set_go::pci_ide_km_rsp_key_set_go(vendor_defined_req_payload_struct)
        }
        K_SET_STOP_OBJECT_ID => pci_ide_km_rsp_key_set_stop::pci_ide_km_rsp_key_set_stop(
            vendor_defined_req_payload_struct,
        ),
        _ => Err(SPDM_STATUS_INVALID_MSG_FIELD),
    }
}
