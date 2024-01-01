// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::convert::TryFrom;
use spdmlib::{
    error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD},
    message::{
        VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct, VendorIDStruct,
        MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE,
    },
};

use crate::pci_tdisp::{vendor_id, TdispErrorCode, TdispRequestResponseCode, TDISP_PROTOCOL_ID};

use super::{
    pci_tdisp_rsp_bind_p2p_stream_request::pci_tdisp_rsp_bind_p2p_stream,
    pci_tdisp_rsp_device_interface_report::pci_tdisp_rsp_interface_report,
    pci_tdisp_rsp_device_interface_state::pci_tdisp_rsp_interface_state,
    pci_tdisp_rsp_lock_interface_request::pci_tdisp_rsp_lock_interface,
    pci_tdisp_rsp_set_mmio_attribute_request::pci_tdisp_rsp_set_mmio_attribute,
    pci_tdisp_rsp_start_interface_request::pci_tdisp_rsp_start_interface,
    pci_tdisp_rsp_stop_interface_request::pci_tdisp_rsp_stop_interface,
    pci_tdisp_rsp_tdisp_capabilities::pci_tdisp_rsp_capabilities,
    pci_tdisp_rsp_tdisp_error::write_error, pci_tdisp_rsp_tdisp_version::pci_tdisp_rsp_version,
    pci_tdisp_rsp_unbind_p2p_stream_request::pci_tdisp_rsp_unbind_p2p_stream,
    pci_tdisp_rsp_vdm_response::pci_tdisp_rsp_vdm_response,
};

pub fn pci_tdisp_rsp_dispatcher(
    vdm_handle: usize,
    vendor_id_struct: &VendorIDStruct,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    if vendor_defined_req_payload_struct.req_length < 3
        || vendor_id_struct != &vendor_id()
        || vendor_defined_req_payload_struct.vendor_defined_req_payload[0] != TDISP_PROTOCOL_ID
    {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    if let Ok(request_response_code) = TdispRequestResponseCode::try_from(
        vendor_defined_req_payload_struct.vendor_defined_req_payload[2],
    ) {
        match request_response_code {
            TdispRequestResponseCode::GET_TDISP_VERSION => {
                pci_tdisp_rsp_version(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::GET_TDISP_CAPABILITIES => {
                pci_tdisp_rsp_capabilities(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::LOCK_INTERFACE_REQUEST => {
                pci_tdisp_rsp_lock_interface(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::GET_DEVICE_INTERFACE_REPORT => {
                pci_tdisp_rsp_interface_report(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::GET_DEVICE_INTERFACE_STATE => {
                pci_tdisp_rsp_interface_state(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::START_INTERFACE_REQUEST => {
                pci_tdisp_rsp_start_interface(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::STOP_INTERFACE_REQUEST => {
                pci_tdisp_rsp_stop_interface(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::SET_MMIO_ATTRIBUTE_REQUEST => {
                pci_tdisp_rsp_set_mmio_attribute(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::BIND_P2P_STREAM_REQUEST => {
                pci_tdisp_rsp_bind_p2p_stream(vdm_handle, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::UNBIND_P2P_STREAM_REQUEST => {
                pci_tdisp_rsp_unbind_p2p_stream(vdm_handle, vendor_defined_req_payload_struct)
            }
            _ => {
                let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
                    rsp_length: 0,
                    vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
                };

                let len = write_error(
                    vdm_handle,
                    TdispErrorCode::UNSUPPORTED_REQUEST,
                    0,
                    &[],
                    &mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload,
                )?;
                vendor_defined_rsp_payload_struct.rsp_length = len as u16;
                Ok(vendor_defined_rsp_payload_struct)
            }
        }
    } else {
        pci_tdisp_rsp_vdm_response(vdm_handle, vendor_defined_req_payload_struct)
    }
}
