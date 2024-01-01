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
    InterfaceId, ReqGetDeviceInterfaceState, RspDeviceInterfaceState, TdiState, TdispErrorCode,
    TdispMessageHeader, TdispRequestResponseCode, TdispVersion,
};

use super::pci_tdisp_rsp_tdisp_error::write_error;

static PCI_TDISP_DEVICE_INTERFACE_STATE_INSTANCE: OnceCell<PciTdispDeviceInterfaceState> =
    OnceCell::uninit();

#[derive(Clone)]
pub struct PciTdispDeviceInterfaceState {
    pub pci_tdisp_device_interface_state_cb: fn(
        // IN
        vdm_handle: usize,
        // OUT
        interface_id: &mut InterfaceId,
        tdi_state: &mut TdiState,
        tdisp_error_code: &mut Option<TdispErrorCode>,
    ) -> SpdmResult,
}

pub fn register(context: PciTdispDeviceInterfaceState) -> bool {
    PCI_TDISP_DEVICE_INTERFACE_STATE_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceInterfaceState = PciTdispDeviceInterfaceState {
    pci_tdisp_device_interface_state_cb: |_: usize,
                                          _: &mut InterfaceId,
                                          _: &mut TdiState,
                                          _: &mut Option<TdispErrorCode>|
     -> SpdmResult { unimplemented!() },
};

pub(crate) fn pci_tdisp_device_interface_state(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
    tdi_state: &mut TdiState,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    (PCI_TDISP_DEVICE_INTERFACE_STATE_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_interface_state_cb)(
        vdm_handle, interface_id, tdi_state, tdisp_error_code
    )
}

pub(crate) fn pci_tdisp_rsp_interface_state(
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let _ = ReqGetDeviceInterfaceState::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut interface_id = InterfaceId::default();
    let mut tdi_state = TdiState::ERROR;
    let mut tdisp_error_code = None;

    pci_tdisp_device_interface_state(
        vdm_handle,
        &mut interface_id,
        &mut tdi_state,
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

    let cnt = RspDeviceInterfaceState {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::DEVICE_INTERFACE_STATE,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
        tdi_state,
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
