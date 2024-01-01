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
    InterfaceId, LockInterfaceFlag, ReqGetTdispCapabilities, RspTdispCapabilities, TdispErrorCode,
    TdispMessageHeader, TdispRequestResponseCode, TdispVersion,
};

use super::pci_tdisp_rsp_tdisp_error::write_error;

static PCI_TDISP_DEVICE_CAPABILITIES_INSTANCE: OnceCell<PciTdispDeviceCapabilities> =
    OnceCell::uninit();

#[derive(Clone)]
pub struct PciTdispDeviceCapabilities {
    #[allow(clippy::type_complexity)]
    pub pci_tdisp_device_capabilities_cb: fn(
        // IN
        vdm_handle: usize,
        tsm_caps: u32,
        // OUT
        interface_id: &mut InterfaceId,
        dsm_caps: &mut u32,
        req_msgs_supported: &mut [u8; 16],
        lock_interface_flags_supported: &mut LockInterfaceFlag,
        dev_addr_width: &mut u8,
        num_req_this: &mut u8,
        num_req_all: &mut u8,
        tdisp_error_code: &mut Option<TdispErrorCode>,
    ) -> SpdmResult,
}

pub fn register(context: PciTdispDeviceCapabilities) -> bool {
    PCI_TDISP_DEVICE_CAPABILITIES_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceCapabilities = PciTdispDeviceCapabilities {
    pci_tdisp_device_capabilities_cb: |// IN
                                       _vdm_handle: usize,
                                       _tsm_caps: u32,
                                       // OUT
                                       _interface_id: &mut InterfaceId,
                                       _dsm_caps: &mut u32,
                                       _req_msgs_supported: &mut [u8; 16],
                                       _lock_interface_flags_supported: &mut LockInterfaceFlag,
                                       _dev_addr_width: &mut u8,
                                       _num_req_this: &mut u8,
                                       _num_req_all: &mut u8,
                                       _tdisp_error_code: &mut Option<TdispErrorCode>|
     -> SpdmResult { unimplemented!() },
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn pci_tdisp_device_capabilities(
    // IN
    vdm_handle: usize,
    tsm_caps: u32,
    // OUT
    interface_id: &mut InterfaceId,
    dsm_caps: &mut u32,
    req_msgs_supported: &mut [u8; 16],
    lock_interface_flags_supported: &mut LockInterfaceFlag,
    dev_addr_width: &mut u8,
    num_req_this: &mut u8,
    num_req_all: &mut u8,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    (PCI_TDISP_DEVICE_CAPABILITIES_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_capabilities_cb)(
        // IN
        vdm_handle,
        tsm_caps,
        // OUT
        interface_id,
        dsm_caps,
        req_msgs_supported,
        lock_interface_flags_supported,
        dev_addr_width,
        num_req_this,
        num_req_all,
        tdisp_error_code,
    )
}

pub(crate) fn pci_tdisp_rsp_capabilities(
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let req_get_tdisp_capabilities = ReqGetTdispCapabilities::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut interface_id = InterfaceId::default();
    let mut dsm_caps = 0u32;
    let mut req_msgs_supported = [0u8; 16];
    let mut lock_interface_flags_supported = LockInterfaceFlag::empty();
    let mut dev_addr_width = 0u8;
    let mut num_req_this = 0u8;
    let mut num_req_all = 0u8;
    let mut tdisp_error_code = None;

    pci_tdisp_device_capabilities(
        vdm_handle,
        req_get_tdisp_capabilities.tsm_caps,
        &mut interface_id,
        &mut dsm_caps,
        &mut req_msgs_supported,
        &mut lock_interface_flags_supported,
        &mut dev_addr_width,
        &mut num_req_this,
        &mut num_req_all,
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

    let cnt = RspTdispCapabilities {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::TDISP_CAPABILITIES,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
        dsm_caps,
        req_msgs_supported,
        lock_interface_flags_supported,
        dev_addr_width,
        num_req_this,
        num_req_all,
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
