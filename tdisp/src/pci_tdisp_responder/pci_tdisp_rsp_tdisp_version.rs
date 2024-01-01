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

use crate::pci_tdisp::{InterfaceId, ReqGetTdispVersion, RspTdispVersion, TdispVersion};

use super::MAX_TDISP_VERSION_COUNT;

static PCI_TDISP_DEVICE_VERSIONI_INSTANCE: OnceCell<PciTdispDeviceVersion> = OnceCell::uninit();

#[derive(Clone)]
pub struct PciTdispDeviceVersion {
    #[allow(clippy::type_complexity)]
    pub pci_tdisp_device_version_cb: fn(
        // IN
        vdm_handle: usize,
        // OUT
        interface_id: &mut InterfaceId,
        version_num_count: &mut u8,
        version_num_entry: &mut [TdispVersion; MAX_TDISP_VERSION_COUNT],
    ) -> SpdmResult,
}

pub fn register(context: PciTdispDeviceVersion) -> bool {
    PCI_TDISP_DEVICE_VERSIONI_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceVersion = PciTdispDeviceVersion {
    pci_tdisp_device_version_cb: |// IN
                                  _vdm_handle: usize,
                                  // OUT
                                  _interface_id: &mut InterfaceId,
                                  _version_num_count: &mut u8,
                                  _version_num_entry: &mut [TdispVersion;
                                           MAX_TDISP_VERSION_COUNT]|
     -> SpdmResult { unimplemented!() },
};

pub(crate) fn pci_tdisp_device_version(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
    version_num_count: &mut u8,
    version_num_entry: &mut [TdispVersion; MAX_TDISP_VERSION_COUNT],
) -> SpdmResult {
    (PCI_TDISP_DEVICE_VERSIONI_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_version_cb)(
        // IN
        vdm_handle,
        // OUT
        interface_id,
        version_num_count,
        version_num_entry,
    )
}

pub(crate) fn pci_tdisp_rsp_version(
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let _ = ReqGetTdispVersion::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut interface_id = InterfaceId::default();
    let mut version_num_count = 0u8;
    let mut version_num_entry = [TdispVersion::default(); MAX_TDISP_VERSION_COUNT];

    pci_tdisp_device_version(
        vdm_handle,
        &mut interface_id,
        &mut version_num_count,
        &mut version_num_entry,
    )?;

    let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 0,
        vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let mut writer =
        Writer::init(&mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload);

    let cnt = RspTdispVersion {
        interface_id,
        version_num_count,
        version_num_entry,
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
