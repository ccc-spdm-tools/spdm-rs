// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Writer};
use conquer_once::spin::OnceCell;
use spdmlib::{
    error::{SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_STATE_LOCAL},
    message::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE,
};

use crate::pci_tdisp::{
    InterfaceId, RspTdispError, TdispErrorCode, TdispMessageHeader, TdispRequestResponseCode,
    TdispVersion,
};

static PCI_TDISP_DEVICE_ERROR_INSTANCE: OnceCell<PciTdispDeviceError> = OnceCell::uninit();

#[derive(Clone)]
pub struct PciTdispDeviceError {
    #[allow(clippy::type_complexity)]
    pub pci_tdisp_device_error_cb: fn(
        // IN
        vdm_handle: usize,
        // OUT
        interface_id: &mut InterfaceId,
    ) -> SpdmResult,
}

pub fn register(context: PciTdispDeviceError) -> bool {
    PCI_TDISP_DEVICE_ERROR_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceError = PciTdispDeviceError {
    pci_tdisp_device_error_cb: |// IN
                                _vdm_handle: usize,
                                // OUT
                                _interface_id: &mut InterfaceId|
     -> SpdmResult { unimplemented!() },
};

pub(crate) fn pci_tdisp_device_error(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
) -> SpdmResult {
    (PCI_TDISP_DEVICE_ERROR_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_error_cb)(
        // IN
        vdm_handle,
        // OUT
        interface_id,
    )
}

pub(crate) fn write_error(
    vdm_handle: usize,
    error_code: TdispErrorCode,
    error_data: u32,
    ext_error_data: &[u8],
    vendor_defined_rsp_payload: &mut [u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
) -> SpdmResult<usize> {
    let mut writer = Writer::init(vendor_defined_rsp_payload);

    let mut interface_id = InterfaceId::default();

    pci_tdisp_device_error(vdm_handle, &mut interface_id)?;

    let len1 = RspTdispError {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::TDISP_ERROR,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
        error_code,
        error_data,
    }
    .encode(&mut writer)
    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    if let Some(len2) = writer.extend_from_slice(ext_error_data) {
        Ok(len1 + len2)
    } else {
        Err(SPDM_STATUS_BUFFER_FULL)
    }
}
