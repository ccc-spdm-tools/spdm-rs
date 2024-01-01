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
    InterfaceId, LockInterfaceFlag, ReqLockInterfaceRequest, RspLockInterfaceResponse,
    TdispErrorCode, TdispMessageHeader, TdispRequestResponseCode, TdispVersion,
    START_INTERFACE_NONCE_LEN,
};

use super::pci_tdisp_rsp_tdisp_error::write_error;

static PCI_TDISP_DEVICE_LOCK_INTERFACE_INSTANCE: OnceCell<PciTdispDeviceLockInterface> =
    OnceCell::uninit();

#[derive(Clone)]
pub struct PciTdispDeviceLockInterface {
    #[allow(clippy::type_complexity)]
    pub pci_tdisp_device_lock_interface_cb: fn(
        // IN
        vdm_handle: usize,
        flags: &LockInterfaceFlag,
        default_stream_id: u8,
        mmio_reporting_offset: u64,
        bind_p2p_address_mask: u64,
        // OUT
        interface_id: &mut InterfaceId,
        start_interface_nonce: &mut [u8; START_INTERFACE_NONCE_LEN],
        tdisp_error_code: &mut Option<TdispErrorCode>,
    ) -> SpdmResult,
}

pub fn register(context: PciTdispDeviceLockInterface) -> bool {
    PCI_TDISP_DEVICE_LOCK_INTERFACE_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceLockInterface = PciTdispDeviceLockInterface {
    pci_tdisp_device_lock_interface_cb:
        |// IN
         _vdm_handle: usize,
         _flags: &LockInterfaceFlag,
         _default_stream_id: u8,
         _mmio_reporting_offset: u64,
         _bind_p2p_address_mask: u64,
         // OUT
         _interface_id: &mut InterfaceId,
         _start_interface_nonce: &mut [u8; START_INTERFACE_NONCE_LEN],
         _tdisp_error_code: &mut Option<TdispErrorCode>|
         -> SpdmResult { unimplemented!() },
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn pci_tdisp_device_lock_interface(
    // IN
    vdm_handle: usize,
    flags: &LockInterfaceFlag,
    default_stream_id: u8,
    mmio_reporting_offset: u64,
    bind_p2p_address_mask: u64,
    // OUT
    interface_id: &mut InterfaceId,
    start_interface_nonce: &mut [u8; START_INTERFACE_NONCE_LEN],
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    (PCI_TDISP_DEVICE_LOCK_INTERFACE_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_lock_interface_cb)(
        vdm_handle,
        flags,
        default_stream_id,
        mmio_reporting_offset,
        bind_p2p_address_mask,
        interface_id,
        start_interface_nonce,
        tdisp_error_code,
    )
}

pub(crate) fn pci_tdisp_rsp_lock_interface(
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let req_lock_interface_request = ReqLockInterfaceRequest::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 0,
        vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let mut interface_id = InterfaceId::default();
    let mut start_interface_nonce = [0u8; START_INTERFACE_NONCE_LEN];
    let mut tdisp_error_code = None;

    pci_tdisp_device_lock_interface(
        vdm_handle,
        &req_lock_interface_request.flags,
        req_lock_interface_request.default_stream_id,
        req_lock_interface_request.mmio_reporting_offset,
        req_lock_interface_request.bind_p2p_address_mask,
        &mut interface_id,
        &mut start_interface_nonce,
        &mut tdisp_error_code,
    )?;

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

    let cnt = RspLockInterfaceResponse {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::LOCK_INTERFACE_RESPONSE,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
        start_interface_nonce,
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
