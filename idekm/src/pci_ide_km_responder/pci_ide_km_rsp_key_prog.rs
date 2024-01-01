// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Writer};
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

use conquer_once::spin::OnceCell;

use crate::pci_idekm::{Aes256GcmKeyBuffer, KeyProgDataObject, KpAckDataObject, KpAckStatus};
static PCI_IDE_KM_DEVICE_KEY_PROG_INSTANCE: OnceCell<PciIdeKmDeviceKeyProg> = OnceCell::uninit();

#[derive(Clone)]
pub struct PciIdeKmDeviceKeyProg {
    pub pci_ide_km_device_key_prog_cb: fn(
        // IN
        stream_id: u8,
        key_set: u8,
        key_direction: u8,
        key_sub_stream: u8,
        port_index: u8,
        key_iv: Aes256GcmKeyBuffer,
        // OUT
        status: &mut KpAckStatus,
    ) -> SpdmResult,
}

pub fn register(context: PciIdeKmDeviceKeyProg) -> bool {
    PCI_IDE_KM_DEVICE_KEY_PROG_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciIdeKmDeviceKeyProg = PciIdeKmDeviceKeyProg {
    pci_ide_km_device_key_prog_cb: |_stream_id: u8,
                                    _key_set: u8,
                                    _key_direction: u8,
                                    _key_sub_stream: u8,
                                    _port_index: u8,
                                    _key_iv: Aes256GcmKeyBuffer,
                                    _status: &mut KpAckStatus|
     -> SpdmResult { unimplemented!() },
};

fn pci_ide_km_device_key_prog(
    stream_id: u8,
    key_set: u8,
    key_direction: u8,
    key_sub_stream: u8,
    port_index: u8,
    key_iv: Aes256GcmKeyBuffer,
    status: &mut KpAckStatus,
) -> SpdmResult {
    (PCI_IDE_KM_DEVICE_KEY_PROG_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_ide_km_device_key_prog_cb)(
        stream_id,
        key_set,
        key_direction,
        key_sub_stream,
        port_index,
        key_iv,
        status,
    )
}

pub(crate) fn pci_ide_km_rsp_key_prog(
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let key_prog_data_object = KeyProgDataObject::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 0,
        vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let mut status = KpAckStatus::default();
    let key_iv = key_prog_data_object.key_iv.clone();
    pci_ide_km_device_key_prog(
        key_prog_data_object.stream_id,
        key_prog_data_object.key_set,
        key_prog_data_object.key_direction,
        key_prog_data_object.key_sub_stream,
        key_prog_data_object.port_index,
        key_iv,
        &mut status,
    )?;

    let mut writer =
        Writer::init(&mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload);
    let cnt = KpAckDataObject {
        stream_id: key_prog_data_object.stream_id,
        status,
        key_set: key_prog_data_object.key_set,
        key_direction: key_prog_data_object.key_direction,
        key_sub_stream: key_prog_data_object.key_sub_stream,
        port_index: key_prog_data_object.port_index,
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
