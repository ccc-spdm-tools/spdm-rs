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

use crate::pci_idekm::{QueryDataObject, QueryRespDataObject, PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT};

use conquer_once::spin::OnceCell;
static PCI_IDE_KM_DEVICE_QUERY_INSTANCE: OnceCell<PciIdeKmDeviceQuery> = OnceCell::uninit();

#[derive(Clone)]
pub struct PciIdeKmDeviceQuery {
    pub pci_ide_km_device_query_cb: fn(
        port_index: u8,
        dev_func_num: &mut u8,
        bus_num: &mut u8,
        segment: &mut u8,
        max_port_index: &mut u8,
        ide_reg_block: &mut [u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT],
        ide_reg_block_cnt: &mut usize,
    ) -> SpdmResult,
}

pub fn register(context: PciIdeKmDeviceQuery) -> bool {
    PCI_IDE_KM_DEVICE_QUERY_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciIdeKmDeviceQuery = PciIdeKmDeviceQuery {
    pci_ide_km_device_query_cb: |_port_index: u8,
                                 _dev_func_num: &mut u8,
                                 _bus_num: &mut u8,
                                 _segment: &mut u8,
                                 _max_port_index: &mut u8,
                                 _ide_reg_block: &mut [u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT],
                                 _ide_reg_block_cnt: &mut usize|
     -> SpdmResult { unimplemented!() },
};

fn pci_ide_km_device_query(
    port_index: u8,
    dev_func_num: &mut u8,
    bus_num: &mut u8,
    segment: &mut u8,
    max_port_index: &mut u8,
    ide_reg_block: &mut [u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT],
    ide_reg_block_cnt: &mut usize,
) -> SpdmResult {
    (PCI_IDE_KM_DEVICE_QUERY_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_ide_km_device_query_cb)(
        port_index,
        dev_func_num,
        bus_num,
        segment,
        max_port_index,
        ide_reg_block,
        ide_reg_block_cnt,
    )
}

pub(crate) fn pci_ide_km_rsp_query(
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let query_data_object = QueryDataObject::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 0,
        vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    let port_index = query_data_object.port_index;
    let mut dev_func_num = 0u8;
    let mut bus_num = 0u8;
    let mut segment = 0u8;
    let mut max_port_index = 0u8;
    let mut ide_reg_block = [0u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT];
    let mut ide_reg_block_cnt = 0usize;

    pci_ide_km_device_query(
        port_index,
        &mut dev_func_num,
        &mut bus_num,
        &mut segment,
        &mut max_port_index,
        &mut ide_reg_block,
        &mut ide_reg_block_cnt,
    )?;

    let mut writer =
        Writer::init(&mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload);

    let cnt = QueryRespDataObject {
        port_index,
        dev_func_num,
        bus_num,
        segment,
        max_port_index,
        ide_reg_block_cnt,
        ide_reg_block,
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
