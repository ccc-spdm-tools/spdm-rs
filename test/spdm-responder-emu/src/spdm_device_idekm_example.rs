// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use idekm::{
    pci_ide_km_responder::{
        pci_ide_km_rsp_key_prog::{self, PciIdeKmDeviceKeyProg},
        pci_ide_km_rsp_key_set_go::{self, PciIdeKmDeviceKeySetGo},
        pci_ide_km_rsp_key_set_stop::{self, PciIdeKmDeviceKeySetStop},
        pci_ide_km_rsp_query::{self, PciIdeKmDeviceQuery},
    },
    pci_idekm::{Aes256GcmKeyBuffer, KpAckStatus, PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT},
};
use spdmlib::error::SpdmResult;

fn pci_ide_km_device_key_prog(
    // IN
    stream_id: u8,
    key_set: u8,
    key_direction: u8,
    key_sub_stream: u8,
    port_index: u8,
    key_iv: Aes256GcmKeyBuffer,
    // OUT
    status: &mut KpAckStatus,
) -> SpdmResult {
    *status = KpAckStatus::SUCCESS;
    log::info!("{stream_id:X?}, {key_set:X?}, {key_direction:X?}, {key_sub_stream:X?}, {port_index:X?}, {key_iv:X?}, {status:X?}!");
    Ok(())
}

fn pci_ide_km_device_key_set_go(
    stream_id: u8,
    key_set: u8,
    key_direction: u8,
    key_sub_stream: u8,
    port_index: u8,
) -> SpdmResult {
    log::info!(
        "{stream_id:X?}, {key_set:X?}, {key_direction:X?}, {key_sub_stream:X?}, {port_index:X?}!"
    );
    Ok(())
}

fn pci_ide_km_device_key_set_stop(
    stream_id: u8,
    key_set: u8,
    key_direction: u8,
    key_sub_stream: u8,
    port_index: u8,
) -> SpdmResult {
    log::info!(
        "{stream_id:X?}, {key_set:X?}, {key_direction:X?}, {key_sub_stream:X?}, {port_index:X?}!"
    );
    Ok(())
}

fn pci_ide_km_device_query(
    port_index: u8,
    dev_func_num: &mut u8,
    bus_num: &mut u8,
    segment: &mut u8,
    max_port_index: &mut u8,
    ide_reg_block: &mut [u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT],
    ide_reg_block_cnt: &mut usize,
) -> SpdmResult {
    *dev_func_num = 0;
    *bus_num = 0x6a;
    *segment = 1;
    *max_port_index = 1;
    *ide_reg_block_cnt = 2;
    log::info!("{port_index:X?}, {dev_func_num:X?}, {bus_num:X?}, {segment:X?}, {max_port_index:X?}, {ide_reg_block:X?}, {ide_reg_block_cnt:X?}!");
    Ok(())
}

pub fn init_device_idekm_instance() {
    pci_ide_km_rsp_key_prog::register(PciIdeKmDeviceKeyProg {
        pci_ide_km_device_key_prog_cb: pci_ide_km_device_key_prog,
    });
    pci_ide_km_rsp_key_set_go::register(PciIdeKmDeviceKeySetGo {
        pci_ide_km_device_key_set_go_cb: pci_ide_km_device_key_set_go,
    });
    pci_ide_km_rsp_key_set_stop::register(PciIdeKmDeviceKeySetStop {
        pci_ide_km_device_key_set_stop_cb: pci_ide_km_device_key_set_stop,
    });
    pci_ide_km_rsp_query::register(PciIdeKmDeviceQuery {
        pci_ide_km_device_query_cb: pci_ide_km_device_query,
    });
}
