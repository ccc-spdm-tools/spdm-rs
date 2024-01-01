// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Writer};
use spdmlib::{
    error::SpdmResult,
    message::{
        VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct,
        MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE,
    },
};
use tdisp::{
    pci_tdisp::{
        InterfaceId, InterfaceInfo, LockInterfaceFlag, MMIORangeAttribute, TdiState,
        TdispErrorCode, TdispMmioRange, TdispVersion, MAX_DEVICE_REPORT_BUFFER,
        START_INTERFACE_NONCE_LEN, TDISP_PROTOCOL_ID,
    },
    pci_tdisp_responder::{
        pci_tdisp_rsp_bind_p2p_stream_request::{self, PciTdispDeviceBindP2pStream},
        pci_tdisp_rsp_device_interface_report::{self, PciTdispDeviceInterfaceReport},
        pci_tdisp_rsp_device_interface_state::{self, PciTdispDeviceInterfaceState},
        pci_tdisp_rsp_lock_interface_request::{self, PciTdispDeviceLockInterface},
        pci_tdisp_rsp_set_mmio_attribute_request::{self, PciTdispDeviceSetMmioAttribute},
        pci_tdisp_rsp_start_interface_request::{self, PciTdispDeviceStartInterface},
        pci_tdisp_rsp_stop_interface_request::{self, PciTdispDeviceStopInterface},
        pci_tdisp_rsp_tdisp_capabilities::{self, PciTdispDeviceCapabilities},
        pci_tdisp_rsp_tdisp_error::{self, PciTdispDeviceError},
        pci_tdisp_rsp_tdisp_version::{self, PciTdispDeviceVersion},
        pci_tdisp_rsp_unbind_p2p_stream_request::{self, PciTdispDeviceUnBindP2pStream},
        pci_tdisp_rsp_vdm_response::{self, PciTdispDeviceVdmResponse},
        MAX_TDISP_VERSION_COUNT,
    },
};

pub const MMIO_RANGE_COUNT: usize = 4;
pub const DEVICE_SPECIFIC_INFO: &[u8; 9] = b"tdisp emu";
pub const DEVICE_SPECIFIC_INFO_LEN: usize = DEVICE_SPECIFIC_INFO.len();

#[derive(Debug, Copy, Clone)]
pub struct TdiReportStructure {
    pub interface_info: InterfaceInfo,
    pub msi_x_message_control: u16,
    pub lnr_control: u16,
    pub tph_control: u32,
    pub mmio_range_count: u32,
    pub mmio_range: [TdispMmioRange; MMIO_RANGE_COUNT],
    pub device_specific_info_len: u32,
    pub device_specific_info: [u8; DEVICE_SPECIFIC_INFO_LEN],
}

impl Default for TdiReportStructure {
    fn default() -> Self {
        Self {
            interface_info: InterfaceInfo::default(),
            msi_x_message_control: 0u16,
            lnr_control: 0u16,
            tph_control: 0u32,
            mmio_range_count: 0u32,
            mmio_range: [TdispMmioRange::default(); MMIO_RANGE_COUNT],
            device_specific_info_len: 0u32,
            device_specific_info: [0u8; DEVICE_SPECIFIC_INFO_LEN],
        }
    }
}

impl Codec for TdiReportStructure {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.interface_info.encode(bytes)?;
        cnt += 0u16.encode(bytes)?;
        cnt += self.msi_x_message_control.encode(bytes)?;
        cnt += self.lnr_control.encode(bytes)?;
        cnt += self.tph_control.encode(bytes)?;
        cnt += self.mmio_range_count.encode(bytes)?;
        for mr in self.mmio_range.iter().take(self.mmio_range_count as usize) {
            cnt += mr.encode(bytes)?;
        }
        cnt += self.device_specific_info_len.encode(bytes)?;
        for dsi in self
            .device_specific_info
            .iter()
            .take(self.device_specific_info_len as usize)
        {
            cnt += dsi.encode(bytes)?;
        }

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let interface_info = InterfaceInfo::read(r)?;
        u16::read(r)?;
        let msi_x_message_control = u16::read(r)?;
        let lnr_control = u16::read(r)?;
        let tph_control = u32::read(r)?;
        let mmio_range_count = u32::read(r)?;
        if mmio_range_count as usize > MMIO_RANGE_COUNT {
            return None;
        }
        let mut mmio_range = [TdispMmioRange::default(); MMIO_RANGE_COUNT];
        for mr in mmio_range.iter_mut().take(mmio_range_count as usize) {
            *mr = TdispMmioRange::read(r)?;
        }
        let device_specific_info_len = u32::read(r)?;
        if device_specific_info_len as usize > DEVICE_SPECIFIC_INFO_LEN {
            return None;
        }
        let mut device_specific_info = [0u8; DEVICE_SPECIFIC_INFO_LEN];
        for dsi in device_specific_info
            .iter_mut()
            .take(device_specific_info_len as usize)
        {
            *dsi = u8::read(r)?;
        }

        Some(Self {
            interface_info,
            msi_x_message_control,
            lnr_control,
            tph_control,
            mmio_range_count,
            mmio_range,
            device_specific_info_len,
            device_specific_info,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DeviceContext {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub negotiated_version: Option<TdispVersion>,
    pub interface_id: InterfaceId,
    pub dsm_caps: u32,
    pub dev_addr_width: u8,
    pub num_req_this: u8,
    pub num_req_all: u8,
    pub flags: LockInterfaceFlag,
    pub tdi_state: TdiState,
    pub default_stream_id: u8,
    pub mmio_reporting_offset: u64,
    pub bind_p2p_address_mask: u64,
    pub start_interface_nonce: [u8; START_INTERFACE_NONCE_LEN],
    pub p2p_stream_id: u8,
}

#[allow(clippy::too_many_arguments)]
fn pci_tdisp_device_capabilities(
    // IN
    vdm_handle: usize,
    _tsm_caps: u32,
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
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &*device_context as &DeviceContext };

    *interface_id = device_context.interface_id;
    *dsm_caps = device_context.dsm_caps;
    req_msgs_supported[0] = 0x7f;
    *lock_interface_flags_supported = device_context.flags;
    *dev_addr_width = device_context.dev_addr_width;
    *num_req_this = device_context.num_req_this;
    *num_req_all = device_context.num_req_all;

    *tdisp_error_code = None;
    Ok(())
}

fn pci_tdisp_device_error(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    *interface_id = device_context.interface_id;

    device_context.tdi_state = TdiState::ERROR;

    Ok(())
}

fn pci_tdisp_device_interface_report(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
    tdi_report: &mut [u8; MAX_DEVICE_REPORT_BUFFER],
    tdi_report_size: &mut usize,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    if device_context.tdi_state != TdiState::CONFIG_LOCKED
        && device_context.tdi_state != TdiState::RUN
    {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_INTERFACE_STATE);
    } else {
        *interface_id = device_context.interface_id;
        let report = TdiReportStructure {
            interface_info: InterfaceInfo::DEVICE_FIRMWARE_UPDATES_NOT_PERMITTED,
            msi_x_message_control: 0u16,
            lnr_control: 0u16,
            tph_control: 0u32,
            mmio_range_count: 1,
            mmio_range: [TdispMmioRange {
                first_page_with_offset_added: 0x12340000 + device_context.mmio_reporting_offset,
                number_of_pages: 32,
                range_attributes: MMIORangeAttribute::empty(),
            }; MMIO_RANGE_COUNT],
            device_specific_info_len: 6,
            device_specific_info: [6u8; DEVICE_SPECIFIC_INFO_LEN],
        };
        let mut writer = Writer::init(tdi_report);
        if let Ok(size) = report.encode(&mut writer) {
            *tdi_report_size = size;
            *tdisp_error_code = None;
        } else {
            *tdi_report_size = 0;
            *tdisp_error_code = Some(TdispErrorCode::INVALID_DEVICE_CONFIGURATION);
        }
    }

    Ok(())
}

fn pci_tdisp_device_interface_state(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
    tdi_state: &mut TdiState,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    *interface_id = device_context.interface_id;
    *tdi_state = device_context.tdi_state;

    *tdisp_error_code = None;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn pci_tdisp_device_lock_interface(
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
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    if device_context.tdi_state != TdiState::CONFIG_UNLOCKED {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_INTERFACE_STATE);
    } else {
        *tdisp_error_code = None;
        *interface_id = device_context.interface_id;

        device_context.flags = *flags;
        device_context.default_stream_id = default_stream_id;
        device_context.mmio_reporting_offset = mmio_reporting_offset;
        device_context.bind_p2p_address_mask = bind_p2p_address_mask;

        if spdmlib::crypto::rand::get_random(start_interface_nonce).is_err() {
            *tdisp_error_code = Some(TdispErrorCode::INSUFFICIENT_ENTROPY);
            return Ok(());
        }

        device_context
            .start_interface_nonce
            .copy_from_slice(start_interface_nonce);

        device_context.tdi_state = TdiState::CONFIG_LOCKED;
    }

    Ok(())
}

fn pci_tdisp_device_start_interface(
    //IN
    vdm_handle: usize,
    start_interface_nonce: &[u8; START_INTERFACE_NONCE_LEN],
    //OUT
    interface_id: &mut InterfaceId,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    if device_context.tdi_state != TdiState::CONFIG_LOCKED {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_INTERFACE_STATE);
    } else if start_interface_nonce != &device_context.start_interface_nonce {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_NONCE);
    } else {
        *tdisp_error_code = None;
        *interface_id = device_context.interface_id;

        device_context.tdi_state = TdiState::RUN;
    }

    Ok(())
}

fn pci_tdisp_device_stop_interface(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    if device_context.tdi_state != TdiState::RUN {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_INTERFACE_STATE);
        return Ok(());
    } else {
        *tdisp_error_code = None;
        *interface_id = device_context.interface_id;

        device_context.tdi_state = TdiState::CONFIG_UNLOCKED;
    }

    Ok(())
}

fn pci_tdisp_device_bind_p2p_stream(
    //IN
    vdm_handle: usize,
    p2p_stream_id: u8,
    //OUT
    interface_id: &mut InterfaceId,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    if device_context.tdi_state != TdiState::RUN {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_INTERFACE_STATE);
        return Ok(());
    } else {
        *tdisp_error_code = None;
        *interface_id = device_context.interface_id;

        device_context.p2p_stream_id = p2p_stream_id;
    }

    Ok(())
}

fn pci_tdisp_device_unbind_p2p_stream(
    //IN
    vdm_handle: usize,
    p2p_stream_id: u8,
    //OUT
    interface_id: &mut InterfaceId,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    if device_context.tdi_state != TdiState::RUN {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_INTERFACE_STATE);
        return Ok(());
    } else if p2p_stream_id != device_context.p2p_stream_id {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_REQUEST);
        return Ok(());
    } else {
        *tdisp_error_code = None;
        *interface_id = device_context.interface_id;

        device_context.p2p_stream_id = 0;
    }

    Ok(())
}

fn pci_tdisp_device_set_mmio_attribute(
    //IN
    vdm_handle: usize,
    _mmio_range: &TdispMmioRange,
    //OUT
    interface_id: &mut InterfaceId,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    if device_context.tdi_state != TdiState::RUN {
        *tdisp_error_code = Some(TdispErrorCode::INVALID_INTERFACE_STATE);
        return Ok(());
    } else {
        *tdisp_error_code = None;
        *interface_id = device_context.interface_id;
    }

    Ok(())
}

fn pci_tdisp_device_vdm_response(
    //IN
    _vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    println!(
        "vdm request: {:X?}",
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize]
    );

    let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 19,
        vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload[0] = TDISP_PROTOCOL_ID;
    vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload[1..19]
        .copy_from_slice(b"tdisp vdm response");

    Ok(vendor_defined_rsp_payload_struct)
}

fn pci_tdisp_device_version(
    // IN
    vdm_handle: usize,
    // OUT
    interface_id: &mut InterfaceId,
    version_num_count: &mut u8,
    version_num_entry: &mut [TdispVersion; MAX_TDISP_VERSION_COUNT],
) -> SpdmResult {
    let device_context = vdm_handle as *mut DeviceContext;

    let device_context = unsafe { &mut *device_context as &mut DeviceContext };

    *interface_id = device_context.interface_id;
    *version_num_count = 1;
    version_num_entry[0] = TdispVersion {
        major_version: 1,
        minor_version: 0,
    };

    device_context.negotiated_version = Some(TdispVersion {
        major_version: 1,
        minor_version: 0,
    });

    Ok(())
}

pub fn init_device_tdisp_instance() {
    pci_tdisp_rsp_tdisp_capabilities::register(PciTdispDeviceCapabilities {
        pci_tdisp_device_capabilities_cb: pci_tdisp_device_capabilities,
    });
    pci_tdisp_rsp_tdisp_error::register(PciTdispDeviceError {
        pci_tdisp_device_error_cb: pci_tdisp_device_error,
    });
    pci_tdisp_rsp_device_interface_report::register(PciTdispDeviceInterfaceReport {
        pci_tdisp_device_interface_report_cb: pci_tdisp_device_interface_report,
    });
    pci_tdisp_rsp_device_interface_state::register(PciTdispDeviceInterfaceState {
        pci_tdisp_device_interface_state_cb: pci_tdisp_device_interface_state,
    });
    pci_tdisp_rsp_lock_interface_request::register(PciTdispDeviceLockInterface {
        pci_tdisp_device_lock_interface_cb: pci_tdisp_device_lock_interface,
    });
    pci_tdisp_rsp_start_interface_request::register(PciTdispDeviceStartInterface {
        pci_tdisp_device_start_interface_cb: pci_tdisp_device_start_interface,
    });
    pci_tdisp_rsp_stop_interface_request::register(PciTdispDeviceStopInterface {
        pci_tdisp_device_stop_interface_cb: pci_tdisp_device_stop_interface,
    });
    pci_tdisp_rsp_tdisp_version::register(PciTdispDeviceVersion {
        pci_tdisp_device_version_cb: pci_tdisp_device_version,
    });
    pci_tdisp_rsp_bind_p2p_stream_request::register(PciTdispDeviceBindP2pStream {
        pci_tdisp_device_bind_p2p_stream_cb: pci_tdisp_device_bind_p2p_stream,
    });
    pci_tdisp_rsp_unbind_p2p_stream_request::register(PciTdispDeviceUnBindP2pStream {
        pci_tdisp_device_unbind_p2p_stream_cb: pci_tdisp_device_unbind_p2p_stream,
    });
    pci_tdisp_rsp_set_mmio_attribute_request::register(PciTdispDeviceSetMmioAttribute {
        pci_tdisp_device_set_mmio_attribute_cb: pci_tdisp_device_set_mmio_attribute,
    });
    pci_tdisp_rsp_vdm_response::register(PciTdispDeviceVdmResponse {
        pci_tdisp_device_vdm_response_cb: pci_tdisp_device_vdm_response,
    });
}
