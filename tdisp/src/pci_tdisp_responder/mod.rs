// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

pub const MAX_TDISP_VERSION_COUNT: usize = u8::MAX as usize;

pub mod pci_tdisp_rsp_dispatcher;
pub use pci_tdisp_rsp_dispatcher::*;

pub mod pci_tdisp_rsp_bind_p2p_stream_request;
pub mod pci_tdisp_rsp_device_interface_report;
pub mod pci_tdisp_rsp_device_interface_state;
pub mod pci_tdisp_rsp_lock_interface_request;
pub mod pci_tdisp_rsp_set_mmio_attribute_request;
pub mod pci_tdisp_rsp_start_interface_request;
pub mod pci_tdisp_rsp_stop_interface_request;
pub mod pci_tdisp_rsp_tdisp_capabilities;
pub mod pci_tdisp_rsp_tdisp_error;
pub mod pci_tdisp_rsp_tdisp_version;
pub mod pci_tdisp_rsp_unbind_p2p_stream_request;
pub mod pci_tdisp_rsp_vdm_response;
