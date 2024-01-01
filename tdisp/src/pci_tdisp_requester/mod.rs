// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::pci_tdisp::{InterfaceId, TdispVersion};

pub mod pci_tdisp_req_get_tdisp_version;
pub use pci_tdisp_req_get_tdisp_version::*;

pub mod pci_tdisp_req_get_tdisp_capabilities;
pub use pci_tdisp_req_get_tdisp_capabilities::*;

pub mod pci_tdisp_req_lock_interface_request;
pub use pci_tdisp_req_lock_interface_request::*;

pub mod pci_tdisp_req_get_device_interface_report;
pub use pci_tdisp_req_get_device_interface_report::*;

pub mod pci_tdisp_req_get_device_interface_state;
pub use pci_tdisp_req_get_device_interface_state::*;

pub mod pci_tdisp_req_start_interface_request;
pub use pci_tdisp_req_start_interface_request::*;

pub mod pci_tdisp_req_stop_interface_request;
pub use pci_tdisp_req_stop_interface_request::*;

pub mod pci_tdisp_req_bind_p2p_stream_request;
pub use pci_tdisp_req_bind_p2p_stream_request::*;

pub mod pci_tdisp_req_set_mmio_attribute_request;
pub use pci_tdisp_req_set_mmio_attribute_request::*;

pub mod pci_tdisp_req_unbind_p2p_stream_request;
pub use pci_tdisp_req_unbind_p2p_stream_request::*;

pub mod pci_tdisp_req_vdm_request;
pub use pci_tdisp_req_vdm_request::*;
