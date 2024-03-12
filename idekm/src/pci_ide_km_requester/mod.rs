// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[derive(Debug, Default, Copy, Clone)]
pub struct IdekmReqContext;

pub mod pci_ide_km_req_query;

pub mod pci_ide_km_req_key_prog;

pub mod pci_ide_km_req_key_set_go;

pub mod pci_ide_km_req_key_set_stop;
