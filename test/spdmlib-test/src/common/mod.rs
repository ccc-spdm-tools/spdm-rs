// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]

// TBD: need test different algorithm combinations
pub const USE_ECDSA: bool = true;

pub mod util;

pub mod device_io;

pub use pcidoe_transport as transport;

pub mod crypto_callback;
pub mod secret_callback;
