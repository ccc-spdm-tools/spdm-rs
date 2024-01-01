// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]

pub mod common;
pub mod protocol;

#[cfg(test)]
mod test_client_server;
#[cfg(test)]
mod test_library;

#[cfg(test)]
mod requester_tests;

#[cfg(test)]
mod responder_tests;

#[cfg(test)]
mod watchdog_impl_sample;
