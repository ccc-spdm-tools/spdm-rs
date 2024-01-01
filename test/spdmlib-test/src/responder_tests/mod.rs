// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]

mod challenge_rsp;

mod algorithm_rsp;

mod capability_rsp;

mod certificate_rsp;

// Disable context here because some test cases use private function,
// may need keep those test cases located in spdmlib/src/responder/context.rs
//
// mod context;

mod digest_rsp;

#[cfg(feature = "mut-auth")]
mod encap_get_certificate;

#[cfg(feature = "mut-auth")]
mod encap_get_digest;

#[cfg(feature = "mut-auth")]
mod encap_rsp;

mod end_session_rsp;

mod error_rsp;

mod finish_rsp;

mod heartbeat_rsp;

mod key_exchange_rsp;

mod key_update_rsp;

mod measurement_rsp;

mod psk_exchange_rsp;

mod psk_finish_rsp;

mod vendor_rsp;

mod version_rsp;
