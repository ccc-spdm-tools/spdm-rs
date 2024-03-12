// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![feature(stmt_expr_attributes)]
#![feature(try_trait_v2)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate bitflags;

extern crate codec;

pub mod protocol;
#[macro_use]
pub mod error;
pub mod common;
pub mod crypto;
pub mod message;
pub mod requester;
pub mod responder;
pub mod secret;
pub mod time;
pub mod watchdog;

pub mod config;

use core::mem::size_of;
pub const SPDM_STACK_SIZE: usize = size_of::<crate::common::SpdmContext>() +
                            size_of::<crate::protocol::SpdmCertChainData>() * (crate::protocol::SPDM_MAX_SLOT_NUMBER + 1) + size_of::<crate::protocol::SpdmCertChainBuffer>() * crate::protocol::SPDM_MAX_SLOT_NUMBER + // SpdmProvisionInfo
                            size_of::<crate::protocol::SpdmCertChainData>() * (crate::protocol::SPDM_MAX_SLOT_NUMBER + 1) + // SpdmPeerInfo
                            (crate::config::MAX_SPDM_MSG_SIZE + crate::config::SENDER_BUFFER_SIZE + crate::config::RECEIVER_BUFFER_SIZE) * 5 + // send/receive + encode/decode
                            crate::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE * 8 + // worst case: 8 slots
                            (crate::config::MAX_SPDM_MEASUREMENT_RECORD_SIZE + crate::config::MAX_SPDM_MEASUREMENT_VALUE_LEN) * 255 + // worst case: 255 index
                            crate::config::MAX_SPDM_PSK_CONTEXT_SIZE + // for PSK
                            crate::config::MAX_SPDM_PSK_HINT_SIZE + // for PSK
                            size_of::<usize>() * 256; // for general stack case
