// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[ignore = "Test Fail"]
#[test]
fn test_capability_struct() {
    // 1. Validate Negative DataTransferSize < MinDataTransferSize. Expectation failed.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);

    u8_slice[5] = 10;
    let flags = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());
    LittleEndian::write_u32(&mut u8_slice[12..16], 1);
    LittleEndian::write_u32(&mut u8_slice[16..20], 1);

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());

    // 2. Validate DataTransferSize > MaxSPDMmsgSize. Expectation failed.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);

    u8_slice[5] = 10;
    let flags = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());
    LittleEndian::write_u32(&mut u8_slice[12..16], 4096);
    LittleEndian::write_u32(&mut u8_slice[16..20], 1024);

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());
}
