// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_case1_spdmversion_struct() {
    // Validata VERSION response VersionNumberEntryCount beyond maximum allowed size.
    let u8_slice = &mut [0u8; 100];

    // VersionNumberEntryCount = 0xfe
    u8_slice[3] = 0xfe;
    let mut reader = Reader::init(u8_slice);
    create_spdm_context!(context);
    let res = SpdmVersionResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());

    // Validata VERSION response VersionNumberEntryCount 0 size.
    let u8_slice = &mut [0u8; 100];

    // VersionNumberEntryCount = 0x0
    u8_slice[3] = 0;
    let mut reader = Reader::init(u8_slice);
    create_spdm_context!(context);
    let res = SpdmVersionResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none())
}
