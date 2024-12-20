// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_case1_spdmversion_struct() {
    // Validate VERSION response VersionNumberEntryCount beyond maximum allowed size.
    let u8_slice = &mut [0u8; 100];

    // VersionNumberEntryCount = 0xfe
    u8_slice[3] = 0xfe;
    let mut reader = Reader::init(u8_slice);
    create_spdm_context!(context);
    let res = SpdmVersionResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());

    // Validate VERSION response VersionNumberEntryCount 0 size.
    let u8_slice = &mut [0u8; 100];

    // VersionNumberEntryCount = 0x0
    u8_slice[3] = 0;
    let mut reader = Reader::init(u8_slice);
    create_spdm_context!(context);
    let res = SpdmVersionResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());

    // Validate VERSION response VersionNumberEntryCount beyond MAX_SPDM_VERSION_COUNT and with duplicated version entries.
    let u8_slice: &mut [u8; 16] = &mut [
        0x0, 0x0, 0x0, 0x6, 0x0, 0x10, 0x0, 0x10, 0x0, 0x11, 0x0, 0x12, 0x0, 0x13, 0x0, 0x13,
    ];
    let mut reader = Reader::init(u8_slice);
    create_spdm_context!(context);
    let res = SpdmVersionResponsePayload::spdm_read(&mut context, &mut reader);
    let version = res.unwrap();
    assert_eq!(version.version_number_entry_count, 4);
    assert_eq!(version.versions[0].version, SpdmVersion::SpdmVersion10);
    assert_eq!(version.versions[1].version, SpdmVersion::SpdmVersion11);
    assert_eq!(version.versions[2].version, SpdmVersion::SpdmVersion12);
    assert_eq!(version.versions[3].version, SpdmVersion::SpdmVersion13);
}
