// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_certificate_struct() {
    create_spdm_context!(context);
    let context = &mut context;
    let u8_slice = &mut [0u8; 10];

    let writer = &mut Writer::init(u8_slice);
    let request = SpdmGetCertificateRequestPayload {
        slot_id: 3,
        offset: 0,
        length: 1024,
    };
    assert!(request.spdm_encode(context, writer).is_ok());
    assert_eq!(writer.used(), 6);

    let u8_slice = &mut [0u8; 1024];

    u8_slice[2] = 1;
    LittleEndian::write_u16(&mut u8_slice[4..6], 512);
    LittleEndian::write_u16(&mut u8_slice[6..8], 0);

    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmCertificateResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.used(), 8 + 512 - 2);
}

#[ignore = "Extended unit test"]
#[test]
fn test_certificate_struct_negative() {
    create_spdm_context!(context);
    let context = &mut context;
    let u8_slice = &mut [0u8; 1024];

    // Verify SlotID < 8
    // SlotID >= 8
    u8_slice[2] = 8;
    LittleEndian::write_u16(&mut u8_slice[4..6], 512);
    LittleEndian::write_u16(&mut u8_slice[6..8], 0);

    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmCertificateResponsePayload::spdm_read(context, reader);
    assert!(ret.is_none());
}
