// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::{
    common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo},
    message::SpdmRequestResponseCode,
    protocol::SpdmVersion,
};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_key_update_struct() {
    create_spdm_context!(context);
    let context = &mut context;

    // 1. Validate KeyUpdate request length is 4.
    let u8_slice = &mut [
        u8::from(SpdmVersion::SpdmVersion11),
        SpdmRequestResponseCode::SpdmRequestKeyUpdate.get_u8(),
        SpdmKeyUpdateOperation::SpdmUpdateSingleKey.get_u8(),
        0u8,
    ];
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyUpdateRequestPayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 2. Validate KEY_UPDATE_ACK response length is 4.
    let u8_slice = &mut [
        u8::from(SpdmVersion::SpdmVersion11),
        SpdmRequestResponseCode::SpdmResponseKeyUpdateAck.get_u8(),
        SpdmKeyUpdateOperation::SpdmUpdateSingleKey.get_u8(),
        0u8,
    ];
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyUpdateResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 3. Validate KEY_UPDATE operations equal to reserved value. Expactation, fail.
    let u8_slice = &mut [
        u8::from(SpdmVersion::SpdmVersion11),
        SpdmRequestResponseCode::SpdmRequestKeyUpdate.get_u8(),
        SpdmKeyUpdateOperation::SpdmUpdateSingleKey.get_u8(),
        0u8,
    ];
    u8_slice[2] = SpdmKeyUpdateOperation::SpdmVerifyNewKey.get_u8() + 1;
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyUpdateRequestPayload::spdm_read(context, reader);
    assert!(ret.is_none());

    // 4. Validate KEY_UPDATE_ACK KEY_UPDATE operations equal to reserved value. Expectation, fail
    let u8_slice = &mut [
        u8::from(SpdmVersion::SpdmVersion11),
        SpdmRequestResponseCode::SpdmResponseKeyUpdateAck.get_u8(),
        SpdmKeyUpdateOperation::SpdmUpdateSingleKey.get_u8(),
        0u8,
    ];
    u8_slice[2] = SpdmKeyUpdateOperation::SpdmVerifyNewKey.get_u8() + 1;
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyUpdateResponsePayload::spdm_read(context, reader);
    assert!(ret.is_none());
}
