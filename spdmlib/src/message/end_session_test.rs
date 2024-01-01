// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_end_session_struct() {
    create_spdm_context!(context);
    let context = &mut context;

    // 1. Validate END_SESSION request length is 4.
    let u8_slice = &mut [0u8; 4];
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmEndSessionRequestPayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 2. Validate END_SESSION_ACK response length is 4.
    let u8_slice = &mut [0u8; 4];
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmEndSessionResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);
}
