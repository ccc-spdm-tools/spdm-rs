// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::{
    common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo},
    protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo},
};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_finish_struct() {
    create_spdm_context!(context);
    let context = &mut context;
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;

    // 1. Validate FINISH request length is 4 + SigLen + H. SigLen if Param1 Bit 0 is set.
    let u8_slice = &mut [0u8; 4 + 32];
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmFinishRequestPayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 2. Validate FINISH_RSP response length is 4 + H. H absent when HANDSHAKE_IN_THE_CLEAR_CAP is zero.
    let u8_slice = &mut [0u8; 4];
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmFinishResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 3. Validate FINISH_RSP response length is 4 + H. when HANDSHAKE_IN_THE_CLEAR_CAPs are not 0.
    let u8_slice = &mut [0u8; 4];
    context.negotiate_info.req_capabilities_sel |=
        SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
    context.negotiate_info.rsp_capabilities_sel |=
        SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmFinishResponsePayload::spdm_read(context, reader);
    assert!(ret.is_none());

    // 4. Validate FINISH_RSP response length is 4 + H. when HANDSHAKE_IN_THE_CLEAR_CAPs are not 0.
    let u8_slice = &mut [0u8; 4 + 32];
    context.negotiate_info.req_capabilities_sel |=
        SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
    context.negotiate_info.rsp_capabilities_sel |=
        SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmFinishResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);
}
