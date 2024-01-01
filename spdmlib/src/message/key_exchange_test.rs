// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::{
    common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo},
    protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDheAlgo},
};
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_key_exchange_req_struct() {
    create_spdm_context!(context);
    let context = &mut context;

    // 1. validate req OpaqueDatalength > 1024, expectation. None
    // OpaqueDataLength = 1025
    const OPAQUE_DATA_LENGTH_CASE2: usize = 1025;
    context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
    let u8_slice = &mut [0u8; 42 + 64 + OPAQUE_DATA_LENGTH_CASE2];
    u8_slice[2] = SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone.get_u8();
    u8_slice[3] = 1;
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xffff); // ReqSessionId
    LittleEndian::write_u16(
        &mut u8_slice[(40 + 64)..(40 + 64 + 2)],
        OPAQUE_DATA_LENGTH_CASE2 as u16,
    );
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeRequestPayload::spdm_read(context, reader);
    assert!(ret.is_none());

    // 2. validate req OpaqueDatalength 0, expectation. ok
    const OPAQUE_DATA_LENGTH_CASE3: usize = 0;
    context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
    let u8_slice = &mut [0u8; 42 + 64 + OPAQUE_DATA_LENGTH_CASE3];
    u8_slice[2] = SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone.get_u8();
    u8_slice[3] = 1;
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xffff); // ReqSessionId
    LittleEndian::write_u16(
        &mut u8_slice[(40 + 64)..(40 + 64 + 2)],
        OPAQUE_DATA_LENGTH_CASE3 as u16,
    );
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeRequestPayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);
}

#[ignore = "extended unit test"]
#[test]
fn test_key_exchange_req_struct_extend() {
    create_spdm_context!(context);
    let context = &mut context;

    // 3. Validate request length equal to 42 + D + OpaqueDataLength
    // OpaqueDataLength = 256
    const OPAQUE_DATA_LENGTH_CASE1: usize = 256;
    context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
    let u8_slice = &mut [0u8; 42 + 64 + OPAQUE_DATA_LENGTH_CASE1];
    u8_slice[2] = SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll.get_u8();
    u8_slice[3] = 1;
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xffff); // ReqSessionId
    LittleEndian::write_u16(
        &mut u8_slice[(40 + 64)..(40 + 64 + 2)],
        OPAQUE_DATA_LENGTH_CASE1 as u16,
    );
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeRequestPayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 4. validate Param2(SlotId is invalid 10), expectation. none
    context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
    let u8_slice = &mut [0u8; 42 + 64 + OPAQUE_DATA_LENGTH_CASE1];
    u8_slice[2] = SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll.get_u8();
    u8_slice[3] = 10;
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xffff); // ReqSessionId
    LittleEndian::write_u16(
        &mut u8_slice[(40 + 64)..(40 + 64 + 2)],
        OPAQUE_DATA_LENGTH_CASE1 as u16,
    );
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeRequestPayload::spdm_read(context, reader);
    assert!(ret.is_none());
}

#[test]
fn test_key_exchange_rsp_struct() {
    create_spdm_context!(context);
    let context = &mut context;
    context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;

    // 1. validate req OpaqueDatalength > 1024, expectation. None
    // OpaqueDataLength = 1025
    const OPAQUE_DATA_LENGTH_CASE1: usize = 1025;
    let u8_slice = &mut [0u8; 42 + 64 + OPAQUE_DATA_LENGTH_CASE1 + 64 + 32];
    u8_slice[2] = 0;
    // RspSessionId
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xfffe);
    // MutAuthRequested
    u8_slice[6] = 0;
    // SlotIDParam
    u8_slice[7] = 0;
    // OpaqueDataLength
    LittleEndian::write_u16(
        &mut u8_slice[(40 + 64)..(40 + 64 + 2)],
        OPAQUE_DATA_LENGTH_CASE1 as u16,
    );

    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeResponsePayload::spdm_read(context, reader);
    assert!(ret.is_none());

    // 2. validate req OpaqueDatalength 0, expectation. ok
    const OPAQUE_DATA_LENGTH_CASE2: usize = 0;
    let u8_slice = &mut [0u8; 42 + 64 + OPAQUE_DATA_LENGTH_CASE2 + 64 + 32];
    u8_slice[2] = 0;
    // RspSessionId
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xfffe);
    // MutAuthRequested
    u8_slice[6] = 0;
    // SlotIDParam
    u8_slice[7] = 0;
    // OpaqueDataLength
    LittleEndian::write_u16(
        &mut u8_slice[(40 + 64)..(40 + 64 + 2)],
        OPAQUE_DATA_LENGTH_CASE2 as u16,
    );

    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // Verify the MutAuthRequested parameter, 0/1/2/4 is ok
    u8_slice[6] = 0x2;
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());

    u8_slice[6] = 0x8;
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeResponsePayload::spdm_read(context, reader);
    assert!(ret.is_none());
}

#[ignore = "extended unit test"]
#[test]
fn test_key_exchange_rsp_struct_extend() {
    create_spdm_context!(context);
    let context = &mut context;
    context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;

    // 2. validate req OpaqueDatalength 0, expectation. ok
    const OPAQUE_DATA_LENGTH_CASE1: usize = 0;
    let u8_slice = &mut [0u8; 42 + 64 + OPAQUE_DATA_LENGTH_CASE1 + 64 + 32];
    u8_slice[2] = 0;
    // RspSessionId
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xfffe);
    // MutAuthRequested
    u8_slice[6] = 3;
    // SlotIDParam
    u8_slice[7] = 0;
    // OpaqueDataLength
    LittleEndian::write_u16(
        &mut u8_slice[(40 + 64)..(40 + 64 + 2)],
        OPAQUE_DATA_LENGTH_CASE1 as u16,
    );

    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 3. validate req OpaqueDatalength 256, expectation. ok
    const OPAQUE_DATA_LENGTH_CASE2: usize = 256;
    let u8_slice = &mut [0u8; 42 + 64 + OPAQUE_DATA_LENGTH_CASE2 + 64 + 32];
    u8_slice[2] = 0;
    // RspSessionId
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xfffe);
    // MutAuthRequested
    u8_slice[6] = 0;
    // SlotIDParam
    u8_slice[7] = 0;
    // OpaqueDataLength
    LittleEndian::write_u16(
        &mut u8_slice[(40 + 64)..(40 + 64 + 2)],
        OPAQUE_DATA_LENGTH_CASE2 as u16,
    );

    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyExchangeResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);
}
