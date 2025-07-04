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

#[test]
fn test_capability_request_struct() {
    // 0. Version 1.3 Successful Setting.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);
    context.data.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

    let flags = SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP
        | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
        | SpdmRequestCapabilityFlags::EP_INFO_CAP_NO_SIG
        | SpdmRequestCapabilityFlags::EVENT_CAP
        | SpdmRequestCapabilityFlags::MULTI_KEY_CAP_ONLY;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());
    LittleEndian::write_u32(&mut u8_slice[12..16], 4096);
    LittleEndian::write_u32(&mut u8_slice[16..20], 4096);

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_some());
    let res = res.unwrap();
    assert!(res.ct_exponent == 0);
    assert!(res.flags.bits() == flags.bits());
    assert!(res.data_transfer_size == 4096);
    assert!(res.max_spdm_msg_size == 4096);

    // 1. Validate SUPPORTED_ALGOS_EXT_CAP bit is set and CHUNK_CAP not supported. Expectation failed.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);
    context.data.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

    u8_slice[2] = 1; // Set SUPPORTED_ALGOS_EXT_CAP bit in param1.
    let flags = SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());
    LittleEndian::write_u32(&mut u8_slice[12..16], 4096);
    LittleEndian::write_u32(&mut u8_slice[16..20], 4096);

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());

    // 2. Validate sample illegal capability flags settings. Expectation failed.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);
    context.data.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

    let flags = SpdmRequestCapabilityFlags::EP_INFO_CAP_SIG
        | SpdmRequestCapabilityFlags::EP_INFO_CAP_NO_SIG;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());
    LittleEndian::write_u32(&mut u8_slice[12..16], 4096);
    LittleEndian::write_u32(&mut u8_slice[16..20], 4096);

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());

    let flags =
        SpdmRequestCapabilityFlags::MULTI_KEY_CAP_ONLY | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());
}

#[test]
fn test_capability_response_struct() {
    // 0. Version 1.3 Successful Setting.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);
    context.data.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

    let flags = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
        | SpdmResponseCapabilityFlags::ENCAP_CAP
        | SpdmResponseCapabilityFlags::HBEAT_CAP
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP
        | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
        | SpdmResponseCapabilityFlags::EP_INFO_CAP_NO_SIG
        | SpdmResponseCapabilityFlags::MEL_CAP
        | SpdmResponseCapabilityFlags::EVENT_CAP
        | SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY
        | SpdmResponseCapabilityFlags::GET_KEY_PAIR_INFO_CAP
        | SpdmResponseCapabilityFlags::SET_KEY_PAIR_INFO_CAP;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());
    LittleEndian::write_u32(&mut u8_slice[12..16], 4096);
    LittleEndian::write_u32(&mut u8_slice[16..20], 4096);

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_some());
    let res = res.unwrap();
    assert!(res.ct_exponent == 0);
    assert!(res.flags.bits() == flags.bits());
    assert!(res.data_transfer_size == 4096);
    assert!(res.max_spdm_msg_size == 4096);

    // 1. Validate sample illegal capability flags settings. Expectation failed.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);
    context.data.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

    let flags = SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY
        | SpdmResponseCapabilityFlags::MULTI_KEY_CAP_CONN_SEL
        | SpdmResponseCapabilityFlags::GET_KEY_PAIR_INFO_CAP;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());
    LittleEndian::write_u32(&mut u8_slice[12..16], 4096);
    LittleEndian::write_u32(&mut u8_slice[16..20], 4096);

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());

    let flags = SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());
}
