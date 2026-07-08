// Copyright (c) 2023, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_capability_struct() {
    // 1. Validate Negative DataTransferSize < MinDataTransferSize. Expectation failed.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

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
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

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
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

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

    // 1. SUPPORTED_ALGOS_EXT_CAP bit is set. The request is accepted regardless of the
    // Responder's CHUNK_CAP; whether the SupportedAlgorithms block is returned is decided on
    // the response side.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

    u8_slice[2] = 1; // Set SUPPORTED_ALGOS_EXT_CAP bit in param1.
    let flags = SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP;
    LittleEndian::write_u32(&mut u8_slice[8..12], flags.bits());
    LittleEndian::write_u32(&mut u8_slice[12..16], 4096);
    LittleEndian::write_u32(&mut u8_slice[16..20], 4096);

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_some());
    assert!(res.unwrap().supported_algos_requested);

    // 2. Validate sample illegal capability flags settings. Expectation failed.
    let u8_slice = &mut [0u8; 100];
    create_spdm_context!(context);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

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
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

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
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

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

// Cross-test with libspdm: the SupportedAlgorithms block returned in CAPABILITIES has the
// exact same on-wire layout as libspdm's `spdm_supported_algorithms_block_t`, whose base size
// is 30 bytes (the NEGOTIATE_ALGORITHMS body minus the 2-byte SPDM message header). libspdm
// validates `length == sizeof(block)(30) + count * sizeof(common_struct_table)(4)`, uses
// `AlgCount = 0x20` (AlgFixedCount=2 in the high nibble) for each table, and orders the tables
// by ascending AlgType. This golden vector is byte-identical to what libspdm produces for a
// SPDM 1.3 Responder configured with SHA-256 / RSASSA-2048 / SECP256R1 / AES-128-GCM /
// SPDM_KEY_SCHEDULE, and we assert both decode and re-encode round-trip against it.
#[test]
fn test_capability_response_supported_algorithms_libspdm_vector() {
    // SPDM 1.3, 4 algorithm structure tables (DHE, AEAD, ReqAsym, KeySchedule).
    // Block length = 30 + 4 * 4 = 46.
    const ALG_STRUCT_COUNT: u8 = 4;
    const BLOCK_LEN: u16 = 30 + 4 * ALG_STRUCT_COUNT as u16;

    #[rustfmt::skip]
    let payload: &[u8] = &[
        // ---- fixed CAPABILITIES response (payload, no SPDM message header) ----
        0x01,                    // param1: SUPPORTED_ALGORITHMS
        0x00,                    // param2
        0x00,                    // reserved
        0x00,                    // ct_exponent
        0x00, 0x00,              // ex_flags (reserved for < 1.4)
        0x06, 0x00, 0x00, 0x00,  // flags = CERT_CAP | CHAL_CAP (passes checks)
        0x00, 0x10, 0x00, 0x00,  // data_transfer_size = 4096
        0x00, 0x10, 0x00, 0x00,  // max_spdm_msg_size = 4096
        // ---- SupportedAlgorithms block ----
        ALG_STRUCT_COUNT,        // block param1 = number of alg struct tables
        0x00,                    // block param2 (reserved)
        (BLOCK_LEN & 0xff) as u8, (BLOCK_LEN >> 8) as u8, // block length = 46
        0x01,                    // measurement_specification = DMTF
        0x00,                    // other_params_support
        0x01, 0x00, 0x00, 0x00,  // base_asym_algo = TPM_ALG_RSASSA_2048
        0x01, 0x00, 0x00, 0x00,  // base_hash_algo = TPM_ALG_SHA_256
        0x00, 0x00, 0x00, 0x00,  // reserved (PQCAsymAlgo added only in 1.4)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved2[8]
        0x00,                    // ext_asym_count
        0x00,                    // ext_hash_count
        0x00,                    // reserved3
        0x00,                    // mel_specification
        // AlgStruct[0]: DHE, AlgCount=0x20, SECP_256_R1 (0x0008)
        0x02, 0x20, 0x08, 0x00,
        // AlgStruct[1]: AEAD, AlgCount=0x20, AES_128_GCM (0x0001)
        0x03, 0x20, 0x01, 0x00,
        // AlgStruct[2]: ReqAsym, AlgCount=0x20, TPM_ALG_RSASSA_2048 (0x0001)
        0x04, 0x20, 0x01, 0x00,
        // AlgStruct[3]: KeySchedule, AlgCount=0x20, SPDM_KEY_SCHEDULE (0x0001)
        0x05, 0x20, 0x01, 0x00,
    ];

    create_spdm_context!(context);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

    // 1. Decode the libspdm-format bytes.
    let mut reader = Reader::init(payload);
    let res = SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader)
        .expect("failed to decode libspdm CAPABILITIES + SupportedAlgorithms");
    assert_eq!(reader.left(), 0);
    assert_eq!(res.data_transfer_size, 4096);
    assert_eq!(res.max_spdm_msg_size, 4096);

    let block = res
        .supported_algorithms
        .as_ref()
        .expect("SupportedAlgorithms block must be present when param1 bit is set");
    assert_eq!(block.alg_struct_count, ALG_STRUCT_COUNT);
    assert_eq!(
        block.measurement_specification,
        SpdmMeasurementSpecification::DMTF
    );
    assert_eq!(block.base_asym_algo, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048);
    assert_eq!(block.base_hash_algo, SpdmBaseHashAlgo::TPM_ALG_SHA_256);
    assert_eq!(block.alg_struct[0].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
    assert_eq!(
        block.alg_struct[0].alg_supported,
        SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
    );
    assert_eq!(
        block.alg_struct[3].alg_type,
        SpdmAlgType::SpdmAlgTypeKeySchedule
    );

    // 2. Re-encode and confirm the bytes are identical to the libspdm golden vector.
    let mut out = [0u8; 128];
    let mut writer = Writer::init(&mut out);
    let used = res
        .spdm_encode(&mut context, &mut writer)
        .expect("failed to re-encode CAPABILITIES + SupportedAlgorithms");
    assert_eq!(&out[..used], payload);
}

// Cross-test with libspdm: the block's internal `Length` field must equal 30 + 4*count. A
// value computed from the SPDM 1.1-style base of 32 (which erroneously includes the 2-byte
// message header) must be rejected, matching libspdm's strict length/count coherence check.
#[test]
fn test_capability_response_supported_algorithms_bad_length() {
    // Full CAPABILITIES payload (18 bytes) + a count-0 SupportedAlgorithms block (30 bytes).
    #[rustfmt::skip]
    let mut payload: [u8; 48] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00,      // param1(SUPPORTED_ALGOS), param2, rsvd, ct, ex_flags
        0x06, 0x00, 0x00, 0x00,                  // flags = CERT_CAP | CHAL_CAP
        0x00, 0x10, 0x00, 0x00,                  // data_transfer_size
        0x00, 0x10, 0x00, 0x00,                  // max_spdm_msg_size
        0x00,                                    // block param1 = 0 tables
        0x00,                                    // block param2
        30, 0x00,                                // block length = 30 (correct for count 0)
        0x01, 0x00,                              // measurement_specification, other_params
        0x01, 0x00, 0x00, 0x00,                  // base_asym_algo
        0x01, 0x00, 0x00, 0x00,                  // base_hash_algo
        0x00, 0x00, 0x00, 0x00,                  // reserved (PQCAsymAlgo only in 1.4)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved2[8]
        0x00,                                    // ext_asym_count
        0x00,                                    // ext_hash_count
        0x00,                                    // reserved3
        0x00,                                    // mel_specification
    ];

    create_spdm_context!(context);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

    // Sanity: with the correct length (30), the block decodes.
    let mut reader = Reader::init(&payload[..]);
    let res = SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_some());
    assert_eq!(
        res.unwrap().supported_algorithms.unwrap().alg_struct_count,
        0
    );

    // Corrupt the block length to the wrong (32-based) value; decode must fail, matching
    // libspdm's `length == sizeof(block) + count * sizeof(table)` coherence check.
    payload[20] = 32;
    let mut reader = Reader::init(&payload[..]);
    let res = SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());
}
