// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use bit_field::BitField;
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_negotiate_struct() {
    create_spdm_context!(context);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

    // 0. [Positive] test
    let u8_slice = &mut [0u8; 256];
    u8_slice[2] = 4;
    LittleEndian::write_u16(&mut u8_slice[4..6], 52);
    u8_slice[6] = SpdmMeasurementSpecification::DMTF.bits();
    u8_slice[7] = 0;
    LittleEndian::write_u32(
        &mut u8_slice[8..],
        SpdmMeasurementHashAlgo::TPM_ALG_SHA_256.bits(),
    );
    LittleEndian::write_u32(
        &mut u8_slice[12..],
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256.bits(),
    );
    LittleEndian::write_u32(
        &mut u8_slice[16..],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256.bits(),
    );

    // ExtAsymSelCount
    u8_slice[32] = 0;
    // ExtHashSelCount
    u8_slice[33] = 0;

    // Response Table 23 DHE structure
    u8_slice[36] = 2; //DHE
    u8_slice[37].set_bits(4..=7, 2);
    u8_slice[37].set_bits(0..=3, 0);
    LittleEndian::write_u16(&mut u8_slice[38..40], SpdmDheAlgo::SECP_256_R1.bits());

    // Response Table 24 AEAD structure
    u8_slice[40] = 3; // AEAD
    u8_slice[41].set_bits(4..=7, 2);
    u8_slice[41].set_bits(0..=3, 0);
    LittleEndian::write_u16(&mut u8_slice[42..44], SpdmAeadAlgo::AES_128_GCM.bits());

    // Response Table 25 ReqBaseAsymAlg structure
    u8_slice[44] = 4; // ReqBaseAsymAlg
    u8_slice[45].set_bits(4..=7, 2);
    u8_slice[45].set_bits(0..=3, 0);
    LittleEndian::write_u16(
        &mut u8_slice[46..48],
        SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256.bits(),
    );

    // Response Table 26 KeySchedule structure
    u8_slice[48] = 5; // KeySchedule structure
    u8_slice[49].set_bits(4..=7, 2);
    u8_slice[49].set_bits(0..=3, 0);
    LittleEndian::write_u16(
        &mut u8_slice[50..52],
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE.bits(),
    );

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmAlgorithmsResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_some());

    // 1. [Negative] validate ALGORITHMS response Length beyond the maximum allowed size. expectation fail.
    let u8_slice = &mut [0u8; 256];
    u8_slice[2] = 4;
    LittleEndian::write_u16(&mut u8_slice[4..6], 0xfffe);
    u8_slice[6] = SpdmMeasurementSpecification::DMTF.bits();
    u8_slice[7] = 0;
    LittleEndian::write_u32(
        &mut u8_slice[8..],
        SpdmMeasurementHashAlgo::TPM_ALG_SHA_256.bits(),
    );
    LittleEndian::write_u32(
        &mut u8_slice[12..],
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256.bits(),
    );
    LittleEndian::write_u32(
        &mut u8_slice[16..],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256.bits(),
    );

    // ExtAsymSelCount
    u8_slice[32] = 0;
    // ExtHashSelCount
    u8_slice[33] = 0;

    // Response Table 23 DHE structure
    u8_slice[36] = 2; //DHE
    u8_slice[37].set_bits(4..=7, 2);
    u8_slice[37].set_bits(0..=3, 0);
    LittleEndian::write_u16(&mut u8_slice[38..40], SpdmDheAlgo::SECP_256_R1.bits());

    // Response Table 24 AEAD structure
    u8_slice[40] = 3; // AEAD
    u8_slice[41].set_bits(4..=7, 2);
    u8_slice[41].set_bits(0..=3, 0);
    LittleEndian::write_u16(&mut u8_slice[42..44], SpdmAeadAlgo::AES_128_GCM.bits());

    // Response Table 25 ReqBaseAsymAlg structure
    u8_slice[44] = 4; // ReqBaseAsymAlg
    u8_slice[45].set_bits(4..=7, 2);
    u8_slice[45].set_bits(0..=3, 0);
    LittleEndian::write_u16(
        &mut u8_slice[46..48],
        SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256.bits(),
    );

    // Response Table 26 KeySchedule structure
    u8_slice[48] = 5; // KeySchedule structure
    u8_slice[49].set_bits(4..=7, 2);
    u8_slice[49].set_bits(0..=3, 0);
    LittleEndian::write_u16(
        &mut u8_slice[50..52],
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE.bits(),
    );

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmAlgorithmsResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());
}

#[ignore = "Test Fail"]
#[test]
fn test_negotiate_struct_response_negative_ext_alg_count_2() {
    create_spdm_context!(context);
    // 2. [Negative] validate ALGORITHMS response ExtAlgCount5 = 2
    let u8_slice = &mut [0u8; 256];
    u8_slice[2] = 4;
    LittleEndian::write_u16(&mut u8_slice[4..6], 60);
    u8_slice[6] = SpdmMeasurementSpecification::DMTF.bits();
    u8_slice[7] = 0;
    LittleEndian::write_u32(
        &mut u8_slice[8..],
        SpdmMeasurementHashAlgo::TPM_ALG_SHA_256.bits(),
    );
    LittleEndian::write_u32(
        &mut u8_slice[12..],
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256.bits(),
    );
    LittleEndian::write_u32(
        &mut u8_slice[16..],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256.bits(),
    );

    // ExtAsymSelCount
    u8_slice[32] = 0;
    // ExtHashSelCount
    u8_slice[33] = 0;

    // Response Table 23 DHE structure
    u8_slice[36] = 2; //DHE
    u8_slice[37].set_bits(4..=7, 2);
    u8_slice[37].set_bits(0..=3, 0);
    LittleEndian::write_u16(&mut u8_slice[38..40], SpdmDheAlgo::SECP_256_R1.bits());

    // Response Table 24 AEAD structure
    u8_slice[40] = 3; // AEAD
    u8_slice[41].set_bits(4..=7, 2);
    u8_slice[41].set_bits(0..=3, 0);
    LittleEndian::write_u16(&mut u8_slice[42..44], SpdmAeadAlgo::AES_128_GCM.bits());

    // Response Table 25 ReqBaseAsymAlg structure
    u8_slice[44] = 4; // ReqBaseAsymAlg
    u8_slice[45].set_bits(4..=7, 2);
    u8_slice[45].set_bits(0..=3, 0);
    LittleEndian::write_u16(
        &mut u8_slice[46..48],
        SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256.bits(),
    );

    // Response Table 26 KeySchedule structure
    u8_slice[48] = 5; // KeySchedule structure
    u8_slice[49].set_bits(4..=7, 2);
    u8_slice[49].set_bits(0..=3, 2);
    LittleEndian::write_u16(
        &mut u8_slice[50..52],
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE.bits(),
    );

    let mut reader = Reader::init(&u8_slice[2..]);
    let res = SpdmAlgorithmsResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(res.is_none());
}
