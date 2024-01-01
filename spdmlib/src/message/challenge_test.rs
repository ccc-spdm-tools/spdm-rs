// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::{
    common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo},
    protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SHA256_DIGEST_SIZE},
};
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_challenge_struct() {
    create_spdm_context!(context);
    let context = &mut context;

    // Validate request payload size is 36 - 2 = 34
    let u8_slice = &mut [0u8; 36];
    let writer = &mut Writer::init(u8_slice);
    let request = SpdmChallengeRequestPayload {
        slot_id: 0xff,
        measurement_summary_hash_type:
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        nonce: SpdmNonceStruct::default(),
    };
    assert!(request.spdm_encode(context, writer).is_ok());
    assert_eq!(writer.used(), 34);

    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
    context.runtime_info.need_measurement_summary_hash = true;

    // Validate OpaqueDataLength is invalid. Expectation, pass
    const INVALID_OPAQUE_DATA_LENGTH: u16 = 1025u16;
    let u8_slice = &mut [0u8; 38
        + 2 * SHA256_DIGEST_SIZE
        + INVALID_OPAQUE_DATA_LENGTH as usize
        + SHA256_DIGEST_SIZE * 2];
    LittleEndian::write_u16(
        &mut u8_slice[(36 + 2 * SHA256_DIGEST_SIZE as usize)..],
        INVALID_OPAQUE_DATA_LENGTH,
    );
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmChallengeAuthResponsePayload::spdm_read(context, reader);
    assert!(ret.is_none());
}

#[ignore = "Extend unit tests"]
#[test]
fn test_challenge_struct_opaque_data_length_negative() {
    create_spdm_context!(context);
    let context = &mut context;

    // Validate support max OpaqueDataLength is 1024. Expectation, pass
    // Validate response payload size is 38 + 2H + OpaqueDataLength + SigLen
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
    context.runtime_info.need_measurement_summary_hash = true;

    let u8_slice = &mut [0u8; 38
        + 2 * SHA256_DIGEST_SIZE
        + OPAQUE_DATA_LENGTH as usize
        + SHA256_DIGEST_SIZE * 2];
    const OPAQUE_DATA_LENGTH: u16 = 1024u16;
    LittleEndian::write_u16(
        &mut u8_slice[(36 + 2 * SHA256_DIGEST_SIZE as usize)..],
        OPAQUE_DATA_LENGTH,
    );
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmChallengeAuthResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);
}
