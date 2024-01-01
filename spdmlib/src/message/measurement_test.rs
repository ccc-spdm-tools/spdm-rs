// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::{
    common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo},
    config::MAX_SPDM_MEASUREMENT_RECORD_SIZE,
};
use bit_field::BitField;
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_measurement_struct() {
    create_spdm_context!(context);
    let context = &mut context;
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

    // Validate SpdmMeasurementAttributes::SIGNATURE_REQUESTED length
    let u8_slice = &mut [0u8; 4 + 32 + 1];
    let writer = &mut Writer::init(u8_slice);
    let request = SpdmGetMeasurementsRequestPayload {
        measurement_attributes: SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
        measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
        nonce: SpdmNonceStruct::default(),
        slot_id: 1,
    };
    assert!(request.spdm_encode(context, writer).is_ok());
    assert_eq!(writer.used(), 4 + 32 + 1 - 2);

    // Validate SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED length
    let writer = &mut Writer::init(u8_slice);
    let request = SpdmGetMeasurementsRequestPayload {
        measurement_attributes: SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
        measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
        nonce: SpdmNonceStruct::default(),
        slot_id: 1,
    };
    assert!(request.spdm_encode(context, writer).is_ok());
    assert_eq!(writer.used(), 4 - 2);
}

#[ignore = "Extend unit tests"]
#[test]
fn test_measurement_response() {
    create_spdm_context!(context);
    let context = &mut context;
    // Validate responder measurement record length is beyond MAX_SPDM_MEASUREMENT_RECORD_SIZE.
    let u8_slice = &mut [0u8; MAX_SPDM_MEASUREMENT_RECORD_SIZE + 200];
    u8_slice[3].set_bits(4..=5, 0b10);
    u8_slice[3].set_bits(0..=3, 1);
    u8_slice[4] = 0xfe;
    LittleEndian::write_u24(&mut u8_slice[5..8], MAX_SPDM_MEASUREMENT_RECORD_SIZE as u32);
    LittleEndian::write_u16(
        &mut u8_slice
            [(40 + MAX_SPDM_MEASUREMENT_RECORD_SIZE)..(42 + MAX_SPDM_MEASUREMENT_RECORD_SIZE)],
        1024,
    );

    let reader = &mut Reader::init(u8_slice);
    let ret = SpdmMeasurementsResponsePayload::spdm_read(context, reader);
    assert!(ret.is_none())
}
