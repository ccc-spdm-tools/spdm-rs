// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::opaque::SpdmOpaqueStruct;
use crate::common::spdm_codec::SpdmCodec;
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::{SpdmMeasurementRecordStructure, SpdmNonceStruct, SpdmSignatureStruct};
use codec::enum_builder;
use codec::{Codec, Reader, Writer};

use crate::common::SpdmMeasurementContentChanged;

use super::SpdmVersion;

pub const MEASUREMENT_RESPONDER_PARAM2_SLOT_ID_MASK: u8 = 0b0000_1111;
pub const MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_MASK: u8 = 0b0011_0000;

bitflags! {
    #[derive(Default)]
    pub struct SpdmMeasurementAttributes: u8 {
        const SIGNATURE_REQUESTED = 0b00000001;
        const RAW_BIT_STREAM_REQUESTED = 0b0000_0010;
    }
}

impl Codec for SpdmMeasurementAttributes {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmMeasurementAttributes> {
        let bits = u8::read(r)?;

        SpdmMeasurementAttributes::from_bits(bits)
    }
}

enum_builder! {
    @U8
    EnumName: SpdmMeasurementOperation;
    EnumVal{
        SpdmMeasurementQueryTotalNumber => 0x0,
        SpdmMeasurementRequestAll => 0xFF
    }
}
impl Default for SpdmMeasurementOperation {
    fn default() -> SpdmMeasurementOperation {
        SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmGetMeasurementsRequestPayload {
    pub measurement_attributes: SpdmMeasurementAttributes,
    pub measurement_operation: SpdmMeasurementOperation,
    pub nonce: SpdmNonceStruct,
    pub slot_id: u8,
}

impl SpdmCodec for SpdmGetMeasurementsRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .measurement_attributes
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += self
            .measurement_operation
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        if self
            .measurement_attributes
            .contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED)
        {
            cnt += self
                .nonce
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
                cnt += self
                    .slot_id
                    .encode(bytes)
                    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            }
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetMeasurementsRequestPayload> {
        let measurement_attributes = SpdmMeasurementAttributes::read(r)?; // param1
        let measurement_operation = SpdmMeasurementOperation::read(r)?; // param2
        let nonce =
            if measurement_attributes.contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED) {
                SpdmNonceStruct::read(r)?
            } else {
                SpdmNonceStruct::default()
            };
        let slot_id =
            if measurement_attributes.contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED) {
                if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
                    u8::read(r)?
                } else {
                    0
                }
            } else {
                0
            };

        Some(SpdmGetMeasurementsRequestPayload {
            measurement_attributes,
            measurement_operation,
            nonce,
            slot_id,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmMeasurementsResponsePayload {
    pub number_of_measurement: u8,
    pub content_changed: SpdmMeasurementContentChanged,
    pub slot_id: u8,
    pub measurement_record: SpdmMeasurementRecordStructure,
    pub nonce: SpdmNonceStruct,
    pub opaque: SpdmOpaqueStruct,
    pub signature: SpdmSignatureStruct,
    pub measurement_operation: SpdmMeasurementOperation,
}

impl SpdmCodec for SpdmMeasurementsResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        //When Param2 in the requested measurement operation is 0 , this
        //parameter shall return the total number of measurement indices on
        //the device. Otherwise, this field is reserved.
        if self.measurement_operation == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber {
            cnt += self
                .number_of_measurement
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += 0_u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12
            && context.runtime_info.need_measurement_signature
        {
            cnt += (self.slot_id | self.content_changed.bits())
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        } else if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11
            && context.runtime_info.need_measurement_signature
        {
            cnt += self
                .slot_id
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param 2
        } else {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param 2
        }
        cnt += self.measurement_record.spdm_encode(context, bytes)?;
        cnt += self
            .nonce
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self.opaque.spdm_encode(context, bytes)?;
        if context.runtime_info.need_measurement_signature {
            cnt += self.signature.spdm_encode(context, bytes)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMeasurementsResponsePayload> {
        let number_of_measurement = u8::read(r)?; // param1
        let param2 = u8::read(r)?; // param2
        let slot_id = param2 & MEASUREMENT_RESPONDER_PARAM2_SLOT_ID_MASK; // Bit [3:0]
        let content_changed = param2 & MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_MASK; // Bit [5:4]
        let content_changed = SpdmMeasurementContentChanged::from_bits(content_changed)?;
        let measurement_record = SpdmMeasurementRecordStructure::spdm_read(context, r)?;
        let nonce = SpdmNonceStruct::read(r)?;
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        let signature = if context.runtime_info.need_measurement_signature {
            SpdmSignatureStruct::spdm_read(context, r)?
        } else {
            SpdmSignatureStruct::default()
        };
        Some(SpdmMeasurementsResponsePayload {
            number_of_measurement,
            content_changed,
            slot_id,
            measurement_record,
            nonce,
            opaque,
            signature,
            measurement_operation: SpdmMeasurementOperation::Unknown(0),
        })
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::opaque::MAX_SPDM_OPAQUE_SIZE;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use crate::config::{self, *};
    use crate::protocol::*;
    use codec::u24;
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};
    extern crate alloc;

    #[test]
    fn test_case0_spdm_spdm_measuremente_attributes() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementAttributes::SIGNATURE_REQUESTED;
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmMeasurementAttributes::read(&mut reader).unwrap(),
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED
        );
        assert_eq!(3, reader.left());
    }
    #[test]
    fn test_case0_spdm_get_measurements_request_payload() {
        let u8_slice = &mut [0u8; 2 + SPDM_NONCE_SIZE + 1];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0x7,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(2 + SPDM_NONCE_SIZE + 1, reader.left());
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED
        );
        assert_eq!(
            get_measurements.measurement_operation,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
        );
        assert_eq!(get_measurements.slot_id, 0x7);
        for i in 0..SPDM_NONCE_SIZE {
            assert_eq!(get_measurements.nonce.data[i], 100u8);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_get_measurements_request_payload() {
        let u8_slice = &mut [0u8; 2];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementAttributes::empty(),
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0x7,
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(2, reader.left());
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementAttributes::empty()
        );
        assert_eq!(
            get_measurements.measurement_operation,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
        );
        assert_eq!(get_measurements.slot_id, 0);
        for i in 0..SPDM_NONCE_SIZE {
            assert_eq!(get_measurements.nonce.data[i], 0);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_measurements_response_payload() {
        create_spdm_context!(context);

        let u8_slice = &mut [0u8; 6
            + 5 * (7 + SPDM_MAX_HASH_SIZE)
            + SPDM_NONCE_SIZE
            + 2
            + MAX_SPDM_OPAQUE_SIZE
            + SPDM_MAX_ASYM_KEY_SIZE];
        let mut writer = Writer::init(u8_slice);
        let mut spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
            index: 1u8,
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            measurement_size: 3 + SHA512_DIGEST_SIZE as u16,
            measurement: SpdmDmtfMeasurementStructure {
                r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
                representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                value_size: SHA512_DIGEST_SIZE as u16,
                value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
            },
        };
        let mut measurement_record_data = [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE];
        let mut measurement_record_data_writer = Writer::init(&mut measurement_record_data);
        for _i in 0..5 {
            assert!(spdm_measurement_block_structure
                .spdm_encode(&mut context, &mut measurement_record_data_writer)
                .is_ok());
            spdm_measurement_block_structure.index += 1;
        }
        let value = SpdmMeasurementsResponsePayload {
            number_of_measurement: 100u8,
            slot_id: 7u8,
            content_changed: SpdmMeasurementContentChanged::NOT_SUPPORTED,
            measurement_record: SpdmMeasurementRecordStructure {
                number_of_blocks: 5,
                measurement_record_length: u24::new(measurement_record_data_writer.used() as u32),
                measurement_record_data,
            },
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
            signature: SpdmSignatureStruct {
                data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
                data: [100u8; SPDM_MAX_ASYM_KEY_SIZE],
            },
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
        };

        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        context.runtime_info.need_measurement_signature = true;
        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);

        assert_eq!(
            6 + 5 * (7 + SPDM_MAX_HASH_SIZE)
                + SPDM_NONCE_SIZE
                + 2
                + MAX_SPDM_OPAQUE_SIZE
                + SPDM_MAX_ASYM_KEY_SIZE,
            reader.left()
        );
        let mut measurements_response =
            SpdmMeasurementsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(measurements_response.number_of_measurement, 100);
        assert_eq!(measurements_response.slot_id, 7);
        assert_eq!(
            measurements_response.content_changed,
            SpdmMeasurementContentChanged::NOT_SUPPORTED
        );

        assert_eq!(measurements_response.measurement_record.number_of_blocks, 5);
        for i in 0..SPDM_NONCE_SIZE {
            assert_eq!(measurements_response.nonce.data[i], 100);
        }

        assert_eq!(
            measurements_response.opaque.data_size,
            MAX_SPDM_OPAQUE_SIZE as u16
        );
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(measurements_response.opaque.data[i], 100);
        }

        assert_eq!(
            measurements_response.signature.data_size,
            RSASSA_4096_KEY_SIZE as u16
        );
        for i in 0..RSASSA_4096_KEY_SIZE {
            assert_eq!(measurements_response.signature.data[i], 100);
        }
        assert_eq!(0, reader.left());

        let u8_slice = &mut [0u8; 6
            + 5 * (7 + SPDM_MAX_HASH_SIZE)
            + SPDM_NONCE_SIZE
            + 2
            + MAX_SPDM_OPAQUE_SIZE];
        let mut writer = Writer::init(u8_slice);

        context.runtime_info.need_measurement_signature = false;
        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(
            6 + 5 * (7 + SPDM_MAX_HASH_SIZE) + SPDM_NONCE_SIZE + 2 + MAX_SPDM_OPAQUE_SIZE,
            reader.left()
        );
        measurements_response =
            SpdmMeasurementsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(measurements_response.signature.data_size, 0);

        for i in 0..SPDM_NONCE_SIZE {
            assert_eq!(measurements_response.nonce.data[i], 100);
        }
        for i in 0..RSASSA_4096_KEY_SIZE {
            assert_eq!(measurements_response.signature.data[i], 0);
        }
        assert_eq!(0, reader.left());
    }
}

#[cfg(test)]
#[path = "measurement_test.rs"]
mod measurement_test;
