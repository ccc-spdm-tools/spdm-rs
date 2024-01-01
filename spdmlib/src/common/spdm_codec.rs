// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::SpdmContext;
use crate::config;
use crate::error::{SpdmResult, SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::{
    SpdmDheExchangeStruct, SpdmDigestStruct, SpdmDmtfMeasurementRepresentation,
    SpdmDmtfMeasurementStructure, SpdmDmtfMeasurementType, SpdmMeasurementBlockStructure,
    SpdmMeasurementHashAlgo, SpdmMeasurementRecordStructure, SpdmMeasurementSpecification,
    SpdmSignatureStruct, SPDM_MAX_ASYM_KEY_SIZE, SPDM_MAX_DHE_KEY_SIZE, SPDM_MAX_HASH_SIZE,
};
use codec::{u24, Codec, Reader, Writer};
use core::fmt::Debug;
extern crate alloc;
use alloc::boxed::Box;

pub trait SpdmCodec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    /// return Ok(usize) or Err(SpdmStatus)
    fn spdm_encode(&self, _context: &mut SpdmContext, _bytes: &mut Writer) -> SpdmResult<usize>;

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn spdm_read(_context: &mut SpdmContext, _: &mut Reader) -> Option<Self>;

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn spdm_read_bytes(context: &mut SpdmContext, bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::spdm_read(context, &mut rd)
    }
}

impl SpdmCodec for SpdmDigestStruct {
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        assert_eq!(self.data_size, context.get_hash_size());
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(self.data_size as usize)
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmDigestStruct> {
        let data_size = context.get_hash_size();
        let mut data = Box::new([0u8; SPDM_MAX_HASH_SIZE]);
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmDigestStruct { data_size, data })
    }
}

impl SpdmCodec for SpdmSignatureStruct {
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        assert_eq!(self.data_size, context.get_asym_key_size());
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(self.data_size as usize)
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmSignatureStruct> {
        let data_size = context.get_asym_key_size();
        let mut data = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmSignatureStruct { data_size, data })
    }
}

impl SpdmMeasurementRecordStructure {
    fn verify_measurement_record(&self, context: &mut SpdmContext) -> bool {
        let measurement_record_length = self.measurement_record_length.get() as usize;
        let mut reader = Reader::init(&self.measurement_record_data[..measurement_record_length]);

        let mut cur_index = 0u8;
        for _ in 0..self.number_of_blocks as usize {
            let measurement_block = SpdmMeasurementBlockStructure::spdm_read(context, &mut reader);
            if measurement_block.is_none() {
                return false;
            }
            let measurement_block = measurement_block.unwrap();
            if measurement_block.index <= cur_index {
                return false;
            }
            cur_index = measurement_block.index;
        }
        if reader.any_left() {
            return false;
        }
        true
    }
}

impl SpdmCodec for SpdmMeasurementRecordStructure {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .number_of_blocks
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .measurement_record_length
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        for d in self
            .measurement_record_data
            .iter()
            .take(self.measurement_record_length.get() as usize)
        {
            cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMeasurementRecordStructure> {
        let number_of_blocks = u8::read(r)?;
        let measurement_record_length = u24::read(r)?;
        if measurement_record_length.get() as usize > config::MAX_SPDM_MEASUREMENT_RECORD_SIZE {
            return None;
        }
        let mut measurement_record_data = [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE];
        for d in measurement_record_data
            .iter_mut()
            .take(measurement_record_length.get() as usize)
        {
            *d = u8::read(r)?;
        }

        let spdm_measurement_record = SpdmMeasurementRecordStructure {
            number_of_blocks,
            measurement_record_length,
            measurement_record_data,
        };
        if !spdm_measurement_record.verify_measurement_record(context) {
            return None;
        }

        Some(spdm_measurement_record)
    }
}

impl SpdmCodec for SpdmDheExchangeStruct {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(self.data_size as usize)
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmDheExchangeStruct> {
        let data_size = context.get_dhe_key_size();
        let mut data = [0u8; SPDM_MAX_DHE_KEY_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmDheExchangeStruct { data_size, data })
    }
}

impl SpdmCodec for SpdmDmtfMeasurementStructure {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        let type_value = self.r#type.get_u8();
        let representation_value = self.representation.get_u8();
        let final_value = type_value + representation_value;
        cnt += final_value
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        // TBD: Check measurement_hash

        cnt += self
            .value_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for v in self.value.iter().take(self.value_size as usize) {
            cnt += v.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmDmtfMeasurementStructure> {
        let final_value = u8::read(r)?;
        let type_value = final_value & 0x7f;
        let representation_value = final_value & 0x80;
        let representation = match representation_value {
            0 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            0x80 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
            _ => return None,
        };
        let r#type = match type_value {
            0 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            1 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
            2 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig,
            3 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig,
            4 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest,
            5 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementStructuredRepresentationMode
                }
                _ => return None,
            },
            6 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementMutableFirmwareVersionNumber
                }
                _ => return None,
            },
            7 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementMutableFirmwareSecurityVersionNumber
                }
                _ => return None,
            },
            val => SpdmDmtfMeasurementType::Unknown(val),
        };

        let value_size = u16::read(r)?;
        if value_size as usize > config::MAX_SPDM_MEASUREMENT_VALUE_LEN {
            return None;
        }

        let measurement_hash_algo = context.negotiate_info.measurement_hash_sel;
        if representation == SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
            && (value_size != measurement_hash_algo.get_size()
                || measurement_hash_algo == SpdmMeasurementHashAlgo::RAW_BIT_STREAM)
        {
            return None;
        }

        let mut value = [0u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
        for v in value.iter_mut().take(value_size as usize) {
            *v = u8::read(r)?;
        }
        Some(SpdmDmtfMeasurementStructure {
            r#type,
            representation,
            value_size,
            value,
        })
    }
}

impl SpdmCodec for SpdmMeasurementBlockStructure {
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .index
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .measurement_specification
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .measurement_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .measurement
            .spdm_encode(context, bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        Ok(cnt)
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMeasurementBlockStructure> {
        let index = u8::read(r)?;
        let measurement_specification = SpdmMeasurementSpecification::read(r)?;
        if measurement_specification != SpdmMeasurementSpecification::DMTF {
            return None;
        }
        let measurement_size = u16::read(r)?;
        if measurement_size as usize > 3 + config::MAX_SPDM_MEASUREMENT_VALUE_LEN {
            return None;
        }
        let measurement = SpdmDmtfMeasurementStructure::spdm_read(context, r)?;
        if measurement_size != 3 + measurement.value_size {
            return None;
        }
        Some(SpdmMeasurementBlockStructure {
            index,
            measurement_specification,
            measurement_size,
            measurement,
        })
    }
}
