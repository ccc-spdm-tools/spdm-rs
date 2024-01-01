// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{u24, Codec};

#[derive(Debug, PartialEq, Eq)]
pub struct GET_MEASUREMENTS {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub Nonce: Option<Vec<u8>>,
    pub SlotIDParam: Option<u8>,
}

const NONCE_LEN: usize = 32;

impl Codec for GET_MEASUREMENTS {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        if self.Param1 & 0b1 == 0b1 {
            let _ = self.Nonce.as_ref().ok_or(codec::EncodeErr)?.encode(bytes)?;
            let _ = self.SlotIDParam.ok_or(codec::EncodeErr)?.encode(bytes)?;
        }
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let (Nonce, SlotIDParam) = if Param1 & 0b1 == 0b1 {
            // This field is only present if Bit [0] of Param1 is 1
            (
                Some(Vec::<u8>::read_vec(reader, NONCE_LEN)?),
                Some(u8::read(reader)?),
            )
        } else {
            (None, None)
        };

        Some(GET_MEASUREMENTS {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            Nonce,
            SlotIDParam,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MEASUREMENTS {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub NumberOfBlocks: u8,
    pub MeasurementRecordLength: u32, // This field size is 3 bytes
    pub MeasurementRecordData: Vec<u8>,
    pub Nonce: [u8; 32],
    pub OpaqueDataLength: u16,
    pub OpaqueData: Vec<u8>,
    pub Signature: Vec<u8>,
}

impl MEASUREMENTS {
    pub fn new(reader: &mut codec::Reader, SigLen: usize) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let NumberOfBlocks = u8::read(reader)?;
        let MeasurementRecordLength = u24::read(reader)?.get();
        let MeasurementRecordData: Vec<u8> =
            Vec::<u8>::read_vec(reader, MeasurementRecordLength as usize)?;
        let Nonce = <[u8; NONCE_LEN]>::read(reader)?;
        let OpaqueDataLength = u16::read(reader)?;
        let OpaqueData: Vec<u8> = Vec::<u8>::read_vec(reader, OpaqueDataLength as usize)?;
        let Signature: Vec<u8> = Vec::<u8>::read_vec(reader, SigLen)?;

        Some(MEASUREMENTS {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            NumberOfBlocks,
            MeasurementRecordLength,
            MeasurementRecordData,
            Nonce,
            OpaqueDataLength,
            OpaqueData,
            Signature,
        })
    }
}

impl Codec for MEASUREMENTS {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self.NumberOfBlocks.encode(bytes)?;
        let _ = u24::new(self.MeasurementRecordLength).encode(bytes)?;
        let _ = self.MeasurementRecordData.encode(bytes)?;
        let _ = self.Nonce.encode(bytes)?;
        let _ = self.OpaqueDataLength.encode(bytes)?;
        let _ = self.OpaqueData.encode(bytes)?;
        let _ = self.Signature.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(_reader: &mut codec::Reader) -> Option<Self> {
        panic!("Not support, use MEASUREMENTS::new instead!")
    }
}
