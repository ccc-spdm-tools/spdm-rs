// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;

#[derive(Debug, PartialEq, Eq)]
pub struct CHALLENGE {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub Nonce: [u8; 32],
}

impl Codec for CHALLENGE {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self.Nonce.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let Nonce = <[u8; 32]>::read(reader)?;
        Some(CHALLENGE {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            Nonce,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CHALLENGE_AUTH {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub CertChainHash: Vec<u8>, // Size(bytes) H
    pub Nonce: [u8; 32],
    pub MeasurementSummaryHash: Vec<u8>,
    pub OpaqueDataLength: u16,
    pub OpaqueData: Vec<u8>,
    pub Signature: Vec<u8>, // Size(bytes) SigLen
}

impl CHALLENGE_AUTH {
    pub fn new(reader: &mut codec::Reader, H: usize, SigLen: usize) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let CertChainHash: Vec<u8> = Vec::<u8>::read_vec(reader, H)?;
        let Nonce = <[u8; 32]>::read(reader)?;
        let MeasurementSummaryHash: Vec<u8> = Vec::<u8>::read_vec(reader, H)?;
        let OpaqueDataLength = u16::read(reader)?;
        let OpaqueData: Vec<u8> = Vec::<u8>::read_vec(reader, OpaqueDataLength as usize)?;
        let Signature: Vec<u8> = Vec::<u8>::read_vec(reader, SigLen as usize)?;

        Some(CHALLENGE_AUTH {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            CertChainHash,
            Nonce,
            MeasurementSummaryHash,
            OpaqueDataLength,
            OpaqueData,
            Signature,
        })
    }
}

impl Codec for CHALLENGE_AUTH {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self.CertChainHash.encode(bytes)?;
        let _ = self.Nonce.encode(bytes)?;
        let _ = self.MeasurementSummaryHash.encode(bytes)?;
        let _ = self.OpaqueDataLength.encode(bytes)?;
        let _ = self.OpaqueData.encode(bytes)?;
        let _ = self.Signature.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(_: &mut codec::Reader) -> Option<Self> {
        // We don't know the size of H and SigLen in current context
        panic!("Not support, use CHALLENGE_AUTH::new instead!")
    }
}
