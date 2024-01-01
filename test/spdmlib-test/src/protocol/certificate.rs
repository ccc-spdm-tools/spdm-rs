// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;

#[derive(Debug, PartialEq, Eq)]
pub struct GET_CERTIFICATE {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub Offset: u16,
    pub Length: u16,
}

impl Codec for GET_CERTIFICATE {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self.Offset.encode(bytes)?;
        let _ = self.Length.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let Offset = u16::read(reader)?;
        let Length = u16::read(reader)?;
        Some(GET_CERTIFICATE {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            Offset,
            Length,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CERTIFICATE {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub PortionLength: u16,
    pub RemainderLength: u16,
    pub CertChain: Vec<u8>,
}

impl Codec for CERTIFICATE {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self.PortionLength.encode(bytes)?;
        let _ = self.RemainderLength.encode(bytes)?;
        let _ = self.CertChain.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let PortionLength = u16::read(reader)?;
        let RemainderLength = u16::read(reader)?;
        let CertChain = Vec::<u8>::read_vec(reader, PortionLength as usize)?;

        Some(CERTIFICATE {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            PortionLength,
            RemainderLength,
            CertChain,
        })
    }
}
