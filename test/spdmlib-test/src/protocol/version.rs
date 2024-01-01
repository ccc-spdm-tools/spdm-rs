// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// Follow SPDM spec field name.
use codec::Codec;

#[derive(Debug, PartialEq, Eq)]
pub struct GET_VERSION {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VERSION {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub Reserved: u8,
    pub VersionNumberEntryCount: u8,
    pub VersionNumberEntry: Vec<u16>,
}

impl Codec for GET_VERSION {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        Some(GET_VERSION {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
        })
    }
}

impl Codec for VERSION {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self.Reserved.encode(bytes)?;
        let _ = self.VersionNumberEntryCount.encode(bytes)?;
        let _ = self.VersionNumberEntry.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let Reserved = u8::read(reader)?;
        let VersionNumberEntryCount = u8::read(reader)?;
        let VersionNumberEntry = Vec::<u16>::read_vec(reader, VersionNumberEntryCount as usize)?;
        Some(VERSION {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            Reserved,
            VersionNumberEntryCount,
            VersionNumberEntry,
        })
    }
}
