// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;

#[derive(Debug, PartialEq, Eq)]
pub struct GET_CAPABILITIES {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub _Reserved: u8,
    pub CTExponent: u8,
    pub _Reserved2: u16,
    pub Flags: u32,
    pub DataTransferSize: u32,
    pub MaxSPDMmsgSize: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CAPABILITIES {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub _Reserved: u8,
    pub CTExponent: u8,
    pub _Reserved2: u16,
    pub Flags: u32,
    pub DataTransferSize: u32,
    pub MaxSPDMmsgSize: u32,
}

impl Codec for GET_CAPABILITIES {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self._Reserved.encode(bytes)?;
        let _ = self.CTExponent.encode(bytes)?;
        let _ = self._Reserved2.encode(bytes)?;
        let _ = self.Flags.encode(bytes)?;
        let _ = self.DataTransferSize.encode(bytes)?;
        let _ = self.MaxSPDMmsgSize.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let _Reserved = u8::read(reader)?;
        let CTExponent = u8::read(reader)?;
        let _Reserved2 = u16::read(reader)?;
        let Flags = u32::read(reader)?;
        let DataTransferSize = u32::read(reader)?;
        let MaxSPDMmsgSize = u32::read(reader)?;
        Some(GET_CAPABILITIES {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            _Reserved,
            CTExponent,
            _Reserved2,
            Flags,
            DataTransferSize,
            MaxSPDMmsgSize,
        })
    }
}

impl Codec for CAPABILITIES {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self._Reserved.encode(bytes)?;
        let _ = self.CTExponent.encode(bytes)?;
        let _ = self._Reserved2.encode(bytes)?;
        let _ = self.Flags.encode(bytes)?;
        let _ = self.DataTransferSize.encode(bytes)?;
        let _ = self.MaxSPDMmsgSize.encode(bytes)?;
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let _Reserved = u8::read(reader)?;
        let CTExponent = u8::read(reader)?;
        let _Reserved2 = u16::read(reader)?;
        let Flags = u32::read(reader)?;
        let DataTransferSize = u32::read(reader)?;
        let MaxSPDMmsgSize = u32::read(reader)?;
        Some(CAPABILITIES {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            _Reserved,
            CTExponent,
            _Reserved2,
            Flags,
            DataTransferSize,
            MaxSPDMmsgSize,
        })
    }
}
