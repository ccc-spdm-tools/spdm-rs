// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;

const ALG_STRUCT_SIZE: usize = 4usize;

#[derive(Debug, PartialEq, Eq)]
pub struct NEGOTIATE_ALGORITHMS {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub Length: u16,
    pub MeasurementSpecification: u8,
    pub OtherParamsSupport: u8,
    pub BaseAsymAlgo: u32,
    pub BaseHashAlgo: u32,
    pub _Reserved1: [u8; 12],
    pub ExtAsymCount: u8,
    pub ExtHashCount: u8,
    pub _Reserved2: [u8; 2],
    pub ExtAsym: Vec<u8>,
    pub Exthash: Vec<u8>,
    pub AlgStruct: Vec<[u8; ALG_STRUCT_SIZE]>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ALGORITHMS {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8, // number of AlgStruct
    pub Param2: u8,
    pub Length: u16,
    pub MeasurementSpecification: u8,
    pub OtherParamsSupport: u8,
    // Response have this extra(MeasurementHashAlgo) field than the requester
    pub MeasurementHashAlgo: u32,
    pub BaseAsymAlgo: u32,
    pub BaseHashAlgo: u32,
    pub _Reserved1: [u8; 12],
    pub ExtAsymCount: u8,
    pub ExtHashCount: u8,
    pub _Reserved2: [u8; 2],
    pub ExtAsym: Vec<u8>,
    pub Exthash: Vec<u8>,
    pub AlgStruct: Vec<[u8; ALG_STRUCT_SIZE]>,
}

impl Codec for NEGOTIATE_ALGORITHMS {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self.Length.encode(bytes)?;
        let _ = self.MeasurementSpecification.encode(bytes)?;
        let _ = self.OtherParamsSupport.encode(bytes)?;
        let _ = self.BaseAsymAlgo.encode(bytes)?;
        let _ = self.BaseHashAlgo.encode(bytes)?;
        let _ = self._Reserved1.encode(bytes)?;
        let _ = self.ExtAsymCount.encode(bytes)?;
        let _ = self.ExtHashCount.encode(bytes)?;
        let _ = self._Reserved2.encode(bytes)?;
        let _ = self.ExtAsym.encode(bytes)?;
        let _ = self.Exthash.encode(bytes)?;
        let _ = self.AlgStruct.encode(bytes)?;
        assert_eq!(bytes.used() - used, self.Length as usize);
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let Length = u16::read(reader)?;
        let MeasurementSpecification = u8::read(reader)?;
        let OtherParamsSupport = u8::read(reader)?;
        let BaseAsymAlgo = u32::read(reader)?;
        let BaseHashAlgo = u32::read(reader)?;
        let _Reserved1 = <[u8; 12]>::read(reader)?;
        let ExtAsymCount = u8::read(reader)?;
        let ExtHashCount = u8::read(reader)?;
        let _Reserved2 = <[u8; 2]>::read(reader)?;
        let ExtAsym: Vec<u8> = Vec::<u8>::read_vec(reader, ExtAsymCount as usize * 4)?;
        let Exthash: Vec<u8> = Vec::<u8>::read_vec(reader, ExtAsymCount as usize * 4)?;
        let AlgStruct = Vec::<[u8; ALG_STRUCT_SIZE]>::read_vec(reader, Param1 as usize)?;
        Some(NEGOTIATE_ALGORITHMS {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            Length,
            MeasurementSpecification,
            OtherParamsSupport,
            BaseAsymAlgo,
            BaseHashAlgo,
            _Reserved1,
            ExtAsymCount,
            ExtHashCount,
            _Reserved2,
            ExtAsym,
            Exthash,
            AlgStruct,
        })
    }
}

impl Codec for ALGORITHMS {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        let _ = self.Length.encode(bytes)?;
        let _ = self.MeasurementSpecification.encode(bytes)?;
        let _ = self.OtherParamsSupport.encode(bytes)?;
        let _ = self.MeasurementHashAlgo.encode(bytes)?;
        let _ = self.BaseAsymAlgo.encode(bytes)?;
        let _ = self.BaseHashAlgo.encode(bytes)?;
        let _ = self._Reserved1.encode(bytes)?;
        let _ = self.ExtAsymCount.encode(bytes)?;
        let _ = self.ExtHashCount.encode(bytes)?;
        let _ = self._Reserved2.encode(bytes)?;
        let _ = self.ExtAsym.encode(bytes)?;
        let _ = self.Exthash.encode(bytes)?;
        let _ = self.AlgStruct.encode(bytes)?;
        assert_eq!(bytes.used() - used, self.Length as usize);
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let Length = u16::read(reader)?;
        let MeasurementSpecification = u8::read(reader)?;
        let OtherParamsSupport = u8::read(reader)?;
        let MeasurementHashAlgo = u32::read(reader)?;
        let BaseAsymAlgo = u32::read(reader)?;
        let BaseHashAlgo = u32::read(reader)?;
        let _Reserved1 = <[u8; 12]>::read(reader)?;
        let ExtAsymCount = u8::read(reader)?;
        let ExtHashCount = u8::read(reader)?;
        let _Reserved2 = <[u8; 2]>::read(reader)?;
        let ExtAsym: Vec<u8> = Vec::<u8>::read_vec(reader, ExtAsymCount as usize * 4)?;
        let Exthash: Vec<u8> = Vec::<u8>::read_vec(reader, ExtAsymCount as usize * 4)?;
        let AlgStruct = Vec::<[u8; ALG_STRUCT_SIZE]>::read_vec(reader, Param1 as usize)?;
        Some(ALGORITHMS {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            Length,
            MeasurementSpecification,
            OtherParamsSupport,
            MeasurementHashAlgo,
            BaseAsymAlgo,
            BaseHashAlgo,
            _Reserved1,
            ExtAsymCount,
            ExtHashCount,
            _Reserved2,
            ExtAsym,
            Exthash,
            AlgStruct,
        })
    }
}
