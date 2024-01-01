// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;
#[derive(Debug, PartialEq, Eq)]
pub struct GET_DIGESTS {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
}

impl Codec for GET_DIGESTS {
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
        Some(GET_DIGESTS {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DIGESTS {
    pub SPDMVersion: u8,
    pub RequestResponseCode: u8,
    pub Param1: u8,
    pub Param2: u8,
    pub Digest: Vec<Vec<u8>>,
}

impl DIGESTS {
    pub fn new(reader: &mut codec::Reader, H: usize) -> Option<Self> {
        let SPDMVersion = u8::read(reader)?;
        let RequestResponseCode = u8::read(reader)?;
        let Param1 = u8::read(reader)?;
        let Param2 = u8::read(reader)?;
        let count = Param2.count_ones();
        let mut Digest = Vec::new();
        for _ in 0..count {
            let CertChainHash: Vec<u8> = Vec::<u8>::read_vec(reader, H)?;
            Digest.push(CertChainHash);
        }

        Some(DIGESTS {
            SPDMVersion,
            RequestResponseCode,
            Param1,
            Param2,
            Digest,
        })
    }
}

impl Codec for DIGESTS {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let used = bytes.used();
        let _ = self.SPDMVersion.encode(bytes)?;
        let _ = self.RequestResponseCode.encode(bytes)?;
        let _ = self.Param1.encode(bytes)?;
        let _ = self.Param2.encode(bytes)?;
        for d in self.Digest.as_slice() {
            let _ = d.encode(bytes)?;
        }
        Ok(bytes.used() - used)
    }

    fn read(_: &mut codec::Reader) -> Option<Self> {
        // We don't know the size of H and SigLen in current context
        panic!("Not support, use CHALLENGE_AUTH::new instead!")
    }
}

#[test]
fn test() {
    let number: u8 = 0b1010_1100; // Example u8 with 8 bits

    // Iterate over each bit from right to left
    for i in (0..8).rev() {
        let bit = (number >> i) & 1;
        println!("Bit {} is {}", i, bit);
    }
}
