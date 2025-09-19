// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

bitflags! {
    #[derive(Default)]
    pub struct SpdmRequestCapabilityFlags: u32 {
        const CERT_CAP                   =                               0b0000_0010;
        const CHAL_CAP                   =                               0b0000_0100;
        const ENCRYPT_CAP                =                               0b0100_0000;
        const MAC_CAP                    =                               0b1000_0000;
        const MUT_AUTH_CAP               =                     0b0000_0001_0000_0000;
        const KEY_EX_CAP                 =                     0b0000_0010_0000_0000;
        const PSK_CAP                    =                     0b0000_0100_0000_0000;
        const PSK_RSVD                   =                     0b0000_1000_0000_0000;
        const ENCAP_CAP                  =                     0b0001_0000_0000_0000;
        const HBEAT_CAP                  =                     0b0010_0000_0000_0000;
        const KEY_UPD_CAP                =                     0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP =                     0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP             =           0b0000_0001_0000_0000_0000_0000;
        const CHUNK_CAP                  =           0b0000_0010_0000_0000_0000_0000;
        const EP_INFO_CAP_NO_SIG         =           0b0100_0000_0000_0000_0000_0000;
        const EP_INFO_CAP_SIG            =           0b1000_0000_0000_0000_0000_0000;
        const EVENT_CAP                  = 0b0000_0010_0000_0000_0000_0000_0000_0000;
        const MULTI_KEY_CAP_ONLY         = 0b0000_0100_0000_0000_0000_0000_0000_0000;
        const MULTI_KEY_CAP_CONN_SEL     = 0b0000_1000_0000_0000_0000_0000_0000_0000;
        const LARGE_RESP_CAP             = 0b1000_0000_0000_0000_0000_0000_0000_0000;
        const VALID_MASK = Self::CERT_CAP.bits
            | Self::CHAL_CAP.bits
            | Self::ENCRYPT_CAP.bits
            | Self::MAC_CAP.bits
            | Self::MUT_AUTH_CAP.bits
            | Self::KEY_EX_CAP.bits
            | Self::PSK_CAP.bits
            | Self::PSK_RSVD.bits
            | Self::ENCAP_CAP.bits
            | Self::HBEAT_CAP.bits
            | Self::KEY_UPD_CAP.bits
            | Self::HANDSHAKE_IN_THE_CLEAR_CAP.bits
            | Self::PUB_KEY_ID_CAP.bits
            | Self::CHUNK_CAP.bits
            | Self::EP_INFO_CAP_NO_SIG.bits
            | Self::EP_INFO_CAP_SIG.bits
            | Self::EVENT_CAP.bits
            | Self::MULTI_KEY_CAP_ONLY.bits
            | Self::MULTI_KEY_CAP_CONN_SEL.bits
            | Self::LARGE_RESP_CAP.bits;
    }
}

impl Codec for SpdmRequestCapabilityFlags {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmRequestCapabilityFlags> {
        let bits = u32::read(r)?;

        SpdmRequestCapabilityFlags::from_bits(bits & SpdmRequestCapabilityFlags::VALID_MASK.bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmRequestCapabilityExFlags: u16 {
    }
}

impl Codec for SpdmRequestCapabilityExFlags {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmRequestCapabilityExFlags> {
        let _bits = u16::read(r)?;

        SpdmRequestCapabilityExFlags::from_bits(0)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmResponseCapabilityFlags: u32 {
        const CACHE_CAP                  =                               0b0000_0001;
        const CERT_CAP                   =                               0b0000_0010;
        const CHAL_CAP                   =                               0b0000_0100;
        const MEAS_CAP_NO_SIG            =                               0b0000_1000;
        const MEAS_CAP_SIG               =                               0b0001_0000;
        const MEAS_FRESH_CAP             =                               0b0010_0000;
        const ENCRYPT_CAP                =                               0b0100_0000;
        const MAC_CAP                    =                               0b1000_0000;
        const MUT_AUTH_CAP               =                     0b0000_0001_0000_0000;
        const KEY_EX_CAP                 =                     0b0000_0010_0000_0000;
        const PSK_CAP_WITHOUT_CONTEXT    =                     0b0000_0100_0000_0000;
        const PSK_CAP_WITH_CONTEXT       =                     0b0000_1000_0000_0000;
        const ENCAP_CAP                  =                     0b0001_0000_0000_0000;
        const HBEAT_CAP                  =                     0b0010_0000_0000_0000;
        const KEY_UPD_CAP                =                     0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP =                     0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP             =           0b0000_0001_0000_0000_0000_0000;
        const CHUNK_CAP                  =           0b0000_0010_0000_0000_0000_0000;
        const ALIAS_CERT_CAP             =           0b0000_0100_0000_0000_0000_0000;
        const SET_CERT_CAP               =           0b0000_1000_0000_0000_0000_0000;
        const CSR_CAP                    =           0b0001_0000_0000_0000_0000_0000;
        const CERT_INSTALL_RESET_CAP     =           0b0010_0000_0000_0000_0000_0000;
        const EP_INFO_CAP_NO_SIG         =           0b0100_0000_0000_0000_0000_0000;
        const EP_INFO_CAP_SIG            =           0b1000_0000_0000_0000_0000_0000;
        const MEL_CAP                    = 0b0000_0001_0000_0000_0000_0000_0000_0000;
        const EVENT_CAP                  = 0b0000_0010_0000_0000_0000_0000_0000_0000;
        const MULTI_KEY_CAP_ONLY         = 0b0000_0100_0000_0000_0000_0000_0000_0000;
        const MULTI_KEY_CAP_CONN_SEL     = 0b0000_1000_0000_0000_0000_0000_0000_0000;
        const GET_KEY_PAIR_INFO_CAP      = 0b0001_0000_0000_0000_0000_0000_0000_0000;
        const SET_KEY_PAIR_INFO_CAP      = 0b0010_0000_0000_0000_0000_0000_0000_0000;
        const SET_KEY_PAIR_RESET_CAP     = 0b0100_0000_0000_0000_0000_0000_0000_0000;
        const LARGE_RESP_CAP             = 0b1000_0000_0000_0000_0000_0000_0000_0000;
        const VALID_MASK = Self::CACHE_CAP.bits
            | Self::CERT_CAP.bits
            | Self::CHAL_CAP.bits
            | Self::MEAS_CAP_NO_SIG.bits
            | Self::MEAS_CAP_SIG.bits
            | Self::MEAS_FRESH_CAP.bits
            | Self::ENCRYPT_CAP.bits
            | Self::MAC_CAP.bits
            | Self::MUT_AUTH_CAP.bits
            | Self::KEY_EX_CAP.bits
            | Self::PSK_CAP_WITHOUT_CONTEXT.bits
            | Self::PSK_CAP_WITH_CONTEXT.bits
            | Self::ENCAP_CAP.bits
            | Self::HBEAT_CAP.bits
            | Self::KEY_UPD_CAP.bits
            | Self::HANDSHAKE_IN_THE_CLEAR_CAP.bits
            | Self::PUB_KEY_ID_CAP.bits
            | Self::CHUNK_CAP.bits
            | Self::ALIAS_CERT_CAP.bits
            | Self::SET_CERT_CAP.bits
            | Self::CSR_CAP.bits
            | Self::CERT_INSTALL_RESET_CAP.bits
            | Self::EP_INFO_CAP_NO_SIG.bits
            | Self::EP_INFO_CAP_SIG.bits
            | Self::MEL_CAP.bits
            | Self::EVENT_CAP.bits
            | Self::MULTI_KEY_CAP_ONLY.bits
            | Self::MULTI_KEY_CAP_CONN_SEL.bits
            | Self::GET_KEY_PAIR_INFO_CAP.bits
            | Self::SET_KEY_PAIR_INFO_CAP.bits
            | Self::SET_KEY_PAIR_RESET_CAP.bits
            | Self::LARGE_RESP_CAP.bits;
    }
}

impl Codec for SpdmResponseCapabilityFlags {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmResponseCapabilityFlags> {
        let bits = u32::read(r)?;

        SpdmResponseCapabilityFlags::from_bits(bits & SpdmResponseCapabilityFlags::VALID_MASK.bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmResponseCapabilityExFlags: u16 {
        const SLOT_MGMT_CAP = 0b0000_0001;
        const VALID_MASK = Self::SLOT_MGMT_CAP.bits;
    }
}

impl Codec for SpdmResponseCapabilityExFlags {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmResponseCapabilityExFlags> {
        let bits = u16::read(r)?;

        SpdmResponseCapabilityExFlags::from_bits(
            bits & SpdmResponseCapabilityExFlags::VALID_MASK.bits,
        )
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmCapabilityParam1: u8 {
        const SUPPORTED_ALGOS_EXT_CAP = 0b0000_0001;
        const VALID_MASK = Self::SUPPORTED_ALGOS_EXT_CAP.bits;
    }
}

impl Codec for SpdmCapabilityParam1 {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmCapabilityParam1> {
        let bits = u8::read(r)?;

        SpdmCapabilityParam1::from_bits(bits & SpdmCapabilityParam1::VALID_MASK.bits)
    }
}
