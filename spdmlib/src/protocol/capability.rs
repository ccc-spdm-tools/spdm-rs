// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

bitflags! {
    #[derive(Default)]
    pub struct SpdmRequestCapabilityFlags: u32 {
        const CERT_CAP = 0b0000_0010;
        const CHAL_CAP = 0b0000_0100;
        const ENCRYPT_CAP = 0b0100_0000;
        const MAC_CAP = 0b1000_0000;
        const MUT_AUTH_CAP = 0b0000_0001_0000_0000;
        const KEY_EX_CAP = 0b0000_0010_0000_0000;
        const PSK_CAP = 0b0000_0100_0000_0000;
        const PSK_RSVD = 0b0000_1000_0000_0000;
        const ENCAP_CAP = 0b0001_0000_0000_0000;
        const HBEAT_CAP = 0b0010_0000_0000_0000;
        const KEY_UPD_CAP = 0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP = 0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP = 0b0000_0001_0000_0000_0000_0000;
        const CHUNK_CAP = 0b0000_0010_0000_0000_0000_0000;
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
            | Self::CHUNK_CAP.bits;
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
    pub struct SpdmResponseCapabilityFlags: u32 {
        const CACHE_CAP = 0b0000_0001;
        const CERT_CAP = 0b0000_0010;
        const CHAL_CAP = 0b0000_0100;
        const MEAS_CAP_NO_SIG = 0b0000_1000;
        const MEAS_CAP_SIG = 0b0001_0000;
        const MEAS_FRESH_CAP = 0b0010_0000;
        const ENCRYPT_CAP = 0b0100_0000;
        const MAC_CAP = 0b1000_0000;
        const MUT_AUTH_CAP = 0b0000_0001_0000_0000;
        const KEY_EX_CAP = 0b0000_0010_0000_0000;
        const PSK_CAP_WITHOUT_CONTEXT = 0b0000_0100_0000_0000;
        const PSK_CAP_WITH_CONTEXT = 0b0000_1000_0000_0000;
        const ENCAP_CAP = 0b0001_0000_0000_0000;
        const HBEAT_CAP = 0b0010_0000_0000_0000;
        const KEY_UPD_CAP = 0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP = 0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP = 0b0000_0001_0000_0000_0000_0000;
        const CHUNK_CAP = 0b0000_0010_0000_0000_0000_0000;
        const ALIAS_CERT_CAP = 0b0000_0100_0000_0000_0000_0000;
        const SET_CERT_CAP = 0b0000_1000_0000_0000_0000_0000;
        const CSR_CAP = 0b0001_0000_0000_0000_0000_0000;
        const CERT_INSTALL_RESET_CAP = 0b0010_0000_0000_0000_0000_0000;
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
            | Self::CERT_INSTALL_RESET_CAP.bits;
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
