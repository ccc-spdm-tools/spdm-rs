// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::config;
use crate::crypto::bytes_mut_scrubbed::BytesMutStrubbed;
use bytes::BytesMut;
use codec::{enum_builder, u24, Codec, Reader, Writer};
use core::convert::From;
extern crate alloc;
use alloc::boxed::Box;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SHA256_DIGEST_SIZE: usize = 32;
pub const SHA384_DIGEST_SIZE: usize = 48;
pub const SHA512_DIGEST_SIZE: usize = 64;

pub const RSASSA_2048_KEY_SIZE: usize = 256;
pub const RSASSA_3072_KEY_SIZE: usize = 384;
pub const RSASSA_4096_KEY_SIZE: usize = 512;
pub const RSAPSS_2048_KEY_SIZE: usize = 256;
pub const RSAPSS_3072_KEY_SIZE: usize = 384;
pub const RSAPSS_4096_KEY_SIZE: usize = 512;

pub const ECDSA_ECC_NIST_P256_KEY_SIZE: usize = 32 * 2;
pub const ECDSA_ECC_NIST_P384_KEY_SIZE: usize = 48 * 2;

pub const SECP_256_R1_KEY_SIZE: usize = 32 * 2;
pub const SECP_384_R1_KEY_SIZE: usize = 48 * 2;

pub const AEAD_AES_128_GCM_KEY_SIZE: usize = 16;
pub const AEAD_AES_256_GCM_KEY_SIZE: usize = 32;
pub const AEAD_CHACHA20_POLY1305_KEY_SIZE: usize = 32;

pub const AEAD_AES_128_GCM_BLOCK_SIZE: usize = 16;
pub const AEAD_AES_256_GCM_BLOCK_SIZE: usize = 16;
pub const AEAD_CHACHA20_POLY1305_BLOCK_SIZE: usize = 16;

pub const AEAD_AES_128_GCM_IV_SIZE: usize = 12;
pub const AEAD_AES_256_GCM_IV_SIZE: usize = 12;
pub const AEAD_CHACHA20_POLY1305_IV_SIZE: usize = 12;

pub const AEAD_AES_128_GCM_TAG_SIZE: usize = 16;
pub const AEAD_AES_256_GCM_TAG_SIZE: usize = 16;
pub const AEAD_CHACHA20_POLY1305_TAG_SIZE: usize = 16;

pub const SPDM_NONCE_SIZE: usize = 32;
pub const SPDM_RANDOM_SIZE: usize = 32;
pub const SPDM_MAX_HASH_SIZE: usize = 64;
pub const SPDM_MAX_ASYM_KEY_SIZE: usize = 512;
pub const SPDM_MAX_DHE_KEY_SIZE: usize = SECP_384_R1_KEY_SIZE;
pub const SPDM_MAX_AEAD_KEY_SIZE: usize = 32;
pub const SPDM_MAX_AEAD_IV_SIZE: usize = 12;
pub const SPDM_MAX_HKDF_OKM_SIZE: usize = SPDM_MAX_HASH_SIZE;

bitflags! {
    #[derive(Default)]
    pub struct SpdmMeasurementSpecification: u8 {
        const DMTF = 0b0000_0001;
        const VALID_MASK = Self::DMTF.bits;
    }
}

impl Codec for SpdmMeasurementSpecification {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmMeasurementSpecification> {
        let bits = u8::read(r)?;
        SpdmMeasurementSpecification::from_bits(
            bits & SpdmMeasurementSpecification::VALID_MASK.bits,
        )
    }
}
impl SpdmMeasurementSpecification {
    pub fn prioritize(&mut self, peer: SpdmMeasurementSpecification) {
        let prio_table = [SpdmMeasurementSpecification::DMTF];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmMeasurementSpecification::empty();
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmMeasurementHashAlgo: u32 {
        const RAW_BIT_STREAM = 0b0000_0001;
        const TPM_ALG_SHA_256 = 0b0000_0010;
        const TPM_ALG_SHA_384 = 0b0000_0100;
        const TPM_ALG_SHA_512 = 0b0000_1000;
        const TPM_ALG_SHA3_256 = 0b0001_0000;
        const TPM_ALG_SHA3_384 = 0b0010_0000;
        const TPM_ALG_SHA3_512 = 0b0100_0000;
        const TPM_ALG_SM3 = 0b1000_0000;
        const VALID_MASK = Self::RAW_BIT_STREAM.bits
            | Self::TPM_ALG_SHA_256.bits
            | Self::TPM_ALG_SHA_384.bits
            | Self::TPM_ALG_SHA_512.bits
            | Self::TPM_ALG_SHA3_256.bits
            | Self::TPM_ALG_SHA3_256.bits
            | Self::TPM_ALG_SHA3_256.bits
            | Self::TPM_ALG_SM3.bits;
    }
}

impl SpdmMeasurementHashAlgo {
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmMeasurementHashAlgo::RAW_BIT_STREAM => 0u16,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_256 => SHA256_DIGEST_SIZE as u16,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384 => SHA384_DIGEST_SIZE as u16,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_512 => SHA512_DIGEST_SIZE as u16,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA3_256 => 32,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA3_384 => 48,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA3_512 => 64,
            SpdmMeasurementHashAlgo::TPM_ALG_SM3 => 32,
            _ => {
                panic!("invalid MeasurementHashAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}
impl Codec for SpdmMeasurementHashAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmMeasurementHashAlgo> {
        let bits = u32::read(r)?;

        SpdmMeasurementHashAlgo::from_bits(bits & SpdmMeasurementHashAlgo::VALID_MASK.bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmBaseAsymAlgo: u32 {
        const TPM_ALG_RSASSA_2048 = 0b0000_0001;
        const TPM_ALG_RSAPSS_2048 = 0b0000_0010;
        const TPM_ALG_RSASSA_3072 = 0b0000_0100;
        const TPM_ALG_RSAPSS_3072 = 0b0000_1000;
        const TPM_ALG_ECDSA_ECC_NIST_P256 = 0b0001_0000;
        const TPM_ALG_RSASSA_4096 = 0b0010_0000;
        const TPM_ALG_RSAPSS_4096 = 0b0100_0000;
        const TPM_ALG_ECDSA_ECC_NIST_P384 = 0b1000_0000;
        const VALID_MASK = Self::TPM_ALG_RSASSA_2048.bits
            | Self::TPM_ALG_RSAPSS_2048.bits
            | Self::TPM_ALG_RSASSA_3072.bits
            | Self::TPM_ALG_RSAPSS_3072.bits
            | Self::TPM_ALG_ECDSA_ECC_NIST_P256.bits
            | Self::TPM_ALG_RSASSA_4096.bits
            | Self::TPM_ALG_RSAPSS_4096.bits
            | Self::TPM_ALG_ECDSA_ECC_NIST_P384.bits;
    }
}

impl SpdmBaseAsymAlgo {
    pub fn prioritize(&mut self, peer: SpdmBaseAsymAlgo) {
        let prio_table = [
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
        ];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmBaseAsymAlgo::empty();
    }
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048 => RSASSA_2048_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048 => RSAPSS_2048_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072 => RSASSA_3072_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072 => RSAPSS_3072_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => RSASSA_4096_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096 => RSAPSS_4096_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256 => ECDSA_ECC_NIST_P256_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => ECDSA_ECC_NIST_P384_KEY_SIZE as u16,
            _ => {
                panic!("invalid AsymAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}

impl Codec for SpdmBaseAsymAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmBaseAsymAlgo> {
        let bits = u32::read(r)?;

        SpdmBaseAsymAlgo::from_bits(bits & SpdmBaseAsymAlgo::VALID_MASK.bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmBaseHashAlgo: u32 {
        const TPM_ALG_SHA_256 = 0b0000_0001;
        const TPM_ALG_SHA_384 = 0b0000_0010;
        const TPM_ALG_SHA_512 = 0b0000_0100;
        const VALID_MASK = Self::TPM_ALG_SHA_256.bits
            | Self::TPM_ALG_SHA_384.bits
            | Self::TPM_ALG_SHA_512.bits;
    }
}

impl SpdmBaseHashAlgo {
    pub fn prioritize(&mut self, peer: SpdmBaseHashAlgo) {
        let prio_table = [
            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        ];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmBaseHashAlgo::empty();
    }
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => SHA256_DIGEST_SIZE as u16,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => SHA384_DIGEST_SIZE as u16,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => SHA512_DIGEST_SIZE as u16,
            _ => {
                panic!("invalid HashAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}

impl Codec for SpdmBaseHashAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmBaseHashAlgo> {
        let bits = u32::read(r)?;

        SpdmBaseHashAlgo::from_bits(bits & SpdmBaseHashAlgo::VALID_MASK.bits)
    }
}

enum_builder! {
    @U8
    EnumName: SpdmStandardId;
    EnumVal{
        SpdmStandardIdDMTF => 0x0,
        SpdmStandardIdTCG => 0x1,
        SpdmStandardIdUSB => 0x2,
        SpdmStandardIdPCISIG => 0x3,
        SpdmStandardIdIANA => 0x4,
        SpdmStandardIdHDBaseT => 0x5,
        SpdmStandardIdMIPI => 0x6,
        SpdmStandardIdCXL => 0x7,
        SpdmStandardIdJDEC => 0x8
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmDheAlgo: u16 {
        const SECP_256_R1 = 0b0000_1000;
        const SECP_384_R1 = 0b0001_0000;
        const VALID_MASK = Self::SECP_256_R1.bits
            | Self::SECP_384_R1.bits;
    }
}

impl SpdmDheAlgo {
    pub fn prioritize(&mut self, peer: SpdmDheAlgo) {
        let prio_table = [SpdmDheAlgo::SECP_384_R1, SpdmDheAlgo::SECP_256_R1];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmDheAlgo::empty();
    }
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmDheAlgo::SECP_256_R1 => SECP_256_R1_KEY_SIZE as u16,
            SpdmDheAlgo::SECP_384_R1 => SECP_384_R1_KEY_SIZE as u16,
            _ => {
                panic!("invalid DheAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}

impl Codec for SpdmDheAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmDheAlgo> {
        let bits = u16::read(r)?;

        SpdmDheAlgo::from_bits(bits & SpdmDheAlgo::VALID_MASK.bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmAeadAlgo: u16 {
        const AES_128_GCM = 0b0000_0001;
        const AES_256_GCM = 0b0000_0010;
        const CHACHA20_POLY1305 = 0b0000_0100;
        const VALID_MASK = Self::AES_128_GCM.bits
            | Self::AES_256_GCM.bits
            | Self::CHACHA20_POLY1305.bits;
    }
}

impl SpdmAeadAlgo {
    pub fn prioritize(&mut self, peer: SpdmAeadAlgo) {
        let prio_table = [
            SpdmAeadAlgo::AES_256_GCM,
            SpdmAeadAlgo::AES_128_GCM,
            SpdmAeadAlgo::CHACHA20_POLY1305,
        ];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmAeadAlgo::empty();
    }
    pub fn get_key_size(&self) -> u16 {
        match *self {
            SpdmAeadAlgo::AES_128_GCM => AEAD_AES_128_GCM_KEY_SIZE as u16,
            SpdmAeadAlgo::AES_256_GCM => AEAD_AES_256_GCM_KEY_SIZE as u16,
            SpdmAeadAlgo::CHACHA20_POLY1305 => AEAD_CHACHA20_POLY1305_KEY_SIZE as u16,
            _ => {
                panic!("invalid AeadAlgo");
            }
        }
    }
    pub fn get_iv_size(&self) -> u16 {
        match *self {
            SpdmAeadAlgo::AES_128_GCM => AEAD_AES_128_GCM_IV_SIZE as u16,
            SpdmAeadAlgo::AES_256_GCM => AEAD_AES_256_GCM_IV_SIZE as u16,
            SpdmAeadAlgo::CHACHA20_POLY1305 => AEAD_CHACHA20_POLY1305_IV_SIZE as u16,
            _ => {
                panic!("invalid AeadAlgo");
            }
        }
    }
    pub fn get_tag_size(&self) -> u16 {
        match *self {
            SpdmAeadAlgo::AES_128_GCM => AEAD_AES_128_GCM_TAG_SIZE as u16,
            SpdmAeadAlgo::AES_256_GCM => AEAD_AES_256_GCM_TAG_SIZE as u16,
            SpdmAeadAlgo::CHACHA20_POLY1305 => AEAD_CHACHA20_POLY1305_TAG_SIZE as u16,
            _ => {
                panic!("invalid AeadAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}

impl Codec for SpdmAeadAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmAeadAlgo> {
        let bits = u16::read(r)?;

        SpdmAeadAlgo::from_bits(bits & SpdmAeadAlgo::VALID_MASK.bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmReqAsymAlgo: u16 {
        const TPM_ALG_RSASSA_2048 = 0b0000_0001;
        const TPM_ALG_RSAPSS_2048 = 0b0000_0010;
        const TPM_ALG_RSASSA_3072 = 0b0000_0100;
        const TPM_ALG_RSAPSS_3072 = 0b0000_1000;
        const TPM_ALG_ECDSA_ECC_NIST_P256 = 0b0001_0000;
        const TPM_ALG_RSASSA_4096 = 0b0010_0000;
        const TPM_ALG_RSAPSS_4096 = 0b0100_0000;
        const TPM_ALG_ECDSA_ECC_NIST_P384 = 0b1000_0000;
        const VALID_MASK = Self::TPM_ALG_RSASSA_2048.bits
            | Self::TPM_ALG_RSAPSS_2048.bits
            | Self::TPM_ALG_RSASSA_3072.bits
            | Self::TPM_ALG_RSAPSS_3072.bits
            | Self::TPM_ALG_ECDSA_ECC_NIST_P256.bits
            | Self::TPM_ALG_RSASSA_4096.bits
            | Self::TPM_ALG_RSAPSS_4096.bits
            | Self::TPM_ALG_ECDSA_ECC_NIST_P384.bits;
    }
}

impl SpdmReqAsymAlgo {
    pub fn prioritize(&mut self, peer: SpdmReqAsymAlgo) {
        let prio_table = [
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_4096,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_3072,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_4096,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048,
        ];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmReqAsymAlgo::empty();
    }
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048 => RSASSA_2048_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048 => RSAPSS_2048_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072 => RSASSA_3072_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_3072 => RSAPSS_3072_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_4096 => RSASSA_4096_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_4096 => RSAPSS_4096_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256 => ECDSA_ECC_NIST_P256_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => ECDSA_ECC_NIST_P384_KEY_SIZE as u16,
            _ => {
                panic!("invalid ReqAsymAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}

impl Codec for SpdmReqAsymAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmReqAsymAlgo> {
        let bits = u16::read(r)?;

        SpdmReqAsymAlgo::from_bits(bits & SpdmReqAsymAlgo::VALID_MASK.bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmKeyScheduleAlgo: u16 {
        const SPDM_KEY_SCHEDULE = 0b0000_0001;
        const VALID_MASK = Self::SPDM_KEY_SCHEDULE.bits;
    }
}

impl SpdmKeyScheduleAlgo {
    pub fn prioritize(&mut self, peer: SpdmKeyScheduleAlgo) {
        let prio_table = [SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmKeyScheduleAlgo::empty();
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}

impl Codec for SpdmKeyScheduleAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmKeyScheduleAlgo> {
        let bits = u16::read(r)?;

        SpdmKeyScheduleAlgo::from_bits(bits & SpdmKeyScheduleAlgo::VALID_MASK.bits)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpdmUnknownAlgo {}
impl Codec for SpdmUnknownAlgo {
    fn encode(&self, _bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        Ok(0)
    }

    fn read(_r: &mut Reader) -> Option<SpdmUnknownAlgo> {
        Some(SpdmUnknownAlgo {})
    }
}

enum_builder! {
    @U8
    EnumName: SpdmAlgType;
    EnumVal{
        SpdmAlgTypeDHE => 0x2,
        SpdmAlgTypeAEAD => 0x3,
        SpdmAlgTypeReqAsym => 0x4,
        SpdmAlgTypeKeySchedule => 0x5
    }
}
impl Default for SpdmAlgType {
    fn default() -> SpdmAlgType {
        SpdmAlgType::Unknown(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpdmAlg {
    SpdmAlgoDhe(SpdmDheAlgo),
    SpdmAlgoAead(SpdmAeadAlgo),
    SpdmAlgoReqAsym(SpdmReqAsymAlgo),
    SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo),
    // TBD: Need consider how to handle this SpdmAlgoUnknown
    SpdmAlgoUnknown(SpdmUnknownAlgo),
}
impl Default for SpdmAlg {
    fn default() -> SpdmAlg {
        SpdmAlg::SpdmAlgoUnknown(SpdmUnknownAlgo {})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmAlgStruct {
    pub alg_type: SpdmAlgType,
    pub alg_supported: SpdmAlg,
}

impl Codec for SpdmAlgStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        // DSP0274 Table: Algorithm request structure
        let alg_fixed_count = 2u8;
        cnt += self.alg_type.encode(bytes)?;
        let alg_count = ((alg_fixed_count as u32) << 4) as u8;
        cnt += alg_count.encode(bytes)?;

        match &self.alg_supported {
            SpdmAlg::SpdmAlgoDhe(alg_supported) => {
                cnt += alg_supported.encode(bytes)?;
            }
            SpdmAlg::SpdmAlgoAead(alg_supported) => {
                cnt += alg_supported.encode(bytes)?;
            }
            SpdmAlg::SpdmAlgoReqAsym(alg_supported) => {
                cnt += alg_supported.encode(bytes)?;
            }
            SpdmAlg::SpdmAlgoKeySchedule(alg_supported) => {
                cnt += alg_supported.encode(bytes)?;
            }
            SpdmAlg::SpdmAlgoUnknown(alg_supported) => {
                cnt += alg_supported.encode(bytes)?;
            }
        }
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<SpdmAlgStruct> {
        let alg_type = SpdmAlgType::read(r)?;
        let alg_count = u8::read(r)?;
        let alg_fixed_count = ((alg_count as u32 >> 4) & 0xF) as u8;
        let alg_ext_count = alg_count & 0xF;
        if alg_fixed_count != 2 {
            return None;
        }
        if alg_ext_count != 0 {
            return None;
        }

        let alg_supported = match alg_type {
            SpdmAlgType::SpdmAlgTypeDHE => Some(SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::read(r)?)),
            SpdmAlgType::SpdmAlgTypeAEAD => Some(SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::read(r)?)),
            SpdmAlgType::SpdmAlgTypeReqAsym => {
                Some(SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::read(r)?))
            }
            SpdmAlgType::SpdmAlgTypeKeySchedule => {
                Some(SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::read(r)?))
            }
            _ => return None,
        };

        let alg_supported = alg_supported?;

        Some(SpdmAlgStruct {
            alg_type,
            alg_supported,
        })
    }
}

pub const SPDM_MAX_SLOT_NUMBER: usize = 8;

enum_builder! {
    @U8
    EnumName: SpdmMeasurementSummaryHashType;
    EnumVal{
        SpdmMeasurementSummaryHashTypeNone => 0x0,
        SpdmMeasurementSummaryHashTypeTcb => 0x1,
        SpdmMeasurementSummaryHashTypeAll => 0xFF
    }
}
impl Default for SpdmMeasurementSummaryHashType {
    fn default() -> SpdmMeasurementSummaryHashType {
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmNonceStruct {
    pub data: [u8; SPDM_NONCE_SIZE],
}

impl Codec for SpdmNonceStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        for d in self.data.iter() {
            d.encode(bytes)?;
        }
        Ok(SPDM_NONCE_SIZE)
    }
    fn read(r: &mut Reader) -> Option<SpdmNonceStruct> {
        let mut data = [0u8; SPDM_NONCE_SIZE];
        for d in data.iter_mut() {
            *d = u8::read(r)?;
        }
        Some(SpdmNonceStruct { data })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmRandomStruct {
    pub data: [u8; SPDM_RANDOM_SIZE],
}

impl Codec for SpdmRandomStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        for d in self.data.iter() {
            d.encode(bytes)?;
        }
        Ok(SPDM_RANDOM_SIZE)
    }
    fn read(r: &mut Reader) -> Option<SpdmRandomStruct> {
        let mut data = [0u8; SPDM_RANDOM_SIZE];
        for d in data.iter_mut() {
            *d = u8::read(r)?;
        }
        Some(SpdmRandomStruct { data })
    }
}

#[derive(Debug, Clone)]
pub struct SpdmSignatureStruct {
    pub data_size: u16,
    pub data: [u8; SPDM_MAX_ASYM_KEY_SIZE],
}
impl Default for SpdmSignatureStruct {
    fn default() -> SpdmSignatureStruct {
        SpdmSignatureStruct {
            data_size: 0,
            data: [0u8; SPDM_MAX_ASYM_KEY_SIZE],
        }
    }
}

impl AsRef<[u8]> for SpdmSignatureStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

impl From<BytesMut> for SpdmSignatureStruct {
    fn from(value: BytesMut) -> Self {
        assert!(value.as_ref().len() <= SPDM_MAX_ASYM_KEY_SIZE);
        let data_size = value.as_ref().len() as u16;
        let mut data = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
        data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

#[derive(Debug, Clone)]
pub struct SpdmCertChainData {
    pub data_size: u16,
    pub data: [u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
}

impl Default for SpdmCertChainData {
    fn default() -> Self {
        SpdmCertChainData {
            data_size: 0u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        }
    }
}
impl AsRef<[u8]> for SpdmCertChainData {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

#[derive(Debug, Clone)]
pub struct SpdmCertChainBuffer {
    pub data_size: u16,
    pub data: [u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
}

impl Default for SpdmCertChainBuffer {
    fn default() -> Self {
        SpdmCertChainBuffer {
            data_size: 0u16,
            data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        }
    }
}
impl AsRef<[u8]> for SpdmCertChainBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

impl SpdmCertChainBuffer {
    ///
    /// Table 28 — Certificate chain format
    /// This function generate the SpdmCertChainBuffer from a x509 certificates chain.
    ///
    pub fn new(cert_chain: &[u8], root_cert_hash: &[u8]) -> Option<Self> {
        if cert_chain.len() + 4 + root_cert_hash.len() > u16::MAX as usize {
            return None;
        }

        let total_len = (cert_chain.len() + root_cert_hash.len() + 4) as u16;
        let mut buff = Self::default();
        let mut pos;
        pos = 0;

        // Length
        let len = 2;
        buff.data[pos..(pos + len)].copy_from_slice(&total_len.to_le_bytes());
        pos += len;

        // Reserved
        buff.data[pos] = 0;
        buff.data[pos + 1] = 0;
        pos += 2;

        // RootHash HashLen
        let len = root_cert_hash.len();
        buff.data[pos..(pos + len)].copy_from_slice(root_cert_hash);
        pos += len;

        // Certificates
        let len = cert_chain.len();
        buff.data[pos..(pos + len)].copy_from_slice(cert_chain);
        pos += len;

        buff.data_size = pos as u16;
        Some(buff)
    }
}

enum_builder! {
    @U8
    EnumName: SpdmDmtfMeasurementType;
    EnumVal{
        SpdmDmtfMeasurementRom => 0x0,
        SpdmDmtfMeasurementFirmware => 0x1,
        SpdmDmtfMeasurementHardwareConfig => 0x2,
        SpdmDmtfMeasurementFirmwareConfig => 0x3,
        SpdmDmtfMeasurementManifest => 0x4,
        SpdmDmtfMeasurementStructuredRepresentationMode => 0x5,
        SpdmDmtfMeasurementMutableFirmwareVersionNumber => 0x6,
        SpdmDmtfMeasurementMutableFirmwareSecurityVersionNumber => 0x7
    }
}

enum_builder! {
    @U8
    EnumName: SpdmDmtfMeasurementRepresentation;
    EnumVal{
        SpdmDmtfMeasurementDigest => 0x0,
        SpdmDmtfMeasurementRawBit => 0x80
    }
}

#[derive(Debug, Clone)]
pub struct SpdmDmtfMeasurementStructure {
    pub r#type: SpdmDmtfMeasurementType,
    pub representation: SpdmDmtfMeasurementRepresentation,
    pub value_size: u16,
    pub value: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
}
impl Default for SpdmDmtfMeasurementStructure {
    fn default() -> SpdmDmtfMeasurementStructure {
        SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: 0,
            value: [0u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
        }
    }
}
impl Codec for SpdmDmtfMeasurementStructure {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        let type_value = self.r#type.get_u8();
        let representation_value = self.representation.get_u8();
        let final_value = type_value + representation_value;
        cnt += final_value.encode(bytes)?;

        // TBD: Check measurement_hash

        cnt += self.value_size.encode(bytes)?;
        for v in self.value.iter().take(self.value_size as usize) {
            cnt += v.encode(bytes)?;
        }
        Ok(cnt)
    }
    fn read(r: &mut Reader) -> Option<SpdmDmtfMeasurementStructure> {
        let final_value = u8::read(r)?;
        let type_value = final_value & 0x7f;
        let representation_value = final_value & 0x80;
        let representation = match representation_value {
            0 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            0x80 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
            val => SpdmDmtfMeasurementRepresentation::Unknown(val),
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
                _ => SpdmDmtfMeasurementType::Unknown(5),
            },
            6 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementMutableFirmwareVersionNumber
                }
                _ => SpdmDmtfMeasurementType::Unknown(6),
            },
            7 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementMutableFirmwareSecurityVersionNumber
                }
                _ => SpdmDmtfMeasurementType::Unknown(7),
            },
            val => SpdmDmtfMeasurementType::Unknown(val),
        };

        // TBD: Check measurement_hash

        let value_size = u16::read(r)?;
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

#[derive(Debug, Clone, Default)]
pub struct SpdmMeasurementBlockStructure {
    pub index: u8,
    pub measurement_specification: SpdmMeasurementSpecification,
    pub measurement_size: u16,
    pub measurement: SpdmDmtfMeasurementStructure,
}
impl Codec for SpdmMeasurementBlockStructure {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.index.encode(bytes)?;
        cnt += self.measurement_specification.encode(bytes)?;
        cnt += self.measurement_size.encode(bytes)?;
        cnt += self.measurement.encode(bytes)?;
        Ok(cnt)
    }
    fn read(r: &mut Reader) -> Option<SpdmMeasurementBlockStructure> {
        let index = u8::read(r)?;
        let measurement_specification = SpdmMeasurementSpecification::read(r)?;
        let measurement_size = u16::read(r)?;
        let measurement = SpdmDmtfMeasurementStructure::read(r)?;
        Some(SpdmMeasurementBlockStructure {
            index,
            measurement_specification,
            measurement_size,
            measurement,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SpdmMeasurementRecordStructure {
    pub number_of_blocks: u8,
    pub measurement_record_length: u24,
    pub measurement_record_data: [u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE],
}
impl Default for SpdmMeasurementRecordStructure {
    fn default() -> SpdmMeasurementRecordStructure {
        SpdmMeasurementRecordStructure {
            number_of_blocks: 0,
            measurement_record_length: u24::new(0),
            measurement_record_data: [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE],
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpdmDheExchangeStruct {
    pub data_size: u16,
    pub data: [u8; SPDM_MAX_DHE_KEY_SIZE],
}
impl Default for SpdmDheExchangeStruct {
    fn default() -> SpdmDheExchangeStruct {
        SpdmDheExchangeStruct {
            data_size: 0,
            data: [0u8; SPDM_MAX_DHE_KEY_SIZE],
        }
    }
}

impl AsRef<[u8]> for SpdmDheExchangeStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

impl From<BytesMut> for SpdmDheExchangeStruct {
    fn from(value: BytesMut) -> Self {
        assert!(value.as_ref().len() <= SPDM_MAX_DHE_KEY_SIZE);
        let data_size = value.as_ref().len() as u16;
        let mut data = [0u8; SPDM_MAX_DHE_KEY_SIZE];
        data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

#[derive(Debug, Clone)]
pub struct SpdmPskContextStruct {
    pub data_size: u16,
    pub data: [u8; config::MAX_SPDM_PSK_CONTEXT_SIZE],
}
impl Default for SpdmPskContextStruct {
    fn default() -> SpdmPskContextStruct {
        SpdmPskContextStruct {
            data_size: 0,
            data: [0u8; config::MAX_SPDM_PSK_CONTEXT_SIZE],
        }
    }
}
impl AsRef<[u8]> for SpdmPskContextStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

#[derive(Debug, Clone)]
pub struct SpdmPskHintStruct {
    pub data_size: u16,
    pub data: [u8; config::MAX_SPDM_PSK_HINT_SIZE],
}
impl Default for SpdmPskHintStruct {
    fn default() -> SpdmPskHintStruct {
        SpdmPskHintStruct {
            data_size: 0,
            data: [0u8; config::MAX_SPDM_PSK_HINT_SIZE],
        }
    }
}
impl AsRef<[u8]> for SpdmPskHintStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

macro_rules! create_sensitive_datatype {
    (Name: $name:ident, Size: $size:expr) => {
        #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name {
            pub data_size: u16,
            pub data: Box<[u8; $size]>,
        }

        impl Default for $name {
            fn default() -> $name {
                $name {
                    data_size: 0,
                    data: Box::new([0u8; $size]),
                }
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.data[0..(self.data_size as usize)]
            }
        }

        impl From<BytesMutStrubbed> for $name {
            fn from(value: BytesMutStrubbed) -> Self {
                assert!(value.as_ref().len() <= $size);
                let data_size = value.as_ref().len() as u16;
                let mut data = Box::new([0u8; $size]);
                data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
                Self { data_size, data }
            }
        }

        impl From<&[u8]> for $name {
            fn from(value: &[u8]) -> Self {
                assert!(value.len() <= $size);
                let data_size = value.len() as u16;
                let mut data = Box::new([0u8; $size]);
                data[0..value.len()].copy_from_slice(value.as_ref());
                Self { data_size, data }
            }
        }
    };
}

create_sensitive_datatype!(Name: SpdmDigestStruct, Size: SPDM_MAX_HASH_SIZE);
create_sensitive_datatype!(Name: SpdmDheFinalKeyStruct, Size: SPDM_MAX_DHE_KEY_SIZE);
create_sensitive_datatype!(Name: SpdmHandshakeSecretStruct, Size: SPDM_MAX_HASH_SIZE);
create_sensitive_datatype!(
    Name: SpdmDirectionHandshakeSecretStruct,
    Size: SPDM_MAX_HASH_SIZE
);
create_sensitive_datatype!(Name: SpdmFinishedKeyStruct, Size: SPDM_MAX_HASH_SIZE);
create_sensitive_datatype!(Name: SpdmMasterSecretStruct, Size: SPDM_MAX_HASH_SIZE);
create_sensitive_datatype!(
    Name: SpdmDirectionDataSecretStruct,
    Size: SPDM_MAX_HASH_SIZE
);
create_sensitive_datatype!(Name: SpdmAeadKeyStruct, Size: SPDM_MAX_AEAD_KEY_SIZE);
create_sensitive_datatype!(Name: SpdmAeadIvStruct, Size: SPDM_MAX_AEAD_IV_SIZE);
create_sensitive_datatype!(Name: SpdmExportMasterSecretStruct, Size: SPDM_MAX_HASH_SIZE);
create_sensitive_datatype!(Name: SpdmZeroFilledStruct, Size: SPDM_MAX_HASH_SIZE);

create_sensitive_datatype!(Name: SpdmHkdfPseudoRandomKey, Size: SPDM_MAX_HASH_SIZE);
create_sensitive_datatype!(
    Name: SpdmHkdfOutputKeyingMaterial,
    Size: SPDM_MAX_HKDF_OKM_SIZE
);

#[derive(Debug, Clone)]
pub enum SpdmMajorSecret<'a> {
    SpdmDirectionHandshakeSecret(&'a SpdmDirectionHandshakeSecretStruct),
    SpdmDirectionDataSecret(&'a SpdmDirectionDataSecretStruct),
}

#[derive(Debug, Clone)]
pub enum SpdmHkdfInputKeyingMaterial<'a> {
    SpdmZeroFilled(&'a SpdmZeroFilledStruct),
    SpdmDheFinalKey(&'a SpdmDheFinalKeyStruct),
    SpdmHandshakeSecret(&'a SpdmHandshakeSecretStruct),
    SpdmDirectionHandshakeSecret(&'a SpdmDirectionHandshakeSecretStruct),
    SpdmFinishedKey(&'a SpdmFinishedKeyStruct),
    SpdmDigest(&'a SpdmDigestStruct),
    SpdmMasterSecret(&'a SpdmMasterSecretStruct),
    SpdmDirectionDataSecret(&'a SpdmDirectionDataSecretStruct),
}

impl AsRef<[u8]> for SpdmHkdfInputKeyingMaterial<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            SpdmHkdfInputKeyingMaterial::SpdmZeroFilled(inner) => inner.as_ref(),
            SpdmHkdfInputKeyingMaterial::SpdmDheFinalKey(inner) => inner.as_ref(),
            SpdmHkdfInputKeyingMaterial::SpdmHandshakeSecret(inner) => inner.as_ref(),
            SpdmHkdfInputKeyingMaterial::SpdmDirectionHandshakeSecret(inner) => inner.as_ref(),
            SpdmHkdfInputKeyingMaterial::SpdmDigest(inner) => inner.as_ref(),
            SpdmHkdfInputKeyingMaterial::SpdmMasterSecret(inner) => inner.as_ref(),
            SpdmHkdfInputKeyingMaterial::SpdmDirectionDataSecret(inner) => inner.as_ref(),
            SpdmHkdfInputKeyingMaterial::SpdmFinishedKey(inner) => inner.as_ref(),
        }
    }
}

impl SpdmHkdfInputKeyingMaterial<'_> {
    pub fn get_data_size(&self) -> u16 {
        match self {
            SpdmHkdfInputKeyingMaterial::SpdmZeroFilled(inner) => inner.data_size,
            SpdmHkdfInputKeyingMaterial::SpdmDheFinalKey(inner) => inner.data_size,
            SpdmHkdfInputKeyingMaterial::SpdmHandshakeSecret(inner) => inner.data_size,
            SpdmHkdfInputKeyingMaterial::SpdmDirectionHandshakeSecret(inner) => inner.data_size,
            SpdmHkdfInputKeyingMaterial::SpdmDigest(inner) => inner.data_size,
            SpdmHkdfInputKeyingMaterial::SpdmMasterSecret(inner) => inner.data_size,
            SpdmHkdfInputKeyingMaterial::SpdmDirectionDataSecret(inner) => inner.data_size,
            SpdmHkdfInputKeyingMaterial::SpdmFinishedKey(inner) => inner.data_size,
        }
    }
}

impl SpdmHandshakeSecretStruct {
    pub fn from_spdm_hkdf_okm(
        okm: SpdmHkdfOutputKeyingMaterial,
    ) -> Option<SpdmHandshakeSecretStruct> {
        if okm.data_size == 0 || okm.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut hds = SpdmHandshakeSecretStruct {
                data_size: okm.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            hds.data[..okm.data_size as usize].copy_from_slice(&okm.data[..okm.data_size as usize]);
            Some(hds)
        }
    }
    pub fn from_spdm_hkdf_prk(prk: SpdmHkdfPseudoRandomKey) -> Option<SpdmHandshakeSecretStruct> {
        if prk.data_size == 0 || prk.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut hds = SpdmHandshakeSecretStruct {
                data_size: prk.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            hds.data[..prk.data_size as usize].copy_from_slice(&prk.data[..prk.data_size as usize]);
            Some(hds)
        }
    }
}

impl SpdmDirectionHandshakeSecretStruct {
    pub fn from_spdm_hkdf_okm(
        okm: SpdmHkdfOutputKeyingMaterial,
    ) -> Option<SpdmDirectionHandshakeSecretStruct> {
        if okm.data_size == 0 || okm.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut dhds = SpdmDirectionHandshakeSecretStruct {
                data_size: okm.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            dhds.data[..okm.data_size as usize]
                .copy_from_slice(&okm.data[..okm.data_size as usize]);
            Some(dhds)
        }
    }
    pub fn from_spdm_hkdf_prk(
        prk: SpdmHkdfPseudoRandomKey,
    ) -> Option<SpdmDirectionHandshakeSecretStruct> {
        if prk.data_size == 0 || prk.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut dhds = SpdmDirectionHandshakeSecretStruct {
                data_size: prk.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            dhds.data[..prk.data_size as usize]
                .copy_from_slice(&prk.data[..prk.data_size as usize]);
            Some(dhds)
        }
    }
}

impl SpdmMasterSecretStruct {
    pub fn from_spdm_hkdf_okm(okm: SpdmHkdfOutputKeyingMaterial) -> Option<SpdmMasterSecretStruct> {
        if okm.data_size == 0 || okm.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut mts = SpdmMasterSecretStruct {
                data_size: okm.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            mts.data[..okm.data_size as usize].copy_from_slice(&okm.data[..okm.data_size as usize]);
            Some(mts)
        }
    }
    pub fn from_spdm_hkdf_prk(prk: SpdmHkdfPseudoRandomKey) -> Option<SpdmMasterSecretStruct> {
        if prk.data_size == 0 || prk.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut mts = SpdmMasterSecretStruct {
                data_size: prk.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            mts.data[..prk.data_size as usize].copy_from_slice(&prk.data[..prk.data_size as usize]);
            Some(mts)
        }
    }
}

impl SpdmDirectionDataSecretStruct {
    pub fn from_spdm_hkdf_okm(
        okm: SpdmHkdfOutputKeyingMaterial,
    ) -> Option<SpdmDirectionDataSecretStruct> {
        if okm.data_size == 0 || okm.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut dmts = SpdmDirectionDataSecretStruct {
                data_size: okm.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            dmts.data[..okm.data_size as usize]
                .copy_from_slice(&okm.data[..okm.data_size as usize]);
            Some(dmts)
        }
    }
    pub fn from_spdm_hkdf_prk(
        prk: SpdmHkdfPseudoRandomKey,
    ) -> Option<SpdmDirectionDataSecretStruct> {
        if prk.data_size == 0 || prk.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut dmts = SpdmDirectionDataSecretStruct {
                data_size: prk.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            dmts.data[..prk.data_size as usize]
                .copy_from_slice(&prk.data[..prk.data_size as usize]);
            Some(dmts)
        }
    }
}

impl SpdmAeadKeyStruct {
    pub fn from_spdm_hkdf_okm(okm: SpdmHkdfOutputKeyingMaterial) -> Option<SpdmAeadKeyStruct> {
        if okm.data_size == 0 || okm.data_size > SPDM_MAX_AEAD_KEY_SIZE as u16 {
            None
        } else {
            let mut adk = SpdmAeadKeyStruct {
                data_size: okm.data_size,
                data: Box::new([0u8; SPDM_MAX_AEAD_KEY_SIZE]),
            };
            adk.data[..okm.data_size as usize].copy_from_slice(&okm.data[..okm.data_size as usize]);
            Some(adk)
        }
    }
    pub fn from_spdm_hkdf_prk(prk: SpdmHkdfPseudoRandomKey) -> Option<SpdmAeadKeyStruct> {
        if prk.data_size == 0 || prk.data_size > SPDM_MAX_AEAD_KEY_SIZE as u16 {
            None
        } else {
            let mut adk = SpdmAeadKeyStruct {
                data_size: prk.data_size,
                data: Box::new([0u8; SPDM_MAX_AEAD_KEY_SIZE]),
            };
            adk.data[..prk.data_size as usize].copy_from_slice(&prk.data[..prk.data_size as usize]);
            Some(adk)
        }
    }
}

impl SpdmAeadIvStruct {
    pub fn from_spdm_hkdf_okm(okm: SpdmHkdfOutputKeyingMaterial) -> Option<SpdmAeadIvStruct> {
        if okm.data_size == 0 || okm.data_size > SPDM_MAX_AEAD_IV_SIZE as u16 {
            None
        } else {
            let mut adv = SpdmAeadIvStruct {
                data_size: okm.data_size,
                data: Box::new([0u8; SPDM_MAX_AEAD_IV_SIZE]),
            };
            adv.data[..okm.data_size as usize].copy_from_slice(&okm.data[..okm.data_size as usize]);
            Some(adv)
        }
    }
    pub fn from_spdm_hkdf_prk(prk: SpdmHkdfPseudoRandomKey) -> Option<SpdmAeadIvStruct> {
        if prk.data_size == 0 || prk.data_size > SPDM_MAX_AEAD_IV_SIZE as u16 {
            None
        } else {
            let mut adv = SpdmAeadIvStruct {
                data_size: prk.data_size,
                data: Box::new([0u8; SPDM_MAX_AEAD_IV_SIZE]),
            };
            adv.data[..prk.data_size as usize].copy_from_slice(&prk.data[..prk.data_size as usize]);
            Some(adv)
        }
    }
}

impl SpdmFinishedKeyStruct {
    pub fn from_spdm_hkdf_okm(okm: SpdmHkdfOutputKeyingMaterial) -> Option<SpdmFinishedKeyStruct> {
        if okm.data_size == 0 || okm.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut fdk = SpdmFinishedKeyStruct {
                data_size: okm.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            fdk.data[..okm.data_size as usize].copy_from_slice(&okm.data[..okm.data_size as usize]);
            Some(fdk)
        }
    }
    pub fn from_spdm_hkdf_prk(prk: SpdmHkdfPseudoRandomKey) -> Option<SpdmFinishedKeyStruct> {
        if prk.data_size == 0 || prk.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut fdk = SpdmFinishedKeyStruct {
                data_size: prk.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            fdk.data[..prk.data_size as usize].copy_from_slice(&prk.data[..prk.data_size as usize]);
            Some(fdk)
        }
    }
}

impl SpdmExportMasterSecretStruct {
    pub fn from_spdm_hkdf_okm(
        okm: SpdmHkdfOutputKeyingMaterial,
    ) -> Option<SpdmExportMasterSecretStruct> {
        if okm.data_size == 0 || okm.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut emk = SpdmExportMasterSecretStruct {
                data_size: okm.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            emk.data[..okm.data_size as usize].copy_from_slice(&okm.data[..okm.data_size as usize]);
            Some(emk)
        }
    }
    pub fn from_spdm_hkdf_prk(
        prk: SpdmHkdfPseudoRandomKey,
    ) -> Option<SpdmExportMasterSecretStruct> {
        if prk.data_size == 0 || prk.data_size > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut emk = SpdmExportMasterSecretStruct {
                data_size: prk.data_size,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            emk.data[..prk.data_size as usize].copy_from_slice(&prk.data[..prk.data_size as usize]);
            Some(emk)
        }
    }
}

impl SpdmHkdfPseudoRandomKey {
    pub fn from_input_keying_material(
        ikm: &SpdmHkdfInputKeyingMaterial,
    ) -> Option<SpdmHkdfPseudoRandomKey> {
        if ikm.get_data_size() == 0 || ikm.get_data_size() > SPDM_MAX_HASH_SIZE as u16 {
            None
        } else {
            let mut prk = SpdmHkdfPseudoRandomKey {
                data_size: ikm.get_data_size(),
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            };
            match ikm {
                SpdmHkdfInputKeyingMaterial::SpdmZeroFilled(inner) => prk.data
                    [..inner.data_size as usize]
                    .copy_from_slice(&inner.data[..inner.data_size as usize]),
                SpdmHkdfInputKeyingMaterial::SpdmDheFinalKey(inner) => prk.data
                    [..inner.data_size as usize]
                    .copy_from_slice(&inner.data[..inner.data_size as usize]),
                SpdmHkdfInputKeyingMaterial::SpdmHandshakeSecret(inner) => prk.data
                    [..inner.data_size as usize]
                    .copy_from_slice(&inner.data[..inner.data_size as usize]),
                SpdmHkdfInputKeyingMaterial::SpdmDirectionHandshakeSecret(inner) => prk.data
                    [..inner.data_size as usize]
                    .copy_from_slice(&inner.data[..inner.data_size as usize]),
                SpdmHkdfInputKeyingMaterial::SpdmFinishedKey(inner) => prk.data
                    [..inner.data_size as usize]
                    .copy_from_slice(&inner.data[..inner.data_size as usize]),
                SpdmHkdfInputKeyingMaterial::SpdmDigest(inner) => prk.data
                    [..inner.data_size as usize]
                    .copy_from_slice(&inner.data[..inner.data_size as usize]),
                SpdmHkdfInputKeyingMaterial::SpdmMasterSecret(inner) => prk.data
                    [..inner.data_size as usize]
                    .copy_from_slice(&inner.data[..inner.data_size as usize]),
                SpdmHkdfInputKeyingMaterial::SpdmDirectionDataSecret(inner) => prk.data
                    [..inner.data_size as usize]
                    .copy_from_slice(&inner.data[..inner.data_size as usize]),
            }
            Some(prk)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Codec, Reader, Writer};

    #[test]
    fn test_case0_spdm_measurement_specification() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementSpecification::all();
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmMeasurementSpecification::read(&mut reader).unwrap(),
            SpdmMeasurementSpecification::DMTF
        );
        assert_eq!(3, reader.left());
    }
    #[test]
    fn test_case0_spdm_measurement_hash_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementHashAlgo::RAW_BIT_STREAM;
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmMeasurementHashAlgo::read(&mut reader).unwrap(),
            SpdmMeasurementHashAlgo::RAW_BIT_STREAM
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_base_asym_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmBaseAsymAlgo::read(&mut reader).unwrap(),
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_base_hash_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmBaseHashAlgo::read(&mut reader).unwrap(),
            SpdmBaseHashAlgo::TPM_ALG_SHA_256
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_dhe_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmDheAlgo::SECP_256_R1;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmDheAlgo::read(&mut reader).unwrap(),
            SpdmDheAlgo::SECP_256_R1
        );
        assert_eq!(2, reader.left());
    }

    #[test]
    fn test_case0_spdm_aead_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAeadAlgo::AES_128_GCM;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmAeadAlgo::read(&mut reader).unwrap(),
            SpdmAeadAlgo::AES_128_GCM
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_req_asym_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmReqAsymAlgo::read(&mut reader).unwrap(),
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_key_schedule_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmKeyScheduleAlgo::read(&mut reader).unwrap(),
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_nonce_struct() {
        let u8_slice = &mut [0u8; SPDM_NONCE_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmNonceStruct {
            data: [100u8; SPDM_NONCE_SIZE],
        };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(SPDM_NONCE_SIZE, reader.left());
        let spdm_nonce_struct = SpdmNonceStruct::read(&mut reader).unwrap();

        for i in 0..SPDM_NONCE_SIZE {
            assert_eq!(spdm_nonce_struct.data[i], 100);
        }
        assert_eq!(0, reader.left());
    }

    #[test]
    fn test_case0_spdm_random_struct() {
        let u8_slice = &mut [0u8; SPDM_RANDOM_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRandomStruct {
            data: [100u8; SPDM_RANDOM_SIZE],
        };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(SPDM_RANDOM_SIZE, reader.left());
        let spdm_random_struct = SpdmRandomStruct::read(&mut reader).unwrap();

        for i in 0..SPDM_RANDOM_SIZE {
            assert_eq!(spdm_random_struct.data[i], 100);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_alg_struct() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAlgStruct {
            alg_type: SpdmAlgType::SpdmAlgTypeDHE,
            alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let spdm_alg_struct = SpdmAlgStruct::read(&mut reader).unwrap();
        assert_eq!(4, reader.left());
        assert_eq!(spdm_alg_struct.alg_type, SpdmAlgType::SpdmAlgTypeDHE);
        assert_eq!(
            spdm_alg_struct.alg_supported,
            SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
        );
    }

    #[test]
    fn test_case3_spdm_alg_struct() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAlgStruct {
            alg_type: SpdmAlgType::Unknown(1),
            alg_supported: SpdmAlg::SpdmAlgoUnknown(SpdmUnknownAlgo {}),
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let spdm_alg_struct = SpdmAlgStruct::read(&mut reader);

        assert!(spdm_alg_struct.is_none());
    }
    #[test]
    fn test_case0_spdm_digest_struct() {
        let bytes_mut = BytesMutStrubbed::new();
        let u8_slice = &mut [0u8; 68];
        let mut _writer = Writer::init(u8_slice);
        let _value = SpdmDigestStruct {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };

        // TODO: assert should use should_panic
        let spdm_digest_struct = SpdmDigestStruct::from(bytes_mut);
        assert_eq!(spdm_digest_struct.data_size, 0);
    }
    #[test]
    fn test_case1_spdm_measurement_specification() {
        let value = SpdmMeasurementSpecification::DMTF;
        let mut spdm_measurement_specification = SpdmMeasurementSpecification::empty();
        spdm_measurement_specification.prioritize(value);
    }
    #[test]
    fn test_case1_spdm_signature_struct() {
        let bytes_mut = BytesMut::new();
        let spdm_signature_struct = SpdmSignatureStruct::from(bytes_mut);
        assert_eq!(spdm_signature_struct.data_size, 0);
        for i in 0..SPDM_MAX_ASYM_KEY_SIZE {
            assert_eq!(spdm_signature_struct.data[i], 0);
        }
    }

    #[test]
    #[should_panic(expected = "invalid MeasurementHashAlgo")]
    fn test_case1_spdm_measurement_hash_algo() {
        let mut value = SpdmMeasurementHashAlgo::TPM_ALG_SHA_256;
        assert_eq!(value.get_size(), SHA256_DIGEST_SIZE as u16);

        value = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        assert_eq!(value.get_size(), SHA384_DIGEST_SIZE as u16);

        value = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;
        assert_eq!(value.get_size(), SHA512_DIGEST_SIZE as u16);

        value = SpdmMeasurementHashAlgo::RAW_BIT_STREAM;
        assert_eq!(value.get_size(), 0u16);

        value = SpdmMeasurementHashAlgo::empty();
        value.get_size();
    }
    #[test]
    #[should_panic(expected = "invalid AsymAlgo")]
    fn test_case1_spdm_base_asym_algo() {
        let mut value = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048;
        assert_eq!(value.get_size(), RSASSA_2048_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048;
        assert_eq!(value.get_size(), RSAPSS_2048_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072;
        assert_eq!(value.get_size(), RSASSA_3072_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072;
        assert_eq!(value.get_size(), RSAPSS_3072_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        assert_eq!(value.get_size(), RSASSA_4096_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096;
        assert_eq!(value.get_size(), RSAPSS_4096_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P256_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P384_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::empty();
        value.get_size();
    }
    #[test]
    #[should_panic(expected = "invalid DheAlgo")]
    fn test_case1_spdm_dhe_algo() {
        let mut value = SpdmDheAlgo::SECP_256_R1;
        assert_eq!(value.get_size(), SECP_256_R1_KEY_SIZE as u16);

        value = SpdmDheAlgo::SECP_384_R1;
        assert_eq!(value.get_size(), SECP_384_R1_KEY_SIZE as u16);

        value = SpdmDheAlgo::empty();
        value.get_size();
    }
    #[test]
    #[should_panic(expected = "invalid AeadAlgo")]
    fn test_case1_spdm_aead_algo() {
        let mut value = SpdmAeadAlgo::AES_128_GCM;
        assert_eq!(value.get_key_size(), AEAD_AES_128_GCM_KEY_SIZE as u16);

        value = SpdmAeadAlgo::AES_256_GCM;
        assert_eq!(value.get_key_size(), AEAD_AES_256_GCM_KEY_SIZE as u16);

        value = SpdmAeadAlgo::CHACHA20_POLY1305;
        assert_eq!(value.get_key_size(), AEAD_CHACHA20_POLY1305_KEY_SIZE as u16);

        value = SpdmAeadAlgo::empty();
        value.get_key_size();
    }
    #[test]
    #[should_panic(expected = "invalid AeadAlgo")]
    fn test_case2_spdm_aead_algo() {
        let mut value = SpdmAeadAlgo::AES_128_GCM;
        assert_eq!(value.get_key_size(), AEAD_AES_128_GCM_KEY_SIZE as u16);

        value = SpdmAeadAlgo::AES_256_GCM;
        assert_eq!(value.get_key_size(), AEAD_AES_256_GCM_KEY_SIZE as u16);

        value = SpdmAeadAlgo::CHACHA20_POLY1305;
        assert_eq!(value.get_key_size(), AEAD_CHACHA20_POLY1305_KEY_SIZE as u16);

        value = SpdmAeadAlgo::empty();
        value.get_key_size();
    }
    #[test]
    #[should_panic(expected = "invalid AeadAlgo")]
    fn test_case3_spdm_aead_algo() {
        let mut value = SpdmAeadAlgo::AES_128_GCM;
        assert_eq!(value.get_iv_size(), AEAD_AES_128_GCM_IV_SIZE as u16);

        value = SpdmAeadAlgo::AES_256_GCM;
        assert_eq!(value.get_iv_size(), AEAD_AES_256_GCM_IV_SIZE as u16);

        value = SpdmAeadAlgo::CHACHA20_POLY1305;
        assert_eq!(value.get_iv_size(), AEAD_CHACHA20_POLY1305_IV_SIZE as u16);

        value = SpdmAeadAlgo::empty();
        value.get_iv_size();
    }
    #[test]
    #[should_panic(expected = "invalid AeadAlgo")]
    fn test_case4_spdm_aead_algo() {
        let mut value = SpdmAeadAlgo::AES_128_GCM;
        assert_eq!(value.get_tag_size(), AEAD_AES_128_GCM_TAG_SIZE as u16);

        value = SpdmAeadAlgo::AES_256_GCM;
        assert_eq!(value.get_tag_size(), AEAD_AES_256_GCM_TAG_SIZE as u16);

        value = SpdmAeadAlgo::CHACHA20_POLY1305;
        assert_eq!(value.get_tag_size(), AEAD_CHACHA20_POLY1305_TAG_SIZE as u16);

        value = SpdmAeadAlgo::empty();
        value.get_tag_size();
    }
    #[test]
    #[should_panic(expected = "invalid ReqAsymAlgo")]
    fn test_case1_spdm_req_asym_algo() {
        let mut value = SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048;
        assert_eq!(value.get_size(), RSASSA_2048_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        assert_eq!(value.get_size(), RSAPSS_2048_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072;
        assert_eq!(value.get_size(), RSASSA_3072_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_3072;
        assert_eq!(value.get_size(), RSAPSS_3072_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSASSA_4096;
        assert_eq!(value.get_size(), RSASSA_4096_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_4096;
        assert_eq!(value.get_size(), RSAPSS_4096_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P256_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P384_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::empty();
        value.get_size();
    }
    #[test]
    fn test_case0_spdm_unknown_algo() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmUnknownAlgo {};
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        SpdmUnknownAlgo::read(&mut reader);
    }
}
