// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;
use core::convert::TryFrom;
use spdmlib::message::{
    RegistryOrStandardsBodyID, VendorIDStruct, MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN,
};
use zeroize::ZeroizeOnDrop;
extern crate alloc;
use alloc::boxed::Box;

pub const PCI_IDE_KM_LINK_IDE_REG_BLOCK_MAX_COUNT: usize = 8;
pub const PCI_IDE_KM_SELECTIVE_IDE_REG_BLOCK_MAX_COUNT: usize = 255;
pub const PCI_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_MAX_COUNT: usize = 15;

pub const PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT: usize = 2
    + 2 * PCI_IDE_KM_LINK_IDE_REG_BLOCK_MAX_COUNT
    + (3 + 2 + 3 * PCI_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_MAX_COUNT)
        * PCI_IDE_KM_SELECTIVE_IDE_REG_BLOCK_MAX_COUNT;
pub const PCI_IDE_KM_IDE_REG_BLOCK_MIN_COUNT: usize = 2;

pub const IDEKM_PROTOCOL_ID: u8 = 0;

pub const QUERY_OBJECT_ID: u8 = 0;
pub const QUERY_RESP_OBJECT_ID: u8 = 1;
pub const KEY_PROG_OBJECT_ID: u8 = 2;
pub const KP_ACK_OBJECT_ID: u8 = 3;
pub const K_SET_GO_OBJECT_ID: u8 = 4;
pub const K_SET_STOP_OBJECT_ID: u8 = 5;
pub const K_GOSTOP_ACK_OBJECT_ID: u8 = 6;

pub const KEY_SET_MASK: u8 = 0x1;
pub const KEY_SET_0: u8 = 0x0;
pub const KEY_SET_1: u8 = 0x1;

pub const KEY_DIRECTION_MASK: u8 = 0x2;
pub const KEY_DIRECTION_RX: u8 = 0x0;
pub const KEY_DIRECTION_TX: u8 = 0x2;

pub const KEY_SUB_STREAM_MASK: u8 = 0xF0;
pub const KEY_SUB_STREAM_PR: u8 = 0x0;
pub const KEY_SUB_STREAM_NPR: u8 = 0x10;
pub const KEY_SUB_STREAM_CPL: u8 = 0x20;

#[derive(Debug)]
pub struct QueryDataObject {
    pub port_index: u8,
}

impl Codec for QueryDataObject {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += IDEKM_PROTOCOL_ID.encode(bytes)?;
        cnt += QUERY_OBJECT_ID.encode(bytes)?;
        cnt += 0u8.encode(bytes)?;
        cnt += self.port_index.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let protocol_id = u8::read(r)?;
        if protocol_id != IDEKM_PROTOCOL_ID {
            return None;
        }

        let object_id = u8::read(r)?;
        if object_id != QUERY_OBJECT_ID {
            return None;
        }

        u8::read(r)?;

        let port_index = u8::read(r)?;

        Some(Self { port_index })
    }
}

#[derive(Debug)]
pub struct QueryRespDataObject {
    pub port_index: u8,
    pub dev_func_num: u8,
    pub bus_num: u8,
    pub segment: u8,
    pub max_port_index: u8,
    pub ide_reg_block_cnt: usize,
    pub ide_reg_block: [u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT],
}

impl Codec for QueryRespDataObject {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += IDEKM_PROTOCOL_ID.encode(bytes)?;
        cnt += QUERY_RESP_OBJECT_ID.encode(bytes)?;
        cnt += 0u8.encode(bytes)?;
        cnt += self.port_index.encode(bytes)?;
        cnt += self.dev_func_num.encode(bytes)?;
        cnt += self.bus_num.encode(bytes)?;
        cnt += self.segment.encode(bytes)?;
        cnt += self.max_port_index.encode(bytes)?;
        for ide_reg in self.ide_reg_block.iter().take(self.ide_reg_block_cnt) {
            cnt += ide_reg.encode(bytes)?;
        }

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let protocol_id = u8::read(r)?;
        if protocol_id != IDEKM_PROTOCOL_ID {
            return None;
        }
        let object_id = u8::read(r)?;
        if object_id != QUERY_RESP_OBJECT_ID {
            return None;
        }
        u8::read(r)?;
        let port_index = u8::read(r)?;
        let dev_func_num = u8::read(r)?;
        let bus_num = u8::read(r)?;
        let segment = u8::read(r)?;
        let max_port_index = u8::read(r)?;

        let left = r.left();
        if left % 4 != 0 {
            return None;
        }

        let ide_reg_block_cnt = left / 4;
        if !(PCI_IDE_KM_IDE_REG_BLOCK_MIN_COUNT..=PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT)
            .contains(&ide_reg_block_cnt)
        {
            return None;
        }

        let mut ide_reg_block = [0u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT];
        for ide_reg in ide_reg_block.iter_mut().take(ide_reg_block_cnt) {
            *ide_reg = u32::read(r)?;
        }

        Some(Self {
            port_index,
            dev_func_num,
            bus_num,
            segment,
            max_port_index,
            ide_reg_block_cnt,
            ide_reg_block,
        })
    }
}

#[derive(Debug, Default, Clone, ZeroizeOnDrop)]
pub struct Aes256GcmKeyBuffer {
    pub key: Box<[u32; 8]>,
    pub iv: Box<[u32; 2]>,
}

impl Codec for Aes256GcmKeyBuffer {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.key[7].encode(bytes)?;
        cnt += self.key[6].encode(bytes)?;
        cnt += self.key[5].encode(bytes)?;
        cnt += self.key[4].encode(bytes)?;
        cnt += self.key[3].encode(bytes)?;
        cnt += self.key[2].encode(bytes)?;
        cnt += self.key[1].encode(bytes)?;
        cnt += self.key[0].encode(bytes)?;
        cnt += self.iv[1].encode(bytes)?;
        cnt += self.iv[0].encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let mut key = Box::new([0u32; 8]);
        let mut iv = Box::new([0u32; 2]);

        for k in key.iter_mut().take(8) {
            *k = u32::read(r)?;
        }

        key.reverse();

        for i in iv.iter_mut().take(2) {
            *i = u32::read(r)?;
        }

        iv.reverse();

        Some(Self { key, iv })
    }
}

#[derive(Debug, Default, ZeroizeOnDrop)]
pub struct KeyProgDataObject {
    pub stream_id: u8,
    pub key_set: u8,
    pub key_direction: u8,
    pub key_sub_stream: u8,
    pub port_index: u8,
    pub key_iv: Aes256GcmKeyBuffer,
}

impl Codec for KeyProgDataObject {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += IDEKM_PROTOCOL_ID.encode(bytes)?;
        cnt += KEY_PROG_OBJECT_ID.encode(bytes)?;
        cnt += 0u16.encode(bytes)?;
        cnt += self.stream_id.encode(bytes)?;
        cnt += 0u8.encode(bytes)?;
        cnt += (self.key_set | self.key_direction | self.key_sub_stream).encode(bytes)?;
        cnt += self.port_index.encode(bytes)?;
        cnt += self.key_iv.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let protocol_id = u8::read(r)?;
        if protocol_id != IDEKM_PROTOCOL_ID {
            return None;
        }
        let object_id = u8::read(r)?;
        if object_id != KEY_PROG_OBJECT_ID {
            return None;
        }
        u16::read(r)?;
        let stream_id = u8::read(r)?;
        u8::read(r)?;
        let key_set_direction_sub_stream = u8::read(r)?;
        let key_set = key_set_direction_sub_stream & KEY_SET_MASK;
        let key_direction = key_set_direction_sub_stream & KEY_DIRECTION_MASK;
        let key_sub_stream = key_set_direction_sub_stream & KEY_SUB_STREAM_MASK;
        if key_sub_stream != KEY_SUB_STREAM_PR
            && key_sub_stream != KEY_SUB_STREAM_NPR
            && key_sub_stream != KEY_SUB_STREAM_CPL
        {
            return None;
        }
        let port_index = u8::read(r)?;
        let key_iv = Aes256GcmKeyBuffer::read(r)?;

        Some(Self {
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
            key_iv,
        })
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KpAckStatus {
    SUCCESS,
    INCORRECT_LENGTH,
    UNSUPPORTED_PORT_INDEX,
    UNSUPPORTED_VALUE,
    UNSPECIFIED_FAILURE,
}

impl Default for KpAckStatus {
    fn default() -> Self {
        Self::UNSPECIFIED_FAILURE
    }
}

impl From<KpAckStatus> for u8 {
    fn from(status: KpAckStatus) -> Self {
        match status {
            KpAckStatus::SUCCESS => 0,
            KpAckStatus::INCORRECT_LENGTH => 1,
            KpAckStatus::UNSUPPORTED_PORT_INDEX => 2,
            KpAckStatus::UNSUPPORTED_VALUE => 3,
            KpAckStatus::UNSPECIFIED_FAILURE => 4,
        }
    }
}

impl TryFrom<u8> for KpAckStatus {
    type Error = ();
    fn try_from(untrusted_status: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match untrusted_status {
            0 => Ok(KpAckStatus::SUCCESS),
            1 => Ok(KpAckStatus::INCORRECT_LENGTH),
            2 => Ok(KpAckStatus::UNSUPPORTED_PORT_INDEX),
            3 => Ok(KpAckStatus::UNSUPPORTED_VALUE),
            4 => Ok(KpAckStatus::UNSPECIFIED_FAILURE),
            _ => Err(()),
        }
    }
}

impl Codec for KpAckStatus {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += u8::from(*self).encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let status = u8::read(r)?;
        KpAckStatus::try_from(status).ok()
    }
}

#[derive(Debug, Default)]
pub struct KpAckDataObject {
    pub stream_id: u8,
    pub status: KpAckStatus,
    pub key_set: u8,
    pub key_direction: u8,
    pub key_sub_stream: u8,
    pub port_index: u8,
}

impl Codec for KpAckDataObject {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += IDEKM_PROTOCOL_ID.encode(bytes)?;
        cnt += KP_ACK_OBJECT_ID.encode(bytes)?;
        cnt += 0u16.encode(bytes)?;
        cnt += self.stream_id.encode(bytes)?;
        cnt += self.status.encode(bytes)?;
        cnt += (self.key_set | self.key_direction | self.key_sub_stream).encode(bytes)?;
        cnt += self.port_index.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let protocol_id = u8::read(r)?;
        if protocol_id != IDEKM_PROTOCOL_ID {
            return None;
        }
        let object_id = u8::read(r)?;
        if object_id != KP_ACK_OBJECT_ID {
            return None;
        }
        u16::read(r)?;
        let stream_id = u8::read(r)?;
        let status = KpAckStatus::read(r)?;
        let key_set_direction_sub_stream = u8::read(r)?;
        let key_set = key_set_direction_sub_stream & KEY_SET_MASK;
        let key_direction = key_set_direction_sub_stream & KEY_DIRECTION_MASK;
        let key_sub_stream = key_set_direction_sub_stream & KEY_SUB_STREAM_MASK;
        if key_sub_stream != KEY_SUB_STREAM_PR
            && key_sub_stream != KEY_SUB_STREAM_NPR
            && key_sub_stream != KEY_SUB_STREAM_CPL
        {
            return None;
        }
        let port_index = u8::read(r)?;

        Some(Self {
            stream_id,
            status,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        })
    }
}

#[derive(Debug, Default)]
pub struct KSetGoDataObject {
    pub stream_id: u8,
    pub key_set: u8,
    pub key_direction: u8,
    pub key_sub_stream: u8,
    pub port_index: u8,
}

impl Codec for KSetGoDataObject {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += IDEKM_PROTOCOL_ID.encode(bytes)?;
        cnt += K_SET_GO_OBJECT_ID.encode(bytes)?;
        cnt += 0u16.encode(bytes)?;
        cnt += self.stream_id.encode(bytes)?;
        cnt += 0u8.encode(bytes)?;
        cnt += (self.key_set | self.key_direction | self.key_sub_stream).encode(bytes)?;
        cnt += self.port_index.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let protocol_id = u8::read(r)?;
        if protocol_id != IDEKM_PROTOCOL_ID {
            return None;
        }
        let object_id = u8::read(r)?;
        if object_id != K_SET_GO_OBJECT_ID {
            return None;
        }
        u16::read(r)?;
        let stream_id = u8::read(r)?;
        u8::read(r)?;
        let key_set_direction_sub_stream = u8::read(r)?;
        let key_set = key_set_direction_sub_stream & KEY_SET_MASK;
        let key_direction = key_set_direction_sub_stream & KEY_DIRECTION_MASK;
        let key_sub_stream = key_set_direction_sub_stream & KEY_SUB_STREAM_MASK;
        if key_sub_stream != KEY_SUB_STREAM_PR
            && key_sub_stream != KEY_SUB_STREAM_NPR
            && key_sub_stream != KEY_SUB_STREAM_CPL
        {
            return None;
        }
        let port_index = u8::read(r)?;

        Some(Self {
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        })
    }
}

#[derive(Debug, Default)]
pub struct KSetStopDataObject {
    pub stream_id: u8,
    pub key_set: u8,
    pub key_direction: u8,
    pub key_sub_stream: u8,
    pub port_index: u8,
}

impl Codec for KSetStopDataObject {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += IDEKM_PROTOCOL_ID.encode(bytes)?;
        cnt += K_SET_STOP_OBJECT_ID.encode(bytes)?;
        cnt += 0u16.encode(bytes)?;
        cnt += self.stream_id.encode(bytes)?;
        cnt += 0u8.encode(bytes)?;
        cnt += (self.key_set | self.key_direction | self.key_sub_stream).encode(bytes)?;
        cnt += self.port_index.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let protocol_id = u8::read(r)?;
        if protocol_id != IDEKM_PROTOCOL_ID {
            return None;
        }
        let object_id = u8::read(r)?;
        if object_id != K_SET_STOP_OBJECT_ID {
            return None;
        }
        u16::read(r)?;
        let stream_id = u8::read(r)?;
        u8::read(r)?;
        let key_set_direction_sub_stream = u8::read(r)?;
        let key_set = key_set_direction_sub_stream & KEY_SET_MASK;
        let key_direction = key_set_direction_sub_stream & KEY_DIRECTION_MASK;
        let key_sub_stream = key_set_direction_sub_stream & KEY_SUB_STREAM_MASK;
        if key_sub_stream != KEY_SUB_STREAM_PR
            && key_sub_stream != KEY_SUB_STREAM_NPR
            && key_sub_stream != KEY_SUB_STREAM_CPL
        {
            return None;
        }
        let port_index = u8::read(r)?;

        Some(Self {
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        })
    }
}

#[derive(Debug, Default)]
pub struct KGoStopAckDataObject {
    pub stream_id: u8,
    pub key_set: u8,
    pub key_direction: u8,
    pub key_sub_stream: u8,
    pub port_index: u8,
}

impl Codec for KGoStopAckDataObject {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += IDEKM_PROTOCOL_ID.encode(bytes)?;
        cnt += K_GOSTOP_ACK_OBJECT_ID.encode(bytes)?;
        cnt += 0u16.encode(bytes)?;
        cnt += self.stream_id.encode(bytes)?;
        cnt += 0u8.encode(bytes)?;
        cnt += (self.key_set | self.key_direction | self.key_sub_stream).encode(bytes)?;
        cnt += self.port_index.encode(bytes)?;

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let protocol_id = u8::read(r)?;
        if protocol_id != IDEKM_PROTOCOL_ID {
            return None;
        }
        let object_id = u8::read(r)?;
        if object_id != K_GOSTOP_ACK_OBJECT_ID {
            return None;
        }
        u16::read(r)?;
        let stream_id = u8::read(r)?;
        u8::read(r)?;
        let key_set_direction_sub_stream = u8::read(r)?;
        let key_set = key_set_direction_sub_stream & KEY_SET_MASK;
        let key_direction = key_set_direction_sub_stream & KEY_DIRECTION_MASK;
        let key_sub_stream = key_set_direction_sub_stream & KEY_SUB_STREAM_MASK;
        if key_sub_stream != KEY_SUB_STREAM_PR
            && key_sub_stream != KEY_SUB_STREAM_NPR
            && key_sub_stream != KEY_SUB_STREAM_CPL
        {
            return None;
        }
        let port_index = u8::read(r)?;

        Some(Self {
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        })
    }
}

pub const STANDARD_ID: RegistryOrStandardsBodyID = RegistryOrStandardsBodyID::PCISIG;

#[inline]
pub const fn vendor_id() -> VendorIDStruct {
    let mut vendor_idstruct = VendorIDStruct {
        len: 2,
        vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
    };

    vendor_idstruct.vendor_id[0] = 0x01;

    vendor_idstruct
}
