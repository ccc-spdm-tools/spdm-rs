// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use codec::enum_builder;
use codec::{Codec, Reader, Writer};
use core::ops::DerefMut;
use spdmlib::common::SpdmTransportEncap;
use spdmlib::error::{SpdmResult, SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_ENCAP_FAIL};
use spin::Mutex;

enum_builder! {
    @U16
    EnumName: PciDoeVendorId;
    EnumVal{
        PciDoeVendorIdPciSig => 0x0001
    }
}
impl Default for PciDoeVendorId {
    fn default() -> PciDoeVendorId {
        PciDoeVendorId::Unknown(0)
    }
}

enum_builder! {
    @U8
    EnumName: PciDoeDataObjectType;
    EnumVal{
        PciDoeDataObjectTypeDoeDiscovery => 0x00,
        PciDoeDataObjectTypeSpdm => 0x01,
        PciDoeDataObjectTypeSecuredSpdm => 0x02
    }
}
impl Default for PciDoeDataObjectType {
    fn default() -> PciDoeDataObjectType {
        PciDoeDataObjectType::Unknown(0)
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct PciDoeMessageHeader {
    pub vendor_id: PciDoeVendorId,
    pub data_object_type: PciDoeDataObjectType,
    pub payload_length: u32, // in bytes
}

impl Codec for PciDoeMessageHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.vendor_id.encode(bytes)?;
        cnt += self.data_object_type.encode(bytes)?;
        cnt += 0u8.encode(bytes)?;
        let mut length = (self.payload_length + 8) >> 2;
        if length > 0x40000 {
            panic!();
        }
        if length == 0x40000 {
            length = 0;
        }
        cnt += length.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<PciDoeMessageHeader> {
        let vendor_id = PciDoeVendorId::read(r)?;
        let data_object_type = PciDoeDataObjectType::read(r)?;
        u8::read(r)?;
        let mut length = u32::read(r)?;
        length &= 0x3ffff;
        if length == 0 {
            length = 0x40000;
        }
        if length < 2 {
            return None;
        }
        let payload_length = (length << 2).checked_sub(8)?;
        Some(PciDoeMessageHeader {
            vendor_id,
            data_object_type,
            payload_length,
        })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct PciDoeTransportEncap {}

#[maybe_async::maybe_async]
impl SpdmTransportEncap for PciDoeTransportEncap {
    async fn encap(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        transport_buffer: Arc<Mutex<&mut [u8]>>,
        secured_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let aligned_payload_len = (payload_len + 3) / 4 * 4;
        let mut transport_buffer = transport_buffer.lock();
        let transport_buffer = transport_buffer.deref_mut();
        let mut writer = Writer::init(transport_buffer);
        let pcidoe_header = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: if secured_message {
                PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm
            } else {
                PciDoeDataObjectType::PciDoeDataObjectTypeSpdm
            },
            payload_length: aligned_payload_len as u32,
        };
        pcidoe_header
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_ENCAP_FAIL)?;
        let header_size = writer.used();
        if transport_buffer.len() < header_size + aligned_payload_len {
            return Err(SPDM_STATUS_ENCAP_FAIL);
        }
        transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(&spdm_buffer);
        Ok(header_size + aligned_payload_len)
    }

    async fn decap(
        &mut self,
        transport_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(&transport_buffer);
        let pcidoe_header: PciDoeMessageHeader =
            PciDoeMessageHeader::read(&mut reader).ok_or(SPDM_STATUS_DECAP_FAIL)?;
        match pcidoe_header.vendor_id {
            PciDoeVendorId::PciDoeVendorIdPciSig => {}
            _ => return Err(SPDM_STATUS_DECAP_FAIL),
        }
        let secured_message = match pcidoe_header.data_object_type {
            PciDoeDataObjectType::PciDoeDataObjectTypeSpdm => false,
            PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm => true,
            _ => return Err(SPDM_STATUS_DECAP_FAIL),
        };
        let header_size = reader.used();
        let payload_size = pcidoe_header.payload_length as usize;
        if transport_buffer.len() < header_size + payload_size {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        let mut spdm_buffer = spdm_buffer.lock();
        let spdm_buffer = spdm_buffer.deref_mut();
        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        let payload = &transport_buffer[header_size..(header_size + payload_size)];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, secured_message))
    }

    async fn encap_app(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        app_buffer: Arc<Mutex<&mut [u8]>>,
        _is_app_message: bool,
    ) -> SpdmResult<usize> {
        let mut app_buffer = app_buffer.lock();
        let app_buffer = app_buffer.deref_mut();
        app_buffer[0..spdm_buffer.len()].copy_from_slice(&spdm_buffer);
        Ok(spdm_buffer.len())
    }

    async fn decap_app(
        &mut self,
        app_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let mut spdm_buffer = spdm_buffer.lock();
        let spdm_buffer = spdm_buffer.deref_mut();
        spdm_buffer[0..app_buffer.len()].copy_from_slice(&app_buffer);
        Ok((app_buffer.len(), false))
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        0
    }
    fn get_max_random_count(&mut self) -> u16 {
        0
    }
}

#[cfg(test)]
mod tests_header {
    use super::*;

    #[test]
    fn test_case0_mctpmessageheader() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
            payload_length: 100,
        };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let pcidoemessageheader = PciDoeMessageHeader::read(&mut reader).unwrap();
        assert_eq!(0, reader.left());
        assert_eq!(
            pcidoemessageheader.vendor_id,
            PciDoeVendorId::PciDoeVendorIdPciSig
        );
        assert_eq!(
            pcidoemessageheader.data_object_type,
            PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery
        );
        assert_eq!(pcidoemessageheader.payload_length, 100);
    }
    #[test]
    fn test_case1_mctpmessageheader() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
            payload_length: 0xffff8,
        };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        let pcidoemessageheader = PciDoeMessageHeader::read(&mut reader).unwrap();
        assert_eq!(pcidoemessageheader.payload_length, 0xffff8);
    }
    #[test]
    fn test_case2_mctpmessageheader() {
        let u8_slice = &mut [0u8; 10];
        let mut writer = Writer::init(u8_slice);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
            payload_length: 0,
        };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        let pcidoemessageheader = PciDoeMessageHeader::read(&mut reader).unwrap();
        assert_eq!(2, reader.left());
        assert_eq!(pcidoemessageheader.payload_length, 0);
    }
    #[test]
    fn test_case3_mctpmessageheader() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
            payload_length: 0x100,
        };

        assert!(value.encode(&mut writer).is_ok());
        assert_eq!(0, writer.left());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        let pcidoemessageheader = PciDoeMessageHeader::read(&mut reader);
        assert_eq!(0, reader.left());
        assert_eq!(pcidoemessageheader.is_none(), true);
    }
    #[test]
    #[should_panic]
    fn test_case4_mctpmessageheader() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
            payload_length: 0xffffffff,
        };
        assert!(value.encode(&mut writer).is_ok());
    }
    #[test]
    #[should_panic]
    fn test_case5_mctpmessageheader() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
            payload_length: 0xf00000,
        };
        assert!(value.encode(&mut writer).is_ok());
    }
}
