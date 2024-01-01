// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::{gen_array_clone, SpdmVersion, MAX_SPDM_VERSION_COUNT};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
pub struct SpdmGetVersionRequestPayload {}

impl SpdmCodec for SpdmGetVersionRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(2)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetVersionRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmGetVersionRequestPayload {})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmVersionStruct {
    pub update: u8,
    pub version: SpdmVersion,
}

impl Codec for SpdmVersionStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.update.encode(bytes)?;
        cnt += self.version.encode(bytes)?;
        Ok(cnt)
    }
    fn read(r: &mut Reader) -> Option<SpdmVersionStruct> {
        let update = u8::read(r)?;
        let version = SpdmVersion::read(r)?;
        Some(SpdmVersionStruct { update, version })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmVersionResponsePayload {
    pub version_number_entry_count: u8,
    pub versions: [SpdmVersionStruct; MAX_SPDM_VERSION_COUNT],
}

impl SpdmCodec for SpdmVersionResponsePayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved
        cnt += self
            .version_number_entry_count
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        for version in self
            .versions
            .iter()
            .take(self.version_number_entry_count as usize)
        {
            cnt += version.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVersionResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        u8::read(r)?; // reserved
        let version_number_entry_count = u8::read(r)?;

        if version_number_entry_count < 1
            || version_number_entry_count > MAX_SPDM_VERSION_COUNT as u8
        {
            return None;
        }

        let mut versions = gen_array_clone(
            SpdmVersionStruct {
                update: 0,
                version: SpdmVersion::SpdmVersion10,
            },
            MAX_SPDM_VERSION_COUNT,
        );
        for version in versions
            .iter_mut()
            .take(version_number_entry_count as usize)
        {
            *version = SpdmVersionStruct::read(r)?;
        }
        Some(SpdmVersionResponsePayload {
            version_number_entry_count,
            versions,
        })
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};
    extern crate alloc;

    #[test]
    fn test_case1_spdmversion_struct() {
        let u8_slice = &mut [0u8; 2];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmVersionStruct {
            update: 0xffu8,
            version: SpdmVersion::SpdmVersion10,
        };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(2, reader.left());
        let spdmversionstruct = SpdmVersionStruct::read(&mut reader).unwrap();
        assert_eq!(spdmversionstruct.update, 0xff);
        assert_eq!(spdmversionstruct.version, SpdmVersion::SpdmVersion10);
    }
    #[test]
    fn test_case2_spdmversion_struct() {
        let u8_slice = &mut [0u8; 1];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmVersionStruct {
            update: 100u8,
            version: SpdmVersion::SpdmVersion10,
        };
        assert!(value.encode(&mut writer).is_err());
        let mut reader = Reader::init(u8_slice);
        let spdmversionstruct = SpdmVersionStruct::read(&mut reader);
        assert_eq!(spdmversionstruct.is_none(), true);
    }
    #[test]
    fn test_case0_spdm_version_response_payload() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmVersionResponsePayload {
            version_number_entry_count: 2u8,
            versions: gen_array_clone(
                SpdmVersionStruct {
                    update: 100u8,
                    version: SpdmVersion::SpdmVersion10,
                },
                MAX_SPDM_VERSION_COUNT,
            ),
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let version_response =
            SpdmVersionResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(version_response.version_number_entry_count, 2u8);
        for i in 0..2 {
            assert_eq!(version_response.versions[i].update, 100u8);
            assert_eq!(
                version_response.versions[i].version,
                SpdmVersion::SpdmVersion10
            );
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_get_version_request_payload() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetVersionRequestPayload {};

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        SpdmGetVersionRequestPayload::spdm_read(&mut context, &mut reader);
    }
}

#[cfg(test)]
#[path = "version_test.rs"]
mod version_test;
