// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::error::{SpdmStatus, SPDM_STATUS_UNSUPPORTED_CAP};
use codec::u24;
use core::convert::TryFrom;

/// This is used in SpdmOpaqueStruct <- SpdmChallengeAuthResponsePayload / SpdmMeasurementsResponsePayload
/// It should be 1024 according to SPDM spec.
pub const MAX_SPDM_OPAQUE_SIZE: usize = 1024;

pub const MAX_SECURE_SPDM_VERSION_COUNT: usize = 0x02;

pub const DMTF_SPEC_ID: u32 = 0x444D5446;
pub const DMTF_OPAQUE_VERSION: u8 = 0x01;
pub const SM_DATA_VERSION: u8 = 0x01;
pub const DMTF_ID: u8 = 0x00;
pub const DMTF_VENDOR_LEN: u8 = 0x00;
pub const OPAQUE_LIST_TOTAL_ELEMENTS: u8 = 0x01;
pub const VERSION_SELECTION_SM_DATA_ID: u8 = 0x00;
pub const SUPPORTED_VERSION_LIST_SM_DATA_ID: u8 = 0x01;

pub const DMTF_SECURE_SPDM_VERSION_10: u8 = 0x10;
pub const DMTF_SECURE_SPDM_VERSION_11: u8 = 0x11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneralOpaqueDataHeader;

impl Codec for GeneralOpaqueDataHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += DMTF_SPEC_ID.encode(bytes)?;
        cnt += DMTF_OPAQUE_VERSION.encode(bytes)?;
        cnt += OPAQUE_LIST_TOTAL_ELEMENTS.encode(bytes)?;
        cnt += 0u16.encode(bytes)?; // reserved

        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let spec_id = u32::read(r)?;
        let opaque_version = u8::read(r)?;
        let opaque_list_total_elements = u8::read(r)?;
        u16::read(r)?; // reserved

        if spec_id != DMTF_SPEC_ID
            || opaque_version != DMTF_OPAQUE_VERSION
            || opaque_list_total_elements != OPAQUE_LIST_TOTAL_ELEMENTS
        {
            None
        } else {
            Some(Self)
        }
    }
}

impl SpdmCodec for GeneralOpaqueDataHeader {
    fn spdm_encode(&self, _context: &mut SpdmContext, bytes: &mut Writer) -> SpdmResult<usize> {
        self.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)
    }

    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<Self> {
        GeneralOpaqueDataHeader::read(r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FM1OpaqueDataHeader;

impl Codec for FM1OpaqueDataHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += OPAQUE_LIST_TOTAL_ELEMENTS.encode(bytes)?;
        cnt += u24::new(0).encode(bytes)?; // reserved

        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let opaque_list_total_elements = u8::read(r)?;
        u24::read(r)?; // reserved

        if opaque_list_total_elements != OPAQUE_LIST_TOTAL_ELEMENTS {
            None
        } else {
            Some(Self)
        }
    }
}

impl SpdmCodec for FM1OpaqueDataHeader {
    fn spdm_encode(&self, _context: &mut SpdmContext, bytes: &mut Writer) -> SpdmResult<usize> {
        self.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)
    }

    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<Self> {
        FM1OpaqueDataHeader::read(r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SMDataId {
    VersionSelectionSmDataId,
    SupportedVersionList,
}

impl From<SMDataId> for u8 {
    fn from(id: SMDataId) -> Self {
        match id {
            SMDataId::VersionSelectionSmDataId => 0,
            SMDataId::SupportedVersionList => 1,
        }
    }
}

impl From<&SMDataId> for u8 {
    fn from(id: &SMDataId) -> Self {
        u8::from(*id)
    }
}

impl TryFrom<u8> for SMDataId {
    type Error = ();
    fn try_from(untrusted: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match untrusted {
            0 => Ok(Self::VersionSelectionSmDataId),
            1 => Ok(Self::SupportedVersionList),
            _ => Err(()),
        }
    }
}

impl Codec for SMDataId {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        u8::from(self).encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let id = u8::read(r)?;
        Self::try_from(id).ok()
    }
}

#[derive(Clone, Copy, Debug, Eq)]
pub struct SecuredMessageVersion {
    pub major_version: u8,
    pub minor_version: u8,
    pub update_version_number: u8,
    pub alpha: u8,
}

impl Default for SecuredMessageVersion {
    fn default() -> Self {
        Self {
            major_version: 0x1,
            minor_version: 0x1,
            update_version_number: 0x0,
            alpha: 0x0,
        }
    }
}

impl Codec for SecuredMessageVersion {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += ((self.update_version_number << 4) + self.alpha).encode(bytes)?;
        cnt += ((self.major_version << 4) + self.minor_version).encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let update_version_number_alpha = u8::read(r)?;
        let major_version_minor_version = u8::read(r)?;
        let update_version_number = update_version_number_alpha >> 4;
        let alpha = update_version_number_alpha & 0x0F;
        let major_version = major_version_minor_version >> 4;
        let minor_version = major_version_minor_version & 0x0F;

        Some(SecuredMessageVersion {
            major_version,
            minor_version,
            update_version_number,
            alpha,
        })
    }
}

impl SpdmCodec for SecuredMessageVersion {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        self.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)
    }
    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<SecuredMessageVersion> {
        SecuredMessageVersion::read(r)
    }
}

impl From<SecuredMessageVersion> for u8 {
    fn from(smv: opaque::SecuredMessageVersion) -> Self {
        (smv.major_version << 4) + smv.minor_version
    }
}

impl From<&SecuredMessageVersion> for u8 {
    fn from(smv: &opaque::SecuredMessageVersion) -> Self {
        u8::from(*smv)
    }
}

impl From<SecuredMessageVersion> for u16 {
    fn from(smv: opaque::SecuredMessageVersion) -> Self {
        (((smv.major_version << 4) as u16 + smv.minor_version as u16) << 8)
            + (smv.update_version_number << 4) as u16
            + smv.alpha as u16
    }
}

impl From<&SecuredMessageVersion> for u16 {
    fn from(smv: &opaque::SecuredMessageVersion) -> Self {
        u16::from(*smv)
    }
}

impl TryFrom<u8> for SecuredMessageVersion {
    type Error = ();
    fn try_from(untrusted_smv: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        let major_version = untrusted_smv >> 4;
        let minor_version = untrusted_smv & 0x0F;
        Ok(Self {
            major_version,
            minor_version,
            update_version_number: 0,
            alpha: 0,
        })
    }
}

impl TryFrom<u16> for SecuredMessageVersion {
    type Error = ();
    fn try_from(untrusted_smv: u16) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        let major_minor = (untrusted_smv >> 8) as u8;
        let major_version = major_minor >> 4;
        let minor_version = major_minor & 0x0F;

        let update_alpha = (untrusted_smv & 0xFF) as u8;
        let update_version_number = update_alpha >> 4;
        let alpha = update_alpha & 0x0F;

        Ok(Self {
            major_version,
            minor_version,
            update_version_number,
            alpha,
        })
    }
}

impl PartialEq for SecuredMessageVersion {
    fn eq(&self, smv: &SecuredMessageVersion) -> bool {
        self.major_version == smv.major_version && self.minor_version == smv.minor_version
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecuredMessageVersionList {
    pub version_count: u8,
    pub versions_list: [SecuredMessageVersion; MAX_SECURE_SPDM_VERSION_COUNT],
}

impl Codec for SecuredMessageVersionList {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.version_count.encode(bytes)?;
        for index in 0..self.version_count as usize {
            cnt += self.versions_list[index].encode(bytes)?;
        }
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let version_count = u8::read(r)?;
        if version_count as usize > MAX_SECURE_SPDM_VERSION_COUNT {
            return None;
        }
        let mut versions_list = [SecuredMessageVersion::default(); MAX_SECURE_SPDM_VERSION_COUNT];
        for d in versions_list.iter_mut().take(version_count as usize) {
            *d = SecuredMessageVersion::read(r)?;
        }

        Some(SecuredMessageVersionList {
            version_count,
            versions_list,
        })
    }
}

impl SpdmCodec for SecuredMessageVersionList {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        self.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)
    }
    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<SecuredMessageVersionList> {
        SecuredMessageVersionList::read(r)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct SMVersionSelOpaque {
    pub secured_message_version: SecuredMessageVersion,
}

impl Codec for SMVersionSelOpaque {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += DMTF_ID.encode(bytes)?;
        cnt += DMTF_VENDOR_LEN.encode(bytes)?;
        cnt += 4u16.encode(bytes)?; // OpaqueElementDataLen, Shall be four.
        cnt += SM_DATA_VERSION.encode(bytes)?;
        cnt += SMDataId::VersionSelectionSmDataId.encode(bytes)?;
        cnt += self.secured_message_version.encode(bytes)?;
        // no padding

        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let dmtf_id = u8::read(r)?;
        let dmtf_vendor_len = u8::read(r)?;
        let opaque_element_data_len = u16::read(r)?;
        let sm_data_version = u8::read(r)?;
        let version_selection_sm_data_id = u8::read(r)?;
        let version_selection_sm_data_id = SMDataId::try_from(version_selection_sm_data_id).ok()?;
        let secured_message_version = SecuredMessageVersion::read(r)?;
        if dmtf_id != DMTF_ID
            || dmtf_vendor_len != DMTF_VENDOR_LEN
            || opaque_element_data_len != 4
            || sm_data_version != SM_DATA_VERSION
            || version_selection_sm_data_id != SMDataId::VersionSelectionSmDataId
        {
            None
        } else {
            Some(Self {
                secured_message_version,
            })
        }
    }
}

impl SpdmCodec for SMVersionSelOpaque {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) -> SpdmResult<usize> {
        let mut cnt = 0;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            if context.negotiate_info.opaque_data_support == SpdmOpaqueSupport::OPAQUE_DATA_FMT1 {
                cnt += FM1OpaqueDataHeader
                    .encode(bytes)
                    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            } else {
                return Err(SPDM_STATUS_UNSUPPORTED_CAP);
            }
        } else {
            cnt += GeneralOpaqueDataHeader
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        cnt += self.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        Ok(cnt)
    }

    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<Self> {
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            if context.negotiate_info.opaque_data_support == SpdmOpaqueSupport::OPAQUE_DATA_FMT1 {
                FM1OpaqueDataHeader::read(r)?;
            } else {
                return None;
            }
        } else {
            GeneralOpaqueDataHeader::read(r)?;
        }
        SMVersionSelOpaque::read(r)
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SMSupportedVerListOpaque {
    pub secured_message_version_list: SecuredMessageVersionList,
}

impl Codec for SMSupportedVerListOpaque {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += DMTF_ID.encode(bytes)?;
        cnt += DMTF_VENDOR_LEN.encode(bytes)?;
        cnt += (3 + 2 * self.secured_message_version_list.version_count as u16).encode(bytes)?; // OpaqueElementDataLen
        cnt += SM_DATA_VERSION.encode(bytes)?;
        cnt += SMDataId::SupportedVersionList.encode(bytes)?;
        cnt += self.secured_message_version_list.encode(bytes)?;

        // padding
        if cnt & 3 != 0 {
            let padding_cnt = 4 - (cnt & 3);
            for _ in 0..padding_cnt {
                cnt += 0u8.encode(bytes)?;
            }
        }

        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let dmtf_id = u8::read(r)?;
        let dmtf_vendor_len = u8::read(r)?;
        let opaque_element_data_len = u16::read(r)?;
        let sm_data_version = u8::read(r)?;
        let supported_version_list_sm_data_id = u8::read(r)?;
        let supported_version_list_sm_data_id =
            SMDataId::try_from(supported_version_list_sm_data_id).ok()?;
        let secured_message_version_list = SecuredMessageVersionList::read(r)?;
        if dmtf_id != DMTF_ID
            || dmtf_vendor_len != DMTF_VENDOR_LEN
            || opaque_element_data_len
                != (3 + 2 * secured_message_version_list.version_count as u16)
            || sm_data_version != SM_DATA_VERSION
            || supported_version_list_sm_data_id != SMDataId::SupportedVersionList
        {
            None
        } else {
            // padding
            let cnt = 7 + 2 * secured_message_version_list.version_count;
            if cnt & 3 != 0 {
                let padding_cnt = 4 - (cnt & 3);
                for _ in 0..padding_cnt {
                    u8::read(r)?;
                }
            }

            Some(Self {
                secured_message_version_list,
            })
        }
    }
}

impl SpdmCodec for SMSupportedVerListOpaque {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) -> SpdmResult<usize> {
        let mut cnt = 0;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            if context.negotiate_info.opaque_data_support == SpdmOpaqueSupport::OPAQUE_DATA_FMT1 {
                cnt += FM1OpaqueDataHeader
                    .encode(bytes)
                    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            } else {
                return Err(SPDM_STATUS_UNSUPPORTED_CAP);
            }
        } else {
            cnt += GeneralOpaqueDataHeader
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        cnt += self.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        Ok(cnt)
    }

    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<Self> {
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            if context.negotiate_info.opaque_data_support == SpdmOpaqueSupport::OPAQUE_DATA_FMT1 {
                FM1OpaqueDataHeader::read(r)?;
            } else {
                return None;
            }
        } else {
            GeneralOpaqueDataHeader::read(r)?;
        }
        SMSupportedVerListOpaque::read(r)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SpdmOpaqueStruct {
    pub data_size: u16,
    pub data: [u8; MAX_SPDM_OPAQUE_SIZE],
}
impl Default for SpdmOpaqueStruct {
    fn default() -> SpdmOpaqueStruct {
        SpdmOpaqueStruct {
            data_size: 0,
            data: [0u8; MAX_SPDM_OPAQUE_SIZE],
        }
    }
}

impl SpdmCodec for SpdmOpaqueStruct {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .data_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for d in self.data.iter().take(self.data_size as usize) {
            cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }
    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmOpaqueStruct> {
        let data_size = u16::read(r)?;
        if data_size > MAX_SPDM_OPAQUE_SIZE as u16 {
            return None;
        }
        let mut data = [0u8; MAX_SPDM_OPAQUE_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }

        Some(SpdmOpaqueStruct { data_size, data })
    }
}

impl SpdmOpaqueStruct {
    pub fn from_sm_version_sel_opaque(
        context: &mut SpdmContext,
        sm_version_sel_opaque: &SMVersionSelOpaque,
    ) -> SpdmResult<Self> {
        let mut opaque = SpdmOpaqueStruct {
            data_size: 0,
            data: [0u8; MAX_SPDM_OPAQUE_SIZE],
        };
        let bytes = &mut Writer::init(&mut opaque.data);

        opaque.data_size = sm_version_sel_opaque.spdm_encode(context, bytes)? as u16;

        Ok(opaque)
    }

    pub fn to_sm_version_sel_opaque(
        &self,
        context: &mut SpdmContext,
    ) -> SpdmResult<SMVersionSelOpaque> {
        SMVersionSelOpaque::spdm_read_bytes(context, &self.data[..self.data_size as usize])
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)
    }

    pub fn from_sm_supported_ver_list_opaque(
        context: &mut SpdmContext,
        sm_supported_ver_list_opaque: &SMSupportedVerListOpaque,
    ) -> SpdmResult<Self> {
        let mut opaque = SpdmOpaqueStruct {
            data_size: 0,
            data: [0u8; MAX_SPDM_OPAQUE_SIZE],
        };
        let bytes = &mut Writer::init(&mut opaque.data);

        opaque.data_size = sm_supported_ver_list_opaque.spdm_encode(context, bytes)? as u16;

        Ok(opaque)
    }

    pub fn to_sm_supported_ver_list_opaque(
        &self,
        context: &mut SpdmContext,
    ) -> SpdmResult<SMSupportedVerListOpaque> {
        SMSupportedVerListOpaque::spdm_read_bytes(context, &self.data[..self.data_size as usize])
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)
    }

    pub fn rsp_get_dmtf_supported_secure_spdm_version_list(
        &self,
        context: &mut SpdmContext,
    ) -> Option<SecuredMessageVersionList> {
        let smsupported_ver_list_opaque = self.to_sm_supported_ver_list_opaque(context).ok()?;
        Some(smsupported_ver_list_opaque.secured_message_version_list)
    }

    pub fn req_get_dmtf_secure_spdm_version_selection(
        &self,
        context: &mut SpdmContext,
    ) -> Option<SecuredMessageVersion> {
        let smversion_sel_opaque = self.to_sm_version_sel_opaque(context).ok()?;
        Some(smversion_sel_opaque.secured_message_version)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmOpaqueSupport: u8 {
        const OPAQUE_DATA_FMT1 = 0b0000_0010;
        const VALID_MASK = Self::OPAQUE_DATA_FMT1.bits;
    }
}

impl Codec for SpdmOpaqueSupport {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmOpaqueSupport> {
        let bits = u8::read(r)?;

        SpdmOpaqueSupport::from_bits(bits & SpdmOpaqueSupport::VALID_MASK.bits)
    }
}

impl SpdmOpaqueSupport {
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
