// Copyright (c) 2020, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::error::{SpdmStatus, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_UNSUPPORTED_CAP};
use codec::u24;

/// This is used in SpdmOpaqueStruct <- SpdmChallengeAuthResponsePayload / SpdmMeasurementsResponsePayload
/// It should be 1024 according to SPDM spec.
pub const MAX_SPDM_OPAQUE_SIZE: usize = 1024;

pub const MAX_SECURE_SPDM_VERSION_COUNT: usize = 0x04;

pub const DMTF_SPEC_ID: u32 = 0x444D5446;
pub const DMTF_OPAQUE_VERSION: u8 = 0x01;
pub const SM_DATA_VERSION: u8 = 0x01;
pub const DMTF_ID: u8 = 0x00;
/// The largest ID of a registry that an opaque data element can name (DSP0274).
pub const SPDM_REGISTRY_ID_MAX: u8 = 0x0B;
pub const DMTF_VENDOR_LEN: u8 = 0x00;
pub const OPAQUE_LIST_TOTAL_ELEMENTS: u8 = 0x01;
pub const VERSION_SELECTION_SM_DATA_ID: u8 = 0x00;
pub const SUPPORTED_VERSION_LIST_SM_DATA_ID: u8 = 0x01;
pub const AEAD_LIMIT_SM_DATA_ID: u8 = 0x02;

/// DSP0277 1.3: the AEAD limit exponent when the AEAD limit data is absent. The AEAD
/// limit is 2^exponent, and the exponent shall not exceed this value.
pub const AEAD_LIMIT_EXPONENT_DEFAULT: u8 = 64;

pub const DMTF_SECURE_SPDM_VERSION_10: u8 = 0x10;
pub const DMTF_SECURE_SPDM_VERSION_11: u8 = 0x11;
pub const DMTF_SECURE_SPDM_VERSION_12: u8 = 0x12;
pub const DMTF_SECURE_SPDM_VERSION_13: u8 = 0x13;

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
            || opaque_list_total_elements == 0
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

        if opaque_list_total_elements == 0 {
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
    AeadLimit,
}

impl From<SMDataId> for u8 {
    fn from(id: SMDataId) -> Self {
        match id {
            SMDataId::VersionSelectionSmDataId => 0,
            SMDataId::SupportedVersionList => 1,
            SMDataId::AeadLimit => 2,
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
            2 => Ok(Self::AeadLimit),
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
            if context
                .negotiate_info
                .other_params_support
                .contains(SpdmAlgoOtherParams::OPAQUE_DATA_FMT1)
            {
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
            if context
                .negotiate_info
                .other_params_support
                .contains(SpdmAlgoOtherParams::OPAQUE_DATA_FMT1)
            {
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
            if context
                .negotiate_info
                .other_params_support
                .contains(SpdmAlgoOtherParams::OPAQUE_DATA_FMT1)
            {
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
            if context
                .negotiate_info
                .other_params_support
                .contains(SpdmAlgoOtherParams::OPAQUE_DATA_FMT1)
            {
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
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmOpaqueStruct> {
        let data_size = u16::read(r)?;
        if data_size > MAX_SPDM_OPAQUE_SIZE as u16 {
            return None;
        }
        let mut data = [0u8; MAX_SPDM_OPAQUE_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }

        let opaque = SpdmOpaqueStruct { data_size, data };
        // Every message that carries opaque data is rejected as a whole if the opaque data is
        // malformed.
        opaque.check_general_opaque_data(context).ok()?;
        Some(opaque)
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

    /// The Secured Message versions that the Requester supports, ordered from the earliest to
    /// the latest version, whatever order the Requester sent them in.
    ///
    /// DSP0277: the Responder should select the latest supported common version. The
    /// Responder selects the last of the versions in this list that it supports too, which
    /// is the latest common one only because of this order.
    pub fn rsp_get_dmtf_supported_secure_spdm_version_list(
        &self,
        context: &mut SpdmContext,
    ) -> Option<SecuredMessageVersionList> {
        let smsupported_ver_list_opaque = self.to_sm_supported_ver_list_opaque(context).ok()?;
        let mut list = smsupported_ver_list_opaque.secured_message_version_list;
        let count = (list.version_count as usize).min(list.versions_list.len());
        list.versions_list[..count].sort_unstable_by_key(|version| u8::from(version));
        Some(list)
    }

    /// The Secured Message version that the Responder selected, or None if there is none, or
    /// if it is not one that this Requester supports. DSP0277: the Responder shall select a
    /// version among the ones that the Requester supports.
    pub fn req_get_dmtf_secure_spdm_version_selection(
        &self,
        context: &mut SpdmContext,
    ) -> Option<SecuredMessageVersion> {
        let smversion_sel_opaque = self.to_sm_version_sel_opaque(context).ok()?;
        let selected = smversion_sel_opaque.secured_message_version;
        if !context
            .config_info
            .secure_spdm_version
            .iter()
            .flatten()
            .any(|offered| *offered == selected)
        {
            return None;
        }
        Some(selected)
    }
}

/// Where the header of general opaque data ends, and where it counts its elements.
struct OpaqueLayout {
    header_size: usize,
    total_elements_index: usize,
}

impl OpaqueLayout {
    // The header is the OpaqueDataFmt1 one from SPDM 1.2 on, the general one before.
    fn of(context: &SpdmContext) -> Option<Self> {
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            if context
                .negotiate_info
                .other_params_support
                .contains(SpdmAlgoOtherParams::OPAQUE_DATA_FMT1)
            {
                Some(Self {
                    header_size: 4,
                    total_elements_index: 0,
                })
            } else {
                None
            }
        } else {
            Some(Self {
                header_size: 8,
                total_elements_index: 5,
            })
        }
    }

    // Check the header and return the number of elements.
    fn total_elements(&self, context: &SpdmContext, data: &[u8]) -> Option<u8> {
        let mut reader = Reader::init(data);
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            FM1OpaqueDataHeader::read(&mut reader)?;
        } else {
            GeneralOpaqueDataHeader::read(&mut reader)?;
        }
        data.get(self.total_elements_index).copied()
    }
}

/// An element of general opaque data: ID, VendorLen, VendorID, OpaqueElementDataLen,
/// OpaqueElementData, then padding to a multiple of 4 bytes.
struct OpaqueElement<'a> {
    id: u8,
    vendor_len: u8,
    data: &'a [u8],
    // The offset after the element data, where its padding starts.
    data_end: usize,
    // The offset after the element, with its padding.
    end: usize,
}

fn read_opaque_element(data: &[u8], offset: usize) -> Option<OpaqueElement<'_>> {
    let id = *data.get(offset)?;
    let vendor_len = *data.get(offset.checked_add(1)?)?;
    let len_offset = offset.checked_add(2)?.checked_add(vendor_len as usize)?;
    let len = u16::from_le_bytes([
        *data.get(len_offset)?,
        *data.get(len_offset.checked_add(1)?)?,
    ]) as usize;
    let data_offset = len_offset.checked_add(2)?;
    let data_end = data_offset.checked_add(len)?;
    let element_data = data.get(data_offset..data_end)?;
    let end = offset.checked_add((data_end - offset).checked_add(3)? & !3)?;
    Some(OpaqueElement {
        id,
        vendor_len,
        data: element_data,
        data_end,
        end,
    })
}

// The Secured Message data (SMData) of the first element with this SMDataID.
fn find_sm_data<'a>(
    context: &SpdmContext,
    layout: &OpaqueLayout,
    data: &'a [u8],
    sm_data_id: u8,
) -> SpdmResult<Option<&'a [u8]>> {
    let total_elements = layout
        .total_elements(context, data)
        .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;
    let mut offset = layout.header_size;
    for _ in 0..total_elements {
        let element = read_opaque_element(data, offset).ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;
        if element.id == DMTF_ID
            && element.vendor_len == DMTF_VENDOR_LEN
            && element.data.len() >= 2
            && element.data[0] == SM_DATA_VERSION
            && element.data[1] == sm_data_id
        {
            return Ok(Some(&element.data[2..]));
        }
        // The padding of the last element may be missing.
        offset = element.end.min(data.len());
    }
    Ok(None)
}

impl SpdmOpaqueStruct {
    /// Check the general opaque data, which any message can carry from SPDM 1.2 on, when
    /// opaque data format 1 is negotiated. Reject it as a whole if it is malformed. Before SPDM
    /// 1.2, or with another format, the format is not defined here, so it is not checked.
    pub fn check_general_opaque_data(&self, context: &SpdmContext) -> SpdmResult {
        if self.data_size == 0
            || context.negotiate_info.spdm_version_sel < SpdmVersion::SpdmVersion12
        {
            return Ok(());
        }
        self.check_element_list(context)
    }

    /// Check the opaque data of KEY_EXCHANGE, KEY_EXCHANGE_RSP, PSK_EXCHANGE and PSK_EXCHANGE_RSP.
    /// DSP0277 defines its format for every SPDM version: the general opaque data from SPDM 1.2
    /// on, which reading the message checks already, and before that a table of its own, with
    /// the same elements and another header. Unlike other opaque data, it is not optional: the
    /// Requester lists its Secured Message versions in it, and the Responder selects one.
    pub fn check_secured_message_opaque_data(&self, context: &SpdmContext) -> SpdmResult {
        if self.data_size == 0 {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        self.check_element_list(context)
    }

    // The header, then every element: it has a known registry, it fits with its padding, which
    // is zero, and a DMTF Secured Message element does not repeat an SMDataID. Nothing follows
    // the last element.
    fn check_element_list(&self, context: &SpdmContext) -> SpdmResult {
        // Without opaque data format 1, the format is not one that is defined.
        let Some(layout) = OpaqueLayout::of(context) else {
            return Ok(());
        };
        let data = &self.data[..self.data_size as usize];
        let total_elements = layout
            .total_elements(context, data)
            .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;
        if total_elements == 0 {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        let mut seen_sm_data_ids = [false; 256];
        let mut offset = layout.header_size;
        for _ in 0..total_elements {
            let element = read_opaque_element(data, offset).ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;
            if element.id > SPDM_REGISTRY_ID_MAX || element.end > data.len() {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            if data[element.data_end..element.end]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            if element.id == DMTF_ID
                && element.vendor_len == DMTF_VENDOR_LEN
                && element.data.len() >= 2
                && element.data[0] == SM_DATA_VERSION
            {
                let seen = &mut seen_sm_data_ids[element.data[1] as usize];
                if *seen {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                *seen = true;
            }
            offset = element.end;
        }
        if offset != data.len() {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        Ok(())
    }

    /// DSP0277 1.3: append the AEAD limit data (AEADlimitOE) to opaque data that already
    /// holds the version selection or the supported version list.
    pub fn append_aead_limit(&mut self, context: &SpdmContext, exponent: u8) -> SpdmResult {
        if exponent > AEAD_LIMIT_EXPONENT_DEFAULT {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }
        let layout = OpaqueLayout::of(context).ok_or(SPDM_STATUS_UNSUPPORTED_CAP)?;

        let data_size = self.data_size as usize;
        let data = &self.data[..data_size];
        let total_elements = layout
            .total_elements(context, data)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
        // The new element goes at the aligned end of the last one. That is after the data when
        // the last element does not have all of its padding.
        let mut end = layout.header_size;
        for _ in 0..total_elements {
            let element = read_opaque_element(data, end).ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
            end = element.end;
        }

        // OpaqueElementData is SMDataVersion, SMDataID and AeadLimitExponent, then one
        // byte of padding.
        let element = [
            DMTF_ID,
            DMTF_VENDOR_LEN,
            3,
            0,
            SM_DATA_VERSION,
            AEAD_LIMIT_SM_DATA_ID,
            exponent,
            0,
        ];
        if total_elements == u8::MAX || end + element.len() > MAX_SPDM_OPAQUE_SIZE {
            return Err(SPDM_STATUS_BUFFER_FULL);
        }
        // Zero the padding that the last element is missing, before the new element.
        if end > data_size {
            self.data[data_size..end].fill(0);
        }
        self.data[end..end + element.len()].copy_from_slice(&element);
        self.data[layout.total_elements_index] = total_elements + 1;
        self.data_size = (end + element.len()) as u16;
        Ok(())
    }

    /// DSP0277 1.3: the AeadLimitExponent in this opaque data, or None when it has no AEAD
    /// limit data. The exponent shall not exceed 64.
    pub fn get_aead_limit_exponent(&self, context: &SpdmContext) -> SpdmResult<Option<u8>> {
        if self.data_size == 0 {
            return Ok(None);
        }
        let layout = OpaqueLayout::of(context).ok_or(SPDM_STATUS_UNSUPPORTED_CAP)?;
        let data = &self.data[..self.data_size as usize];
        match find_sm_data(context, &layout, data, AEAD_LIMIT_SM_DATA_ID)? {
            None => Ok(None),
            Some(&[exponent]) if exponent <= AEAD_LIMIT_EXPONENT_DEFAULT => Ok(Some(exponent)),
            Some(_) => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}

impl SpdmContext {
    /// The AEAD limit exponent this endpoint asks for: the configured one, or the default
    /// when none is configured.
    pub fn local_aead_limit_exponent(&self) -> u8 {
        match self.config_info.aead_limit_exponent {
            1..=AEAD_LIMIT_EXPONENT_DEFAULT => self.config_info.aead_limit_exponent,
            _ => AEAD_LIMIT_EXPONENT_DEFAULT,
        }
    }

    /// Whether this endpoint supports a Secured Message version with the AEAD limit
    /// (DSP0277 1.3 or later).
    pub fn supports_aead_limit(&self) -> bool {
        self.config_info
            .secure_spdm_version
            .iter()
            .flatten()
            .any(secured_message_version_has_aead_limit)
    }

    /// Tell the peer this endpoint's AEAD limit by appending it to `opaque`. Nothing is
    /// appended for the default limit, which is what a peer assumes when it is absent.
    pub fn advertise_aead_limit(&self, opaque: &mut SpdmOpaqueStruct) -> SpdmResult {
        let exponent = self.local_aead_limit_exponent();
        if exponent == AEAD_LIMIT_EXPONENT_DEFAULT {
            return Ok(());
        }
        opaque.append_aead_limit(self, exponent)
    }

    /// The AEAD limit exponent of a session: the smaller one of this endpoint and the peer.
    /// A peer that sent no AEAD limit data has the default.
    pub fn session_aead_limit_exponent(&self, peer_exponent: Option<u8>) -> u8 {
        self.local_aead_limit_exponent()
            .min(peer_exponent.unwrap_or(AEAD_LIMIT_EXPONENT_DEFAULT))
    }
}

/// Whether a Secured Message version has the AEAD limit data (DSP0277 1.3 or later).
pub fn secured_message_version_has_aead_limit(version: &SecuredMessageVersion) -> bool {
    u8::from(version) >= DMTF_SECURE_SPDM_VERSION_13
}
