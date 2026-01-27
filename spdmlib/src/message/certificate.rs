// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::spdm_codec::SpdmCodec;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::protocol::{
    SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion, SPDM_MAX_SLOT_NUMBER,
};
use crate::{common, error::SpdmStatus};
use codec::{Codec, Reader, Writer};

pub const MAX_SPDM_CERT_PORTION_LEN: usize = 512;

#[derive(Debug, Clone, Default)]
pub struct SpdmGetCertificateRequestPayload {
    pub slot_id: u8,
    pub offset: u32,
    pub length: u32,
}

impl SpdmCodec for SpdmGetCertificateRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let large_cert = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
            && context
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP);
        let mut cnt = 0usize;
        let param1 = self.slot_id & 0xF | if large_cert { 0x80u8 } else { 0x00u8 };
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        if large_cert {
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // offset
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // length
            cnt += self
                .offset
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += self
                .length
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += ((self.offset & 0xffff) as u16)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += ((self.length & 0xffff) as u16)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetCertificateRequestPayload> {
        let param1 = u8::read(r)?; // param1
        let slot_id = param1 & 0xF;
        if slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
            return None;
        }
        let large_cert = (param1 & 0x80) != 0;
        if large_cert
            && !(context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
                && context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP))
        {
            return None;
        }
        u8::read(r)?; // param2
        if large_cert {
            u16::read(r)?; // offset
            u16::read(r)?; // length
        }
        let offset = if large_cert {
            u32::read(r)?
        } else {
            u16::read(r)? as u32
        };
        let length = if large_cert {
            u32::read(r)?
        } else {
            u16::read(r)? as u32
        };

        Some(SpdmGetCertificateRequestPayload {
            slot_id,
            offset,
            length,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SpdmCertificateResponsePayload {
    pub slot_id: u8,
    pub portion_length: u32,
    pub remainder_length: u32,
    pub cert_chain: [u8; MAX_SPDM_CERT_PORTION_LEN],
}
impl Default for SpdmCertificateResponsePayload {
    fn default() -> SpdmCertificateResponsePayload {
        SpdmCertificateResponsePayload {
            slot_id: 0,
            portion_length: 0,
            remainder_length: 0,
            cert_chain: [0u8; MAX_SPDM_CERT_PORTION_LEN],
        }
    }
}

impl SpdmCodec for SpdmCertificateResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let large_cert = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
            && context
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP);
        let mut cnt = 0usize;
        let param1 = self.slot_id & 0xF | if large_cert { 0x80u8 } else { 0x00u8 };
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        if large_cert {
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // portion_length
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // remainder_length
            cnt += self
                .portion_length
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += self
                .remainder_length
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += ((self.portion_length & 0xffff) as u16)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += ((self.remainder_length & 0xffff) as u16)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }

        for d in self.cert_chain.iter().take(self.portion_length as usize) {
            cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmCertificateResponsePayload> {
        let param1 = u8::read(r)?; // param1
        let slot_id = param1 & 0xF;
        if slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
            return None;
        }
        let large_cert = (param1 & 0x80) != 0;
        if large_cert
            && !(context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
                && context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::LARGE_RESP_CAP)
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::LARGE_RESP_CAP))
        {
            return None;
        }
        u8::read(r)?; // param2
        if large_cert {
            u16::read(r)?; // portion_length
            u16::read(r)?; // remainder_length
        }
        let portion_length = if large_cert {
            u32::read(r)?
        } else {
            u16::read(r)? as u32
        };
        let remainder_length = if large_cert {
            u32::read(r)?
        } else {
            u16::read(r)? as u32
        };

        let mut response = SpdmCertificateResponsePayload {
            slot_id,
            portion_length,
            remainder_length,
            cert_chain: [0u8; MAX_SPDM_CERT_PORTION_LEN],
        };

        for data in response.cert_chain.iter_mut().take(portion_length as usize) {
            *data = u8::read(r)?;
        }
        Some(response)
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
    fn test_case0_spdm_get_certificate_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let mut value = SpdmGetCertificateRequestPayload::default();
        value.slot_id = 4;
        value.offset = 100;
        value.length = 100;

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_get_certificate_request_payload =
            SpdmGetCertificateRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_certificate_request_payload.slot_id, 4);
        assert_eq!(spdm_get_certificate_request_payload.offset, 100);
        assert_eq!(spdm_get_certificate_request_payload.length, 100);
        assert_eq!(6, reader.left());
    }
    #[test]
    fn test_case0_spdm_certificate_response_payload() {
        let u8_slice = &mut [0u8; 6 + MAX_SPDM_CERT_PORTION_LEN];
        let mut writer = Writer::init(u8_slice);
        let mut value = SpdmCertificateResponsePayload::default();
        value.slot_id = 4;
        value.portion_length = MAX_SPDM_CERT_PORTION_LEN as u32;
        value.remainder_length = 100;
        value.cert_chain = [100u8; MAX_SPDM_CERT_PORTION_LEN];

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(6 + MAX_SPDM_CERT_PORTION_LEN, reader.left());
        let spdm_get_certificate_request_payload =
            SpdmCertificateResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_certificate_request_payload.slot_id, 4);
        assert_eq!(
            spdm_get_certificate_request_payload.portion_length,
            MAX_SPDM_CERT_PORTION_LEN as u32
        );
        assert_eq!(spdm_get_certificate_request_payload.remainder_length, 100);
        for i in 0..MAX_SPDM_CERT_PORTION_LEN {
            assert_eq!(spdm_get_certificate_request_payload.cert_chain[i], 100u8);
        }
    }
}

#[cfg(test)]
#[path = "certificate_test.rs"]
mod certificate_test;
