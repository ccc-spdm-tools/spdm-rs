// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::message::*;

#[derive(Debug, Clone, Default)]
pub struct SpdmGetCapabilitiesRequestPayload {
    pub ct_exponent: u8,
    pub flags: SpdmRequestCapabilityFlags,
    // New fields from SpdmVersion12
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl SpdmCodec for SpdmGetCapabilitiesRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved
            cnt += self
                .ct_exponent
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved2
            cnt += self
                .flags
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            cnt += self
                .data_transfer_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += self
                .max_spdm_msg_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetCapabilitiesRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        let mut ct_exponent = 0;
        let mut flags = SpdmRequestCapabilityFlags::default();
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            u8::read(r)?; // reserved
            ct_exponent = u8::read(r)?;
            u16::read(r)?; // reserved2
            flags = SpdmRequestCapabilityFlags::read(r)?;

            // check req_capability
            if flags.contains(SpdmRequestCapabilityFlags::PSK_RSVD) {
                return None;
            }
            if flags.contains(SpdmRequestCapabilityFlags::KEY_EX_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::PSK_CAP)
            {
                if !flags.contains(SpdmRequestCapabilityFlags::MAC_CAP) {
                    return None;
                }
            } else if flags.contains(SpdmRequestCapabilityFlags::MAC_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::ENCRYPT_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::HBEAT_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::KEY_UPD_CAP)
            {
                return None;
            }
            if !flags.contains(SpdmRequestCapabilityFlags::KEY_EX_CAP)
                && flags.contains(SpdmRequestCapabilityFlags::PSK_CAP)
                && flags.contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            {
                return None;
            }
            if flags.contains(SpdmRequestCapabilityFlags::CERT_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP)
            {
                if flags.contains(SpdmRequestCapabilityFlags::CERT_CAP)
                    && flags.contains(SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP)
                {
                    return None;
                }
                if !flags.contains(SpdmRequestCapabilityFlags::CHAL_CAP)
                    && !flags.contains(SpdmRequestCapabilityFlags::KEY_EX_CAP)
                {
                    return None;
                }
            } else if flags.contains(SpdmRequestCapabilityFlags::CHAL_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP)
            {
                return None;
            }

            if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion11
                && flags.contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP)
                && !flags.contains(SpdmRequestCapabilityFlags::ENCAP_CAP)
            {
                return None;
            }
        }

        let mut data_transfer_size = 0;
        let mut max_spdm_msg_size = 0;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            data_transfer_size = u32::read(r)?;
            max_spdm_msg_size = u32::read(r)?;
            if data_transfer_size < 42 || max_spdm_msg_size < data_transfer_size {
                log::error!(
                    "responder: data_transfer_size < 42 or max_spdm_msg_size < data_transfer_size"
                );
                return None;
            }
        }

        Some(SpdmGetCapabilitiesRequestPayload {
            ct_exponent,
            flags,
            data_transfer_size,
            max_spdm_msg_size,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmCapabilitiesResponsePayload {
    pub ct_exponent: u8,
    pub flags: SpdmResponseCapabilityFlags,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl SpdmCodec for SpdmCapabilitiesResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved
        cnt += self
            .ct_exponent
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved2
        cnt += self
            .flags
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            cnt += self
                .data_transfer_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += self
                .max_spdm_msg_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }

        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmCapabilitiesResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        u8::read(r)?; // reserved
        let ct_exponent = u8::read(r)?;
        u16::read(r)?; // reserved2
        let flags = SpdmResponseCapabilityFlags::read(r)?;

        // check rsp_capability
        if flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_NO_SIG)
            && flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
        {
            return None;
        }
        if (!flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_NO_SIG)
            && !flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG))
            && flags.contains(SpdmResponseCapabilityFlags::MEAS_FRESH_CAP)
        {
            return None;
        }
        if context.negotiate_info.spdm_version_sel < SpdmVersion::SpdmVersion11 {
            if !flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG) {
                if flags.contains(SpdmResponseCapabilityFlags::CERT_CAP)
                    != flags.contains(SpdmResponseCapabilityFlags::CHAL_CAP)
                {
                    return None;
                }
            } else if !flags.contains(SpdmResponseCapabilityFlags::CERT_CAP) {
                return None;
            }
        } else {
            if flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                && flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT)
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                || flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT)
            {
                if !flags.contains(SpdmResponseCapabilityFlags::MAC_CAP) {
                    return None;
                }
            } else if flags.contains(SpdmResponseCapabilityFlags::MAC_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::ENCRYPT_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::HBEAT_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::KEY_UPD_CAP)
            {
                return None;
            }
            if !flags.contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                && (flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                    || flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT))
                && flags.contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::CERT_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP)
            {
                if flags.contains(SpdmResponseCapabilityFlags::CERT_CAP)
                    && flags.contains(SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP)
                {
                    return None;
                }
                if !flags.contains(SpdmResponseCapabilityFlags::CHAL_CAP)
                    && !flags.contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                    && !flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
                {
                    return None;
                }
            } else if flags.contains(SpdmResponseCapabilityFlags::CHAL_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
                || flags.contains(SpdmResponseCapabilityFlags::MUT_AUTH_CAP)
            {
                return None;
            }
        }
        if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion11
            && flags.contains(SpdmResponseCapabilityFlags::MUT_AUTH_CAP)
            && !flags.contains(SpdmResponseCapabilityFlags::ENCAP_CAP)
        {
            return None;
        }
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            if !flags.contains(SpdmResponseCapabilityFlags::CERT_CAP)
                && (flags.contains(SpdmResponseCapabilityFlags::ALIAS_CERT_CAP)
                    || flags.contains(SpdmResponseCapabilityFlags::SET_CERT_CAP))
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::CSR_CAP)
                && !flags.contains(SpdmResponseCapabilityFlags::SET_CERT_CAP)
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::CERT_INSTALL_RESET_CAP)
                && !flags.contains(SpdmResponseCapabilityFlags::CSR_CAP)
                && !flags.contains(SpdmResponseCapabilityFlags::SET_CERT_CAP)
            {
                return None;
            }
        }

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            let data_transfer_size = u32::read(r)?;
            let max_spdm_msg_size = u32::read(r)?;
            if data_transfer_size < 42 || max_spdm_msg_size < data_transfer_size {
                log::error!(
                    "requester: data_transfer_size < 42 or max_spdm_msg_size < data_transfer_size"
                );
                return None;
            }
            Some(SpdmCapabilitiesResponsePayload {
                ct_exponent,
                flags,
                data_transfer_size,
                max_spdm_msg_size,
            })
        } else {
            Some(SpdmCapabilitiesResponsePayload {
                ct_exponent,
                flags,
                data_transfer_size: 0,
                max_spdm_msg_size: 0,
            })
        }
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
    fn test_case0_spdm_response_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmResponseCapabilityFlags::all();
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            SpdmResponseCapabilityFlags::all()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_response_capability_flags() {
        let value = SpdmResponseCapabilityFlags::CACHE_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::KEY_UPD_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::HBEAT_CAP;
        new_spdm_response_capability_flags(value);
    }
    #[test]
    fn test_case2_spdm_response_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmResponseCapabilityFlags::empty();
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            SpdmResponseCapabilityFlags::empty()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_request_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRequestCapabilityFlags::all();
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            SpdmRequestCapabilityFlags::all()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_request_capability_flags() {
        let value = SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::CERT_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::CHAL_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::ENCRYPT_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::MAC_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
        new_spdm_request_capability_flags(value);
    }
    #[test]
    fn test_case3_spdm_request_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRequestCapabilityFlags::empty();
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            SpdmRequestCapabilityFlags::empty()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload {
            ct_exponent: 7,
            flags: SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_get_capabilities_request_payload =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_capabilities_request_payload.ct_exponent, 7);
        assert_eq!(
            spdm_get_capabilities_request_payload.flags,
            SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case1_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload {
            ct_exponent: 0,
            flags: SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_get_capabilities_request_payload =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_capabilities_request_payload.ct_exponent, 0);
        assert_eq!(
            spdm_get_capabilities_request_payload.flags,
            SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case2_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload::default();

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader);
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload {
            ct_exponent: 7,
            flags: SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 7);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case1_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload {
            ct_exponent: 0,
            flags: SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 0);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case2_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload::default();

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 0);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::empty()
        );
        assert_eq!(2, reader.left());
    }

    fn new_spdm_response_capability_flags(value: SpdmResponseCapabilityFlags) {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            value
        );
        assert_eq!(0, reader.left())
    }

    fn new_spdm_request_capability_flags(value: SpdmRequestCapabilityFlags) {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            value
        );
        assert_eq!(0, reader.left())
    }
}

#[cfg(test)]
#[path = "capability_test.rs"]
mod capability_test;
