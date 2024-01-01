// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::SPDM_STATUS_INVALID_STATE_PEER;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;

impl ResponderContext {
    pub fn handle_spdm_capability<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (_, rsp_slice) = self.write_spdm_capability_response(bytes, writer);
        (Ok(()), rsp_slice)
    }

    pub fn write_spdm_capability_response<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if self.common.runtime_info.get_connection_state()
            != SpdmConnectionState::SpdmConnectionAfterVersion
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(SpdmMessageHeader {
            version,
            request_response_code: _,
        }) = message_header
        {
            if version < SpdmVersion::SpdmVersion10 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            self.common.negotiate_info.spdm_version_sel = version;
        } else {
            error!("!!! get_capabilities : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            None,
        );

        let get_capabilities =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_capabilities) = get_capabilities {
            debug!("!!! get_capabilities : {:02x?}\n", get_capabilities);

            #[cfg(feature = "mandatory-mut-auth")]
            if !get_capabilities
                .flags
                .contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP)
            {
                error!("!!! get_capabilities : mut-auth is not supported by requester while mandatory-mut-auth is enabled in responder !!!\n");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
                return (
                    Err(crate::error::SPDM_STATUS_UNSUPPORTED_CAP),
                    Some(writer.used_slice()),
                );
            }

            self.common.negotiate_info.req_ct_exponent_sel = get_capabilities.ct_exponent;
            self.common.negotiate_info.req_capabilities_sel = get_capabilities.flags;
            self.common.negotiate_info.rsp_ct_exponent_sel =
                self.common.config_info.rsp_ct_exponent;
            self.common.negotiate_info.rsp_capabilities_sel =
                self.common.config_info.rsp_capabilities;

            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
                self.common.negotiate_info.req_data_transfer_size_sel =
                    get_capabilities.data_transfer_size;
                self.common.negotiate_info.req_max_spdm_msg_size_sel =
                    get_capabilities.max_spdm_msg_size;
                self.common.negotiate_info.rsp_data_transfer_size_sel =
                    self.common.config_info.data_transfer_size;
                self.common.negotiate_info.rsp_max_spdm_msg_size_sel =
                    self.common.config_info.max_spdm_msg_size;
            }
        } else {
            error!("!!! get_capabilities : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        if self
            .common
            .append_message_a(&bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        info!("send spdm capability\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCapabilities,
            },
            payload: SpdmMessagePayload::SpdmCapabilitiesResponse(
                SpdmCapabilitiesResponsePayload {
                    ct_exponent: self.common.config_info.rsp_ct_exponent,
                    flags: self.common.config_info.rsp_capabilities,
                    data_transfer_size: self.common.config_info.data_transfer_size,
                    max_spdm_msg_size: self.common.config_info.max_spdm_msg_size,
                },
            ),
        };
        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }
        if self.common.append_message_a(writer.used_slice()).is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }
}
