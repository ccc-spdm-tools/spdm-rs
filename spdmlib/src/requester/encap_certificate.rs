// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::{
    common::SpdmCodec,
    message::{
        SpdmCertificateResponsePayload, SpdmErrorCode, SpdmGetCertificateRequestPayload,
        SpdmMessage, SpdmMessageHeader, SpdmMessagePayload, SpdmRequestResponseCode,
        MAX_SPDM_CERT_PORTION_LEN,
    },
    protocol::{SpdmRequestCapabilityFlags, SPDM_MAX_SLOT_NUMBER},
};

use super::RequesterContext;

impl RequesterContext {
    pub fn encap_handle_get_certificate(
        &mut self,
        encap_request: &[u8],
        encap_response: &mut Writer,
    ) {
        let mut reader = Reader::init(encap_request);

        if !self
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::CERT_CAP)
        {
            self.encode_encap_error_response(
                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                0,
                encap_response,
            );
            return;
        }

        if let Some(message_header) = SpdmMessageHeader::read(&mut reader) {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.encode_encap_error_response(
                    SpdmErrorCode::SpdmErrorVersionMismatch,
                    0,
                    encap_response,
                );
                return;
            }
        } else {
            self.encode_encap_error_response(
                SpdmErrorCode::SpdmErrorInvalidRequest,
                0,
                encap_response,
            );
            return;
        }

        let get_certificate = if let Some(get_certificate) =
            SpdmGetCertificateRequestPayload::spdm_read(&mut self.common, &mut reader)
        {
            debug!("!!! encap get_certificate : {:02x?}\n", get_certificate);
            if get_certificate.slot_id != 0 {
                self.encode_encap_error_response(
                    SpdmErrorCode::SpdmErrorInvalidRequest,
                    0,
                    encap_response,
                );
                return;
            }
            get_certificate
        } else {
            error!("!!! encap get_certificate : fail !!!\n");
            self.encode_encap_error_response(
                SpdmErrorCode::SpdmErrorInvalidRequest,
                0,
                encap_response,
            );
            return;
        };

        let slot_id = get_certificate.slot_id as usize;
        if slot_id >= SPDM_MAX_SLOT_NUMBER
            || self.common.provision_info.my_cert_chain[slot_id].is_none()
        {
            self.encode_encap_error_response(
                SpdmErrorCode::SpdmErrorInvalidRequest,
                0,
                encap_response,
            );
            return;
        }

        let my_cert_chain = self.common.provision_info.my_cert_chain[slot_id]
            .as_ref()
            .unwrap();

        let mut length = get_certificate.length;
        if length > MAX_SPDM_CERT_PORTION_LEN as u16 {
            length = MAX_SPDM_CERT_PORTION_LEN as u16;
        }

        let offset = get_certificate.offset;
        if offset > my_cert_chain.data_size {
            self.encode_encap_error_response(
                SpdmErrorCode::SpdmErrorInvalidRequest,
                0,
                encap_response,
            );
            return;
        }

        if length > my_cert_chain.data_size - offset {
            length = my_cert_chain.data_size - offset;
        }

        let portion_length = length;
        let remainder_length = my_cert_chain.data_size - (length + offset);

        let cert_chain_data =
            &my_cert_chain.data[(offset as usize)..(offset as usize + length as usize)];

        let mut cert_chain = [0u8; MAX_SPDM_CERT_PORTION_LEN];
        cert_chain[..cert_chain_data.len()].copy_from_slice(cert_chain_data);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCertificate,
            },
            payload: SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
                slot_id: slot_id as u8,
                portion_length,
                remainder_length,
                cert_chain,
            }),
        };
        let _ = response.spdm_encode(&mut self.common, encap_response);

        debug!("!!! encap get_certificate : complete\n");
    }
}
