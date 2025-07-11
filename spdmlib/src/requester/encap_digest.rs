// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::{
    common::SpdmCodec,
    crypto,
    message::{
        SpdmDigestsResponsePayload, SpdmErrorCode, SpdmGetDigestsRequestPayload, SpdmMessage,
        SpdmMessageHeader, SpdmMessagePayload, SpdmRequestResponseCode,
    },
    protocol::{
        gen_array_clone, SpdmCertificateModelType, SpdmDigestStruct, SpdmKeyUsageMask,
        SpdmRequestCapabilityFlags, SpdmVersion, SPDM_MAX_HASH_SIZE, SPDM_MAX_SLOT_NUMBER,
    },
};
extern crate alloc;
use alloc::boxed::Box;

use super::RequesterContext;

impl RequesterContext {
    pub fn encap_handle_get_digest(&mut self, encap_request: &[u8], encap_response: &mut Writer) {
        let mut reader = Reader::init(encap_request);

        if !self
            .common
            .data
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
            if message_header.version != self.common.data.negotiate_info.spdm_version_sel {
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

        if let Some(get_digests) =
            SpdmGetDigestsRequestPayload::spdm_read(&mut self.common, &mut reader)
        {
            debug!("!!! encap get_digests : {:02x?}\n", get_digests);
        } else {
            error!("!!! encap get_digests : fail !!!\n");
            self.encode_encap_error_response(
                SpdmErrorCode::SpdmErrorInvalidRequest,
                0,
                encap_response,
            );
            return;
        }

        let mut slot_mask = 0u8;
        for slot_id in 0..SPDM_MAX_SLOT_NUMBER {
            if self.common.data.provision_info.my_cert_chain[slot_id].is_some() {
                slot_mask |= (1 << slot_id) as u8;
            }
        }

        let mut key_pair_id = gen_array_clone(0u8, SPDM_MAX_SLOT_NUMBER);
        let mut certificate_info = gen_array_clone(
            SpdmCertificateModelType::SpdmCertModelTypeNone,
            SPDM_MAX_SLOT_NUMBER,
        );
        let mut key_usage_mask = gen_array_clone(SpdmKeyUsageMask::empty(), SPDM_MAX_SLOT_NUMBER);

        if self.common.data.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13
            && self.common.data.negotiate_info.multi_key_conn_rsp
        {
            let mut slot_count = 0usize;
            for slot_id in 0..SPDM_MAX_SLOT_NUMBER {
                if self.common.data.provision_info.my_cert_chain[slot_id].is_some() {
                    key_pair_id[slot_count] =
                        self.common.data.provision_info.local_key_pair_id[slot_id].unwrap();
                    certificate_info[slot_count] =
                        self.common.data.provision_info.local_cert_info[slot_id].unwrap();
                    key_usage_mask[slot_count] =
                        self.common.data.provision_info.local_key_usage_bit_mask[slot_id].unwrap();
                    slot_count += 1;
                }
            }
        }

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.data.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmDigestsResponse(SpdmDigestsResponsePayload {
                slot_mask,
                digests: gen_array_clone(
                    SpdmDigestStruct {
                        data_size: self.common.data.negotiate_info.base_hash_sel.get_size(),
                        data: Box::new([0xffu8; SPDM_MAX_HASH_SIZE]),
                    },
                    SPDM_MAX_SLOT_NUMBER,
                ),
                supported_slot_mask: self.common.data.provision_info.local_supported_slot_mask,
                key_pair_id,
                certificate_info,
                key_usage_mask,
            }),
        };

        if response
            .spdm_encode(&mut self.common, encap_response)
            .is_err()
        {
            self.encode_encap_error_response(
                SpdmErrorCode::SpdmErrorUnspecified,
                0,
                encap_response,
            );
            return;
        }

        for slot_id in 0..SPDM_MAX_SLOT_NUMBER {
            if self.common.data.provision_info.my_cert_chain[slot_id].is_some() {
                let my_cert_chain = self.common.data.provision_info.my_cert_chain[slot_id]
                    .as_ref()
                    .unwrap();
                let cert_chain_hash = crypto::hash::hash_all(
                    self.common.data.negotiate_info.base_hash_sel,
                    my_cert_chain.as_ref(),
                )
                .unwrap();

                // patch the message before send
                let used = encap_response.used();
                encap_response.mut_used_slice()[(used - cert_chain_hash.data_size as usize)..used]
                    .copy_from_slice(cert_chain_hash.as_ref());
            }
        }
        debug!("!!! encap get_digests : complete\n");
    }
}
