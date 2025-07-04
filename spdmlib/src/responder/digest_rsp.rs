// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::crypto;
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::SPDM_STATUS_INVALID_STATE_PEER;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
extern crate alloc;
use crate::error::SpdmResult;
use alloc::boxed::Box;

impl ResponderContext {
    pub fn handle_spdm_digest<'a>(
        &mut self,
        bytes: &[u8],
        session_id: Option<u32>,
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (_, rsp_slice) = self.write_spdm_digest_response(session_id, bytes, writer);
        (Ok(()), rsp_slice)
    }

    fn write_spdm_digest_response<'a>(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if self.common.data.runtime_info.get_connection_state().get_u8()
            < SpdmConnectionState::SpdmConnectionNegotiated.get_u8()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.data.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetDigests,
            session_id,
        );

        let get_digests = SpdmGetDigestsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_digests) = get_digests {
            debug!("!!! get_digests : {:02x?}\n", get_digests);
        } else {
            error!("!!! get_digests : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        match session_id {
            None => {
                if self
                    .common
                    .append_message_b(&bytes[..reader.used()])
                    .is_err()
                {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                        Some(writer.used_slice()),
                    );
                }
            }
            Some(_session_id) => {}
        }

        let digest_size = self.common.data.negotiate_info.base_hash_sel.get_size();

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

        info!("send spdm digest\n");
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.data.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmDigestsResponse(SpdmDigestsResponsePayload {
                slot_mask,
                digests: crate::protocol::gen_array_clone(
                    SpdmDigestStruct {
                        data_size: digest_size,
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
        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        let mut digest_offset = SPDM_DIGESTS_RESPONSE_DIGEST_FIELD_BYTE_OFFSET;

        for slot_id in 0..SPDM_MAX_SLOT_NUMBER {
            if self.common.data.provision_info.my_cert_chain[slot_id].is_some() {
                let my_cert_chain = self.common.data.provision_info.my_cert_chain[slot_id]
                    .as_ref()
                    .unwrap();
                let cert_chain_hash = crypto::hash::hash_all(
                    self.common.data.negotiate_info.base_hash_sel,
                    my_cert_chain.as_ref(),
                );

                let cert_chain_hash = if let Some(hash) = cert_chain_hash {
                    hash
                } else {
                    return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
                };

                // patch the message before send
                writer.mut_used_slice()
                    [digest_offset..(digest_offset + cert_chain_hash.data_size as usize)]
                    .copy_from_slice(cert_chain_hash.as_ref());
                digest_offset += cert_chain_hash.data_size as usize;
            }
        }

        match session_id {
            None => {
                if self.common.append_message_b(writer.used_slice()).is_err() {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return (
                        Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                        Some(writer.used_slice()),
                    );
                }
            }
            Some(_session_id) => {}
        }

        (Ok(()), Some(writer.used_slice()))
    }
}
