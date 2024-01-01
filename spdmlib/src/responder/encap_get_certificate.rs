// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::{
    common::SpdmCodec,
    config,
    crypto::{self, is_root_certificate},
    error::{
        SpdmResult, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_CERT,
        SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_MSG_SIZE, SPDM_STATUS_INVALID_PARAMETER,
        SPDM_STATUS_INVALID_STATE_LOCAL,
    },
    message::{
        SpdmCertificateResponsePayload, SpdmGetCertificateRequestPayload, SpdmMessage,
        SpdmMessageGeneralPayload, SpdmMessageHeader, SpdmMessagePayload, SpdmRequestResponseCode,
        MAX_SPDM_CERT_PORTION_LEN,
    },
    protocol::{SpdmCertChainBuffer, SpdmCertChainData},
};

use super::ResponderContext;

impl ResponderContext {
    pub fn encode_encap_requst_get_certificate(
        &mut self,
        encap_request: &mut Writer,
    ) -> SpdmResult {
        if self.common.peer_info.peer_cert_chain_temp.is_none() {
            self.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());
        }

        let encapsulated_request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
            },
            payload: SpdmMessagePayload::SpdmGetCertificateRequest(
                SpdmGetCertificateRequestPayload {
                    offset: self
                        .common
                        .peer_info
                        .peer_cert_chain_temp
                        .as_ref()
                        .unwrap()
                        .data_size,
                    length: MAX_SPDM_CERT_PORTION_LEN as u16,
                    slot_id: self.common.encap_context.req_slot_id,
                },
            ),
        };

        let _ = encapsulated_request.spdm_encode(&mut self.common, encap_request)?;

        Ok(())
    }

    pub fn handle_encap_response_certificate(&mut self, encap_response: &[u8]) -> SpdmResult<bool> {
        let mut reader = Reader::init(encap_response);
        let mut get_cert_completed = false;
        match SpdmMessageHeader::read(&mut reader) {
            Some(encap_header) => {
                if encap_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match encap_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseCertificate => {
                        let certificate = SpdmCertificateResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        if let Some(certificate) = certificate {
                            debug!("!!! mut_auth certificate : {:02x?}\n", certificate);

                            let peer_cert_chain_temp = self
                                .common
                                .peer_info
                                .peer_cert_chain_temp
                                .as_mut()
                                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
                            let offset = peer_cert_chain_temp.data_size;

                            if certificate.portion_length as usize > MAX_SPDM_CERT_PORTION_LEN
                                || certificate.portion_length
                                    > config::MAX_SPDM_CERT_CHAIN_DATA_SIZE as u16 - offset
                            {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }
                            if certificate.remainder_length
                                >= config::MAX_SPDM_CERT_CHAIN_DATA_SIZE as u16
                                    - offset
                                    - certificate.portion_length
                            {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }

                            if certificate.slot_id != self.common.encap_context.req_slot_id {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }

                            if offset == 0 {
                                self.common.encap_context.encap_cert_size =
                                    certificate.portion_length + certificate.remainder_length;
                            }

                            if self.common.encap_context.encap_cert_size != 0
                                && self.common.encap_context.encap_cert_size
                                    != offset
                                        + certificate.portion_length
                                        + certificate.remainder_length
                            {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }

                            peer_cert_chain_temp.data[(offset as usize)
                                ..(offset as usize + certificate.portion_length as usize)]
                                .copy_from_slice(
                                    &certificate.cert_chain
                                        [0..(certificate.portion_length as usize)],
                                );

                            peer_cert_chain_temp.data_size = offset + certificate.portion_length;

                            if certificate.remainder_length == 0 {
                                get_cert_completed = true;
                            }
                        } else {
                            error!("!!! mut_auth certificate : fail !!!\n");
                            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let payload = SpdmMessageGeneralPayload::read(&mut reader)
                            .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
                        self.handle_encap_error_response_main(payload.param1)?;
                    }
                    _ => return Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => return Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
        if self.common.encap_context.encap_cert_size == 0 {
            self.common.peer_info.peer_cert_chain_temp = None;
            return Err(SPDM_STATUS_INVALID_CERT);
        }

        if !get_cert_completed {
            return Ok(true);
        }

        let result = self.verify_spdm_certificate_chain().map(|_| {
            self.common.peer_info.peer_cert_chain[self.common.encap_context.req_slot_id as usize] =
                self.common.peer_info.peer_cert_chain_temp.clone();
            self.common
                .runtime_info
                .set_peer_used_cert_chain_slot_id(self.common.encap_context.req_slot_id);
            false
        });

        self.common.peer_info.peer_cert_chain_temp = None;

        #[cfg(feature = "mandatory-mut-auth")]
        if result.is_ok() {
            self.common.mut_auth_done = true;
        }

        result
    }

    pub fn verify_spdm_certificate_chain(&mut self) -> SpdmResult {
        //
        // 1. Verify the integrity of cert chain
        //
        if self.common.peer_info.peer_cert_chain_temp.is_none() {
            error!("peer_cert_chain is not populated!\n");
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        let peer_cert_chain = self
            .common
            .peer_info
            .peer_cert_chain_temp
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
        if peer_cert_chain.data_size <= (4 + self.common.negotiate_info.base_hash_sel.get_size()) {
            return Err(SPDM_STATUS_INVALID_CERT);
        }

        let data_size_in_cert_chain =
            peer_cert_chain.data[0] as u16 + ((peer_cert_chain.data[1] as u16) << 8);
        if data_size_in_cert_chain != peer_cert_chain.data_size {
            return Err(SPDM_STATUS_INVALID_CERT);
        }

        let data_size =
            peer_cert_chain.data_size - 4 - self.common.negotiate_info.base_hash_sel.get_size();
        let mut data = [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE];
        data[0..(data_size as usize)].copy_from_slice(
            &peer_cert_chain.data[(4usize
                + self.common.negotiate_info.base_hash_sel.get_size() as usize)
                ..(peer_cert_chain.data_size as usize)],
        );
        let runtime_peer_cert_chain_data = SpdmCertChainData { data_size, data };
        info!("1. get runtime_peer_cert_chain_data!\n");

        //
        // 1.1 verify the integrity of the chain
        //
        if crypto::cert_operation::verify_cert_chain(
            &runtime_peer_cert_chain_data.data[..(runtime_peer_cert_chain_data.data_size as usize)],
        )
        .is_err()
        {
            error!("cert_chain verification - fail! - TBD later\n");
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        info!("1.1. integrity of cert_chain is verified!\n");

        //
        // 1.2 verify the root cert hash
        //
        let (root_cert_begin, root_cert_end) = crypto::cert_operation::get_cert_from_cert_chain(
            &runtime_peer_cert_chain_data.data[..(runtime_peer_cert_chain_data.data_size as usize)],
            0,
        )?;
        let root_cert = &runtime_peer_cert_chain_data.data[root_cert_begin..root_cert_end];
        if is_root_certificate(root_cert).is_ok() {
            let root_hash = if let Some(rh) =
                crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, root_cert)
            {
                rh
            } else {
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            };
            if root_hash.data[..(root_hash.data_size as usize)]
                != peer_cert_chain.data[4usize
                    ..(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)]
            {
                error!("root_hash - fail!\n");
                return Err(SPDM_STATUS_INVALID_CERT);
            }
            info!("1.2. root cert hash is verified!\n");
        }

        //
        // 2. verify the authority of cert chain if provisioned
        //
        let mut cert_chain_provisioned = false;
        let mut found_match = false;
        for peer_root_cert_data in self
            .common
            .provision_info
            .peer_root_cert_data
            .iter()
            .flatten()
        {
            cert_chain_provisioned = true;
            if root_cert.len() != peer_root_cert_data.data_size as usize {
                continue;
            }
            if root_cert[..] != peer_root_cert_data.data[..peer_root_cert_data.data_size as usize] {
                continue;
            } else {
                found_match = true;
                break;
            }
        }

        if cert_chain_provisioned && !found_match {
            return Err(SPDM_STATUS_INVALID_CERT);
        }

        info!("2. root cert is verified!\n");

        info!("cert_chain verification - pass!\n");
        Ok(())
    }
}
