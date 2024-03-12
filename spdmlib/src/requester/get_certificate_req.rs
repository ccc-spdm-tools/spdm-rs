// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::{self, check_leaf_certificate, is_root_certificate};
use crate::error::{
    SpdmResult, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_CERT,
    SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_INVALID_STATE_LOCAL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    async fn send_receive_spdm_certificate_partial(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        total_size: u16,
        offset: u16,
        length: u16,
    ) -> SpdmResult<(u16, u16)> {
        info!("send spdm certificate\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used =
            self.encode_spdm_certificate_partial(slot_id, offset, length, &mut send_buffer)?;

        self.send_message(session_id, &send_buffer[..send_used], false)
            .await?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(session_id, &mut receive_buffer, false)
            .await?;

        self.handle_spdm_certificate_partial_response(
            session_id,
            slot_id,
            total_size,
            offset,
            length,
            &send_buffer[..send_used],
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_certificate_partial(
        &mut self,
        slot_id: u8,
        offset: u16,
        length: u16,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
            },
            payload: SpdmMessagePayload::SpdmGetCertificateRequest(
                SpdmGetCertificateRequestPayload {
                    slot_id,
                    offset,
                    length,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_spdm_certificate_partial_response(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        total_size: u16,
        offset: u16,
        length: u16,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult<(u16, u16)> {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseCertificate => {
                        let certificate = SpdmCertificateResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let used = reader.used();
                        if let Some(certificate) = certificate {
                            debug!("!!! certificate : {:02x?}\n", certificate);

                            if certificate.portion_length == 0
                                || certificate.portion_length > length
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
                            if total_size != 0
                                && total_size
                                    != offset
                                        + certificate.portion_length
                                        + certificate.remainder_length
                            {
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }
                            if certificate.slot_id != slot_id {
                                error!("slot id is not match between requester and responder!\n");
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }

                            let peer_cert_chain_temp = self
                                .common
                                .peer_info
                                .peer_cert_chain_temp
                                .as_mut()
                                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;

                            peer_cert_chain_temp.data[(offset as usize)
                                ..(offset as usize + certificate.portion_length as usize)]
                                .copy_from_slice(
                                    &certificate.cert_chain
                                        [0..(certificate.portion_length as usize)],
                                );

                            peer_cert_chain_temp.data_size = offset + certificate.portion_length;

                            match session_id {
                                None => {
                                    self.common.append_message_b(send_buffer)?;
                                    self.common.append_message_b(&receive_buffer[..used])?;
                                }
                                Some(_session_id) => {}
                            }

                            Ok((certificate.portion_length, certificate.remainder_length))
                        } else {
                            error!("!!! certificate : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let status = self.spdm_handle_error_response_main(
                            session_id,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestGetCertificate,
                            SpdmRequestResponseCode::SpdmResponseCertificate,
                        );
                        match status {
                            Err(status) => Err(status),
                            Ok(()) => Err(SPDM_STATUS_ERROR_PEER),
                        }
                    }
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_certificate(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
    ) -> SpdmResult {
        let mut offset = 0u16;
        let mut length = MAX_SPDM_CERT_PORTION_LEN as u16;
        let mut total_size = 0u16;

        if slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetCertificate,
            session_id,
        );

        self.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());
        while length != 0 {
            let (portion_length, remainder_length) = self
                .send_receive_spdm_certificate_partial(
                    session_id, slot_id, total_size, offset, length,
                )
                .await?;
            if total_size == 0 {
                total_size = portion_length + remainder_length;
            }
            offset += portion_length;
            length = remainder_length;
            if length > MAX_SPDM_CERT_PORTION_LEN as u16 {
                length = MAX_SPDM_CERT_PORTION_LEN as u16;
            }
        }
        if total_size == 0 {
            self.common.peer_info.peer_cert_chain_temp = None;
            return Err(SPDM_STATUS_INVALID_CERT);
        }

        let result = self.verify_spdm_certificate_chain();
        if result.is_ok() {
            self.common.peer_info.peer_cert_chain[slot_id as usize]
                .clone_from(&self.common.peer_info.peer_cert_chain_temp);
        }
        self.common.peer_info.peer_cert_chain_temp = None;
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
        // 1.3 verify the leaf cert
        //
        let (leaf_cert_begin, leaf_cert_end) = crypto::cert_operation::get_cert_from_cert_chain(
            &runtime_peer_cert_chain_data.data[..(runtime_peer_cert_chain_data.data_size as usize)],
            -1,
        )?;
        let leaf_cert = &runtime_peer_cert_chain_data.data[leaf_cert_begin..leaf_cert_end];
        if check_leaf_certificate(
            leaf_cert,
            self.common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::ALIAS_CERT_CAP),
        )
        .is_ok()
        {
            info!("1.3. Leaf cert is verified\n");
        } else {
            info!("Leaf cert verification - fail! \n");
            return Err(SPDM_STATUS_INVALID_CERT);
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
