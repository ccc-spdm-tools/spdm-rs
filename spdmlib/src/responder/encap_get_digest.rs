// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use super::ResponderContext;

use crate::common::SpdmCodec;
use crate::error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD};
use crate::message::*;
use crate::protocol::{SpdmVersion, SPDM_MAX_SLOT_NUMBER};

impl ResponderContext {
    pub fn encode_encap_request_get_digest(&mut self, encap_request: &mut Writer) -> SpdmResult {
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetDigests,
            },
            payload: SpdmMessagePayload::SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload {}),
        };

        let _ = request.spdm_encode(&mut self.common, encap_request)?;

        Ok(())
    }

    pub fn handle_encap_response_digest(&mut self, encap_response: &[u8]) -> SpdmResult {
        let mut reader = Reader::init(encap_response);
        match SpdmMessageHeader::read(&mut reader) {
            Some(header) => {
                if header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseDigests => {
                        let multi_key = if self.common.negotiate_info.spdm_version_sel
                            >= SpdmVersion::SpdmVersion14
                        {
                            self.common.negotiate_info.multi_key_conn_req
                        } else {
                            self.common.negotiate_info.multi_key_conn_rsp
                        };
                        let digests = SpdmDigestsResponsePayload::spdm_read_with_multi_key(
                            &mut self.common,
                            &mut reader,
                            multi_key,
                        );
                        if let Some(digests) = digests {
                            debug!("!!! digests : {:02x?}\n", digests);
                            if self.common.negotiate_info.spdm_version_sel
                                >= SpdmVersion::SpdmVersion14
                            {
                                self.common.peer_info.peer_provisioned_slot_mask =
                                    digests.slot_mask;
                                self.common.peer_info.peer_supported_slot_mask =
                                    digests.supported_slot_mask;
                                self.common.peer_info.peer_cert_info.fill(None);
                                self.common.peer_info.peer_key_pair_id.fill(None);
                                self.common.peer_info.peer_key_usage_bit_mask.fill(None);
                                if self.common.negotiate_info.multi_key_conn_req {
                                    let mut packed_index = 0;
                                    for slot_index in 0..SPDM_MAX_SLOT_NUMBER {
                                        if digests.slot_mask & (1 << slot_index) != 0 {
                                            self.common.peer_info.peer_key_pair_id[slot_index] =
                                                Some(digests.key_pair_id[packed_index]);
                                            self.common.peer_info.peer_cert_info[slot_index] =
                                                Some(digests.certificate_info[packed_index]);
                                            self.common.peer_info.peer_key_usage_bit_mask
                                                [slot_index] =
                                                Some(digests.key_usage_mask[packed_index]);
                                            packed_index += 1;
                                        }
                                    }
                                }
                            }
                            Ok(())
                        } else {
                            error!("!!! digests : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    _ => Err(SPDM_STATUS_INVALID_MSG_FIELD),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
