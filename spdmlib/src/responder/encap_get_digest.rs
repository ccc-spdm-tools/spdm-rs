// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use super::ResponderContext;

use crate::common::SpdmCodec;
use crate::error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD};
use crate::message::*;

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
                        let digests =
                            SpdmDigestsResponsePayload::spdm_read(&mut self.common, &mut reader);
                        if let Some(digests) = digests {
                            debug!("!!! digests : {:02x?}\n", digests);
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
