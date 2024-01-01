// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Codec;
use codec::Writer;
use spdmlib::error::SPDM_STATUS_BUFFER_FULL;
use spdmlib::error::SPDM_STATUS_INVALID_MSG_FIELD;
use spdmlib::{
    error::SpdmResult,
    message::{VendorDefinedReqPayloadStruct, MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE},
    requester::RequesterContext,
};

use crate::pci_idekm::vendor_id;
use crate::pci_idekm::KGoStopAckDataObject;
use crate::pci_idekm::KSetStopDataObject;
use crate::pci_idekm::STANDARD_ID;

use super::IdekmReqContext;

impl IdekmReqContext {
    #[allow(clippy::too_many_arguments)]
    #[maybe_async::maybe_async]
    pub async fn pci_ide_km_key_set_stop(
        &mut self,
        // IN
        spdm_requester: &mut RequesterContext,
        session_id: u32,
        stream_id: u8,
        key_set: u8,
        key_direction: u8,
        key_sub_stream: u8,
        port_index: u8,
    ) -> SpdmResult {
        let mut vendor_defined_req_payload_struct = VendorDefinedReqPayloadStruct {
            req_length: 0,
            vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
        };

        let mut writer =
            Writer::init(&mut vendor_defined_req_payload_struct.vendor_defined_req_payload);

        vendor_defined_req_payload_struct.req_length = KSetStopDataObject {
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        }
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?
            as u16;

        let vendor_defined_rsp_payload_struct = spdm_requester
            .send_spdm_vendor_defined_request(
                Some(session_id),
                STANDARD_ID,
                vendor_id(),
                vendor_defined_req_payload_struct,
            )
            .await?;

        let kgo_stop_ack_data_object = KGoStopAckDataObject::read_bytes(
            &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
                [..vendor_defined_rsp_payload_struct.rsp_length as usize],
        )
        .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

        if kgo_stop_ack_data_object.stream_id != stream_id
            || kgo_stop_ack_data_object.key_set != key_set
            || kgo_stop_ack_data_object.key_direction != key_direction
            || kgo_stop_ack_data_object.key_sub_stream != key_sub_stream
            || kgo_stop_ack_data_object.port_index != port_index
        {
            Err(SPDM_STATUS_INVALID_MSG_FIELD)
        } else {
            Ok(())
        }
    }
}
