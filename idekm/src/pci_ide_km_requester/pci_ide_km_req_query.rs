// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Writer};
use spdmlib::{
    error::{SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_MSG_FIELD},
    message::{VendorDefinedReqPayloadStruct, MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE},
    requester::RequesterContext,
};

use crate::pci_idekm::{
    vendor_id, QueryDataObject, QueryRespDataObject, PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT,
    STANDARD_ID,
};

use super::IdekmReqContext;

impl IdekmReqContext {
    #[allow(clippy::too_many_arguments)]
    #[maybe_async::maybe_async]
    pub async fn pci_ide_km_query(
        &mut self,
        // IN
        spdm_requester: &mut RequesterContext,
        session_id: u32,
        port_index: u8,
        // OUT
        dev_func_num: &mut u8,
        bus_num: &mut u8,
        segment: &mut u8,
        max_port_index: &mut u8,
        ide_reg_block: &mut [u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT],
        ide_reg_block_cnt: &mut usize,
    ) -> SpdmResult {
        let mut vendor_defined_req_payload_struct = VendorDefinedReqPayloadStruct {
            req_length: 0,
            vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
        };

        let mut writer =
            Writer::init(&mut vendor_defined_req_payload_struct.vendor_defined_req_payload);

        vendor_defined_req_payload_struct.req_length = QueryDataObject { port_index }
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

        let query_resp_data_object = QueryRespDataObject::read_bytes(
            &vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload
                [..vendor_defined_rsp_payload_struct.rsp_length as usize],
        )
        .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

        if port_index != query_resp_data_object.port_index {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        *dev_func_num = query_resp_data_object.dev_func_num;
        *bus_num = query_resp_data_object.bus_num;
        *segment = query_resp_data_object.segment;
        *max_port_index = query_resp_data_object.max_port_index;
        *ide_reg_block = query_resp_data_object.ide_reg_block;
        *ide_reg_block_cnt = query_resp_data_object.ide_reg_block_cnt;

        Ok(())
    }
}
