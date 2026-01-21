// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD};
use crate::message::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    async fn send_spdm_vendor_defined_request_op(
        &mut self,
        session_id: Option<u32>,
        standard_id: RegistryOrStandardsBodyID,
        vendor_id_struct: VendorIDStruct,
        req_payload_struct: VendorDefinedReqPayloadStruct,
    ) -> SpdmResult {
        info!("send vendor defined request\n");

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
            session_id,
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self.encode_spdm_vendor_defined_request(
            standard_id,
            vendor_id_struct,
            req_payload_struct,
            &mut send_buffer,
        )?;

        {
            let mut guard = self.exec_state.send_buffer.lock();
            guard.0[..used].copy_from_slice(&send_buffer[..used]);
            guard.1 = used;
        }

        self.send_message(session_id, &send_buffer[..used], false)
            .await?;

        Ok(())
    }

    #[maybe_async::maybe_async]
    async fn receive_spdm_vendor_defined_response_op(
        &mut self,
        session_id: Option<u32>,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let receive_used = self
            .receive_message(session_id, &mut receive_buffer, false)
            .await?;

        self.handle_spdm_vendor_defined_respond(session_id, &receive_buffer[..receive_used])
    }

    pub fn encode_spdm_vendor_defined_request(
        &mut self,
        standard_id: RegistryOrStandardsBodyID,
        vendor_id_struct: VendorIDStruct,
        req_payload_struct: VendorDefinedReqPayloadStruct,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
            },
            payload: SpdmMessagePayload::SpdmVendorDefinedRequest(
                SpdmVendorDefinedRequestPayload {
                    standard_id,
                    vendor_id: vendor_id_struct,
                    req_payload: req_payload_struct,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_vendor_defined_respond(
        &mut self,
        session_id: Option<u32>,
        receive_buffer: &[u8],
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse => {
                        match SpdmVendorDefinedResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        ) {
                            Some(spdm_vendor_defined_response_payload) => {
                                Ok(spdm_vendor_defined_response_payload.rsp_payload)
                            }
                            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let status = self.spdm_handle_error_response_main(
                            session_id,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
                            SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse,
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
    pub async fn send_spdm_vendor_defined_request(
        &mut self,
        session_id: Option<u32>,
        standard_id: RegistryOrStandardsBodyID,
        vendor_id_struct: VendorIDStruct,
        req_payload_struct: VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        use crate::requester::context::{SpdmCommandState, VendorSubstate};

        if self.exec_state.command_state == SpdmCommandState::Idle {
            self.exec_state.command_state =
                SpdmCommandState::VendorRequesting(VendorSubstate::Init);
        }

        if self.exec_state.command_state == SpdmCommandState::VendorRequesting(VendorSubstate::Init)
        {
            self.exec_state.command_state =
                SpdmCommandState::VendorRequesting(VendorSubstate::Send);
            self.send_spdm_vendor_defined_request_op(
                session_id,
                standard_id,
                vendor_id_struct,
                req_payload_struct,
            )
            .await?;
        }

        let result = if self.exec_state.command_state
            == SpdmCommandState::VendorRequesting(VendorSubstate::Send)
        {
            self.exec_state.command_state =
                SpdmCommandState::VendorRequesting(VendorSubstate::Receive);
            let result = self
                .receive_spdm_vendor_defined_response_op(session_id)
                .await?;
            self.exec_state.command_state = SpdmCommandState::Idle;
            result
        } else {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        };

        Ok(result)
    }
}
