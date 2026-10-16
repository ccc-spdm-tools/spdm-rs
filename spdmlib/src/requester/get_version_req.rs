// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_NEGOTIATION_FAIL, SPDM_STATUS_NOT_READY_PEER,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_spdm_version(&mut self, send_buffer: &mut [u8]) -> SpdmResult<usize> {
        // reset context on get version request
        self.common.reset_context();

        let send_used = self.encode_spdm_version(send_buffer)?;
        self.send_message(None, &send_buffer[..send_used], false)
            .await?;
        Ok(send_used)
    }

    #[maybe_async::maybe_async]
    pub async fn receive_spdm_version(&mut self, send_buffer: &[u8]) -> SpdmResult {
        info!("!!! receive version !!!");
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut used = self
            .receive_message(None, &mut receive_buffer, false)
            .await?;

        for _ in 0..super::handle_error_response_req::MAX_RESPOND_IF_READY_RETRY_COUNT {
            let result = self.handle_spdm_version_response(0, send_buffer, &receive_buffer[..used]);
            match result {
                Err(status) if status == SPDM_STATUS_NOT_READY_PEER => {
                    if let Some(ext_data) =
                        self.parse_response_not_ready_ext_data(&receive_buffer[..used])
                    {
                        let delay_us = 1usize << (ext_data.rdt_exponent as usize).min(31);
                        crate::time::sleep(delay_us);
                        used = self
                            .send_receive_respond_if_ready(
                                None,
                                SpdmRequestResponseCode::SpdmRequestGetVersion,
                                ext_data.token,
                                &mut receive_buffer,
                                false,
                            )
                            .await?;
                        continue;
                    }
                    return Err(SPDM_STATUS_NOT_READY_PEER);
                }
                other => return other,
            }
        }
        Err(SPDM_STATUS_NOT_READY_PEER)
    }

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_version(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used = self.send_spdm_version(&mut send_buffer).await?;
        self.receive_spdm_version(&send_buffer[..send_used]).await
    }

    pub fn encode_spdm_version(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetVersion,
            },
            payload: SpdmMessagePayload::SpdmGetVersionRequest(SpdmGetVersionRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_version_response(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseVersion => {
                    let version =
                        SpdmVersionResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(version) = version {
                        debug!("!!! version : {:02x?}\n", version);

                        let SpdmVersionResponsePayload {
                            version_number_entry_count,
                            mut versions,
                        } = version;

                        versions.sort_unstable_by(|a, b| b.version.cmp(&a.version));

                        let mut negotiate_version: Option<SpdmVersion> = None;

                        for spdm_version_struct in
                            versions.iter().take(version_number_entry_count as usize)
                        {
                            if self
                                .common
                                .config_info
                                .spdm_version
                                .contains(&Some(spdm_version_struct.version))
                            {
                                negotiate_version = Some(spdm_version_struct.version);
                                break;
                            }
                        }

                        if let Some(negotiate_version) = negotiate_version {
                            self.common.negotiate_info.spdm_version_sel = negotiate_version;
                            debug!(
                                "Version negotiated: {:?}",
                                self.common.negotiate_info.spdm_version_sel
                            );
                        } else {
                            debug!(
                                "Version negotiation failed! with given version list: {:?}",
                                versions
                            );
                            return Err(SPDM_STATUS_NEGOTIATION_FAIL);
                        }

                        // clear cache data
                        self.common.reset_runtime_info();

                        self.common.append_message_a(send_buffer)?;
                        self.common.append_message_a(&receive_buffer[..used])?;

                        Ok(())
                    } else {
                        error!("!!! version : fail !!!\n");
                        Err(SPDM_STATUS_INVALID_MSG_FIELD)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => self.spdm_handle_error_response_main(
                    Some(session_id),
                    receive_buffer,
                    SpdmRequestResponseCode::SpdmRequestGetVersion,
                    SpdmRequestResponseCode::SpdmResponseVersion,
                ),
                _ => Err(SPDM_STATUS_ERROR_PEER),
            },
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
