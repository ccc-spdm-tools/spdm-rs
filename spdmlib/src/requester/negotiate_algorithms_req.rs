// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_NEGOTIATION_FAIL,
};

use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_spdm_algorithm(&mut self, send_buffer: &mut [u8]) -> SpdmResult<usize> {
        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            None,
        );

        let send_used = self.encode_spdm_algorithm(send_buffer)?;
        self.send_message(None, &send_buffer[..send_used], false)
            .await?;
        Ok(send_used)
    }

    #[maybe_async::maybe_async]
    pub async fn receive_spdm_algorithm(&mut self, send_buffer: &[u8]) -> SpdmResult {
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(None, &mut receive_buffer, false)
            .await?;
        self.handle_spdm_algorithm_response(0, send_buffer, &receive_buffer[..used])
    }

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_algorithm(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used = self.send_spdm_algorithm(&mut send_buffer).await?;
        self.receive_spdm_algorithm(&send_buffer[..send_used]).await
    }

    pub fn encode_spdm_algorithm(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut other_params_support = SpdmAlgoOtherParams::empty();

        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            other_params_support.insert(self.common.config_info.other_params_support);
        }
        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13 {
            if self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY)
            {
                other_params_support.insert(SpdmAlgoOtherParams::MULTI_KEY_CONN);
            }
            if self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_CONN_SEL)
                && self
                    .common
                    .config_info
                    .other_params_support
                    .contains(SpdmAlgoOtherParams::MULTI_KEY_CONN)
            {
                other_params_support.insert(SpdmAlgoOtherParams::MULTI_KEY_CONN);
            }
        }

        let mel_specification =
            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13 {
                self.common.config_info.mel_specification
            } else {
                SpdmMelSpecification::empty()
            };

        let mut alg_struct_count = 0;
        let mut alg_struct: [SpdmAlgStruct; MAX_SUPPORTED_ALG_STRUCTURE_COUNT] =
            gen_array_clone(SpdmAlgStruct::default(), MAX_SUPPORTED_ALG_STRUCTURE_COUNT);
        if self.common.config_info.dhe_algo.is_valid() {
            alg_struct[alg_struct_count].alg_type = SpdmAlgType::SpdmAlgTypeDHE;
            alg_struct[alg_struct_count].alg_supported =
                SpdmAlg::SpdmAlgoDhe(self.common.config_info.dhe_algo);
            alg_struct_count += 1;
        }
        if self.common.config_info.aead_algo.is_valid() {
            alg_struct[alg_struct_count].alg_type = SpdmAlgType::SpdmAlgTypeAEAD;
            alg_struct[alg_struct_count].alg_supported =
                SpdmAlg::SpdmAlgoAead(self.common.config_info.aead_algo);
            alg_struct_count += 1;
        }
        if self.common.config_info.req_asym_algo.is_valid() {
            alg_struct[alg_struct_count].alg_type = SpdmAlgType::SpdmAlgTypeReqAsym;
            alg_struct[alg_struct_count].alg_supported =
                SpdmAlg::SpdmAlgoReqAsym(self.common.config_info.req_asym_algo);
            alg_struct_count += 1;
        }
        if self.common.config_info.key_schedule_algo.is_valid() {
            alg_struct[alg_struct_count].alg_type = SpdmAlgType::SpdmAlgTypeKeySchedule;
            alg_struct[alg_struct_count].alg_supported =
                SpdmAlg::SpdmAlgoKeySchedule(self.common.config_info.key_schedule_algo);
            alg_struct_count += 1;
        }
        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
            if self.common.config_info.pqc_req_asym_algo.is_valid() {
                alg_struct[alg_struct_count].alg_type = SpdmAlgType::SpdmAlgTypePqcReqAsym;
                alg_struct[alg_struct_count].alg_supported =
                    SpdmAlg::SpdmAlgoPqcReqAsym(self.common.config_info.pqc_req_asym_algo);
                alg_struct_count += 1;
            }
            if self.common.config_info.kem_algo.is_valid() {
                alg_struct[alg_struct_count].alg_type = SpdmAlgType::SpdmAlgTypeKEM;
                alg_struct[alg_struct_count].alg_supported =
                    SpdmAlg::SpdmAlgoKem(self.common.config_info.kem_algo);
                alg_struct_count += 1;
            }
        }

        let pqc_asym_algo =
            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
                self.common.config_info.pqc_asym_algo
            } else {
                SpdmPqcAsymAlgo::empty()
            };

        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                SpdmNegotiateAlgorithmsRequestPayload {
                    measurement_specification: self.common.config_info.measurement_specification,
                    other_params_support,
                    base_asym_algo: self.common.config_info.base_asym_algo,
                    base_hash_algo: self.common.config_info.base_hash_algo,
                    pqc_asym_algo,
                    mel_specification,
                    alg_struct_count: alg_struct_count as u8,
                    alg_struct,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_algorithm_response(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseAlgorithms => {
                        let algorithms =
                            SpdmAlgorithmsResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let used = reader.used();
                        if let Some(algorithms) = algorithms {
                            debug!("!!! algorithms : {:02x?}\n", algorithms);

                            self.common.negotiate_info.measurement_specification_sel =
                                algorithms.measurement_specification_sel;

                            self.common.negotiate_info.other_params_support =
                                algorithms.other_params_selection;

                            if self.common.negotiate_info.spdm_version_sel
                                >= SpdmVersion::SpdmVersion13
                            {
                                if self
                                    .common
                                    .negotiate_info
                                    .rsp_capabilities_sel
                                    .contains(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY)
                                {
                                    self.common.negotiate_info.multi_key_conn_rsp = true;
                                } else if self
                                    .common
                                    .negotiate_info
                                    .rsp_capabilities_sel
                                    .contains(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_CONN_SEL)
                                {
                                    self.common.negotiate_info.multi_key_conn_rsp = self
                                        .common
                                        .config_info
                                        .other_params_support
                                        .contains(SpdmAlgoOtherParams::MULTI_KEY_CONN);
                                } else {
                                    self.common.negotiate_info.multi_key_conn_rsp = false;
                                }

                                if algorithms
                                    .other_params_selection
                                    .contains(SpdmAlgoOtherParams::MULTI_KEY_CONN)
                                {
                                    if !self
                                        .common
                                        .config_info
                                        .req_capabilities
                                        .contains(SpdmRequestCapabilityFlags::MULTI_KEY_CAP_ONLY)
                                        && !self.common.config_info.req_capabilities.contains(
                                            SpdmRequestCapabilityFlags::MULTI_KEY_CAP_CONN_SEL,
                                        )
                                    {
                                        return Err(SPDM_STATUS_NEGOTIATION_FAIL);
                                    }
                                    self.common.negotiate_info.multi_key_conn_req = true;
                                } else {
                                    if self
                                        .common
                                        .config_info
                                        .req_capabilities
                                        .contains(SpdmRequestCapabilityFlags::MULTI_KEY_CAP_ONLY)
                                    {
                                        return Err(SPDM_STATUS_NEGOTIATION_FAIL);
                                    }
                                    self.common.negotiate_info.multi_key_conn_req = false;
                                }
                            }

                            self.common.negotiate_info.measurement_hash_sel =
                                algorithms.measurement_hash_algo;
                            if algorithms.base_hash_sel.bits() == 0 {
                                return Err(SPDM_STATUS_NEGOTIATION_FAIL);
                            }
                            self.common.negotiate_info.base_hash_sel = algorithms.base_hash_sel;
                            self.common.negotiate_info.base_asym_sel = algorithms.base_asym_sel;
                            if self.common.negotiate_info.spdm_version_sel
                                >= SpdmVersion::SpdmVersion14
                            {
                                self.common.negotiate_info.pqc_asym_sel = algorithms.pqc_asym_sel;
                            }
                            if algorithms.base_asym_sel.bits() == 0
                                && algorithms.pqc_asym_sel.bits() == 0
                            {
                                return Err(SPDM_STATUS_NEGOTIATION_FAIL);
                            }
                            for alg in algorithms
                                .alg_struct
                                .iter()
                                .take(algorithms.alg_struct_count as usize)
                            {
                                match &alg.alg_supported {
                                    SpdmAlg::SpdmAlgoDhe(v) => {
                                        if v.is_no_more_than_one_selected() || v.bits() == 0 {
                                            self.common.negotiate_info.dhe_sel = *v;
                                        } else {
                                            error!(
                                                "unknown Dhe algorithm structure:{:X?}\n",
                                                v.bits()
                                            );
                                            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                        }
                                    }
                                    SpdmAlg::SpdmAlgoAead(v) => {
                                        if v.is_no_more_than_one_selected() || v.bits() == 0 {
                                            self.common.negotiate_info.aead_sel = *v;
                                        } else {
                                            error!(
                                                "unknown aead algorithm structure:{:X?}\n",
                                                v.bits()
                                            );
                                            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                        }
                                    }
                                    SpdmAlg::SpdmAlgoReqAsym(v) => {
                                        if v.is_no_more_than_one_selected() || v.bits() == 0 {
                                            self.common.negotiate_info.req_asym_sel = *v;
                                        } else {
                                            error!(
                                                "unknown req asym algorithm structure:{:X?}\n",
                                                v.bits()
                                            );
                                            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                        }
                                    }
                                    SpdmAlg::SpdmAlgoKeySchedule(v) => {
                                        if v.is_no_more_than_one_selected() || v.bits() == 0 {
                                            self.common.negotiate_info.key_schedule_sel = *v;
                                        } else {
                                            error!(
                                                "unknown key schedule algorithm structure:{:X?}\n",
                                                v.bits()
                                            );
                                            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                        }
                                    }
                                    SpdmAlg::SpdmAlgoPqcReqAsym(v) => {
                                        if self.common.negotiate_info.spdm_version_sel
                                            >= SpdmVersion::SpdmVersion14
                                        {
                                            if v.is_no_more_than_one_selected() || v.bits() == 0 {
                                                self.common.negotiate_info.pqc_req_asym_sel = *v;
                                            } else {
                                                error!(
                                                    "unknown pqc req asym algorithm structure:{:X?}\n",
                                                    v.bits()
                                                );
                                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                            }
                                        }
                                    }
                                    SpdmAlg::SpdmAlgoKem(v) => {
                                        if self.common.negotiate_info.spdm_version_sel
                                            >= SpdmVersion::SpdmVersion14
                                        {
                                            if v.is_no_more_than_one_selected() || v.bits() == 0 {
                                                self.common.negotiate_info.kem_sel = *v;
                                            } else {
                                                error!(
                                                    "unknown Kem algorithm structure:{:X?}\n",
                                                    v.bits()
                                                );
                                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                            }
                                        }
                                    }
                                    SpdmAlg::SpdmAlgoUnknown(_v) => {}
                                }
                            }

                            if self.common.negotiate_info.spdm_version_sel
                                >= SpdmVersion::SpdmVersion13
                            {
                                if self.common.config_info.mel_specification
                                    != SpdmMelSpecification::empty()
                                    && self
                                        .common
                                        .negotiate_info
                                        .rsp_capabilities_sel
                                        .contains(SpdmResponseCapabilityFlags::MEL_CAP)
                                {
                                    if algorithms.mel_specification_sel
                                        != SpdmMelSpecification::DMTF_MEL_SPEC
                                    {
                                        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                    }
                                } else if algorithms.mel_specification_sel
                                    != SpdmMelSpecification::empty()
                                {
                                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                                }
                                self.common.negotiate_info.mel_specification_sel =
                                    algorithms.mel_specification_sel;
                            }

                            self.common.append_message_a(send_buffer)?;
                            self.common.append_message_a(&receive_buffer[..used])?;

                            return Ok(());
                        }
                        error!("!!! algorithms : fail !!!\n");
                        Err(SPDM_STATUS_INVALID_MSG_FIELD)
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
                            SpdmRequestResponseCode::SpdmResponseAlgorithms,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
