// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::SPDM_STATUS_INVALID_STATE_PEER;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;

impl ResponderContext {
    pub fn handle_spdm_algorithm<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (_, rsp_slice) = self.write_spdm_algorithm(bytes, writer);
        (Ok(()), rsp_slice)
    }

    pub fn write_spdm_algorithm<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if self.common.runtime_info.get_connection_state()
            != SpdmConnectionState::SpdmConnectionAfterCapabilities
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
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
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
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            None,
        );

        let other_params_support;

        let negotiate_algorithms =
            SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(negotiate_algorithms) = negotiate_algorithms {
            debug!("!!! negotiate_algorithms : {:02x?}\n", negotiate_algorithms);
            other_params_support = negotiate_algorithms.other_params_support;
            self.common.negotiate_info.measurement_specification_sel =
                negotiate_algorithms.measurement_specification;
            self.common.negotiate_info.base_hash_sel = negotiate_algorithms.base_hash_algo;
            self.common.negotiate_info.base_asym_sel = negotiate_algorithms.base_asym_algo;
            for alg in negotiate_algorithms
                .alg_struct
                .iter()
                .take(negotiate_algorithms.alg_struct_count as usize)
            {
                match &alg.alg_supported {
                    SpdmAlg::SpdmAlgoDhe(v) => {
                        if v.is_valid() {
                            self.common.negotiate_info.dhe_sel = *v;
                        } else {
                            error!("unknown Dhe algorithm structure:{:X?}\n", v.bits());
                            self.write_spdm_error(
                                SpdmErrorCode::SpdmErrorInvalidRequest,
                                0,
                                writer,
                            );
                            return (
                                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                                Some(writer.used_slice()),
                            );
                        }
                    }
                    SpdmAlg::SpdmAlgoAead(v) => {
                        if v.is_valid() {
                            self.common.negotiate_info.aead_sel = *v;
                        } else {
                            error!("unknown aead algorithm structure:{:X?}\n", v.bits());
                            self.write_spdm_error(
                                SpdmErrorCode::SpdmErrorInvalidRequest,
                                0,
                                writer,
                            );
                            return (
                                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                                Some(writer.used_slice()),
                            );
                        }
                    }
                    SpdmAlg::SpdmAlgoReqAsym(v) => {
                        if v.is_valid() {
                            self.common.negotiate_info.req_asym_sel = *v;
                        } else {
                            error!("unknown req asym algorithm structure:{:X?}\n", v.bits());
                            self.write_spdm_error(
                                SpdmErrorCode::SpdmErrorInvalidRequest,
                                0,
                                writer,
                            );
                            return (
                                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                                Some(writer.used_slice()),
                            );
                        }
                    }
                    SpdmAlg::SpdmAlgoKeySchedule(v) => {
                        if v.is_valid() {
                            self.common.negotiate_info.key_schedule_sel = *v;
                        } else {
                            error!("unknown key schedule algorithm structure:{:X?}\n", v.bits());
                            self.write_spdm_error(
                                SpdmErrorCode::SpdmErrorInvalidRequest,
                                0,
                                writer,
                            );
                            return (
                                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                                Some(writer.used_slice()),
                            );
                        }
                    }
                    SpdmAlg::SpdmAlgoUnknown(_v) => {}
                }
            }
        } else {
            error!("!!! negotiate_algorithms : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        if self
            .common
            .append_message_a(&bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        self.common
            .negotiate_info
            .measurement_specification_sel
            .prioritize(self.common.config_info.measurement_specification);
        self.common.negotiate_info.measurement_hash_sel =
            self.common.config_info.measurement_hash_algo;
        self.common
            .negotiate_info
            .base_hash_sel
            .prioritize(self.common.config_info.base_hash_algo);
        self.common
            .negotiate_info
            .base_asym_sel
            .prioritize(self.common.config_info.base_asym_algo);
        self.common
            .negotiate_info
            .dhe_sel
            .prioritize(self.common.config_info.dhe_algo);
        self.common
            .negotiate_info
            .aead_sel
            .prioritize(self.common.config_info.aead_algo);
        self.common
            .negotiate_info
            .req_asym_sel
            .prioritize(self.common.config_info.req_asym_algo);
        self.common
            .negotiate_info
            .key_schedule_sel
            .prioritize(self.common.config_info.key_schedule_algo);

        //
        // update cert chain - append root cert hash
        //
        if self.common.construct_my_cert_chain().is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        info!("send spdm algorithm\n");

        let other_params_selection = self.common.config_info.opaque_support & other_params_support;
        self.common.negotiate_info.opaque_data_support = other_params_selection;

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmAlgorithmsResponse(SpdmAlgorithmsResponsePayload {
                measurement_specification_sel: self
                    .common
                    .negotiate_info
                    .measurement_specification_sel,
                other_params_selection,
                measurement_hash_algo: self.common.negotiate_info.measurement_hash_sel,
                base_asym_sel: self.common.negotiate_info.base_asym_sel,
                base_hash_sel: self.common.negotiate_info.base_hash_sel,
                alg_struct_count: 4,
                alg_struct: [
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                        alg_supported: SpdmAlg::SpdmAlgoDhe(self.common.negotiate_info.dhe_sel),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                        alg_supported: SpdmAlg::SpdmAlgoAead(self.common.negotiate_info.aead_sel),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                        alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                            self.common.negotiate_info.req_asym_sel,
                        ),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                        alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                            self.common.negotiate_info.key_schedule_sel,
                        ),
                    },
                ],
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
        if self.common.append_message_a(writer.used_slice()).is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }
}
