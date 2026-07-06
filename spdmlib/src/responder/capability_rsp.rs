// Copyright (c) 2020, 2026 Intel Corporation
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
    pub fn handle_spdm_capability<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        self.write_spdm_capability_response(bytes, writer)
    }

    pub fn write_spdm_capability_response<'a>(
        &mut self,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if self.common.runtime_info.get_connection_state()
            != SpdmConnectionState::SpdmConnectionAfterVersion
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(SpdmMessageHeader {
            version,
            request_response_code: _,
        }) = message_header
        {
            if version < SpdmVersion::SpdmVersion10 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            self.common.negotiate_info.spdm_version_sel = version;
        } else {
            error!("!!! get_capabilities : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            None,
        );

        let get_capabilities =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut self.common, &mut reader);
        let supported_algos_requested;
        if let Some(get_capabilities) = get_capabilities {
            debug!("!!! get_capabilities : {:02x?}\n", get_capabilities);
            supported_algos_requested = get_capabilities.supported_algos_requested;

            #[cfg(feature = "mandatory-mut-auth")]
            if !get_capabilities
                .flags
                .contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP)
            {
                error!("!!! get_capabilities : mut-auth is not supported by requester while mandatory-mut-auth is enabled in responder !!!\n");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
                return (
                    Err(crate::error::SPDM_STATUS_UNSUPPORTED_CAP),
                    Some(writer.used_slice()),
                );
            }

            self.common.negotiate_info.req_ct_exponent_sel = get_capabilities.ct_exponent;
            self.common.negotiate_info.req_capabilities_sel = get_capabilities.flags;
            self.common.negotiate_info.rsp_ct_exponent_sel =
                self.common.config_info.rsp_ct_exponent;
            self.common.negotiate_info.rsp_capabilities_sel =
                self.common.config_info.rsp_capabilities;

            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
                self.common.negotiate_info.req_data_transfer_size_sel =
                    get_capabilities.data_transfer_size;
                self.common.negotiate_info.req_max_spdm_msg_size_sel =
                    get_capabilities.max_spdm_msg_size;
                self.common.negotiate_info.rsp_data_transfer_size_sel =
                    self.common.config_info.data_transfer_size;
                self.common.negotiate_info.rsp_max_spdm_msg_size_sel =
                    self.common.config_info.max_spdm_msg_size;
            }
        } else {
            error!("!!! get_capabilities : fail !!!\n");
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

        info!("send spdm capability\n");

        // DSP0274 1.3+: when the Requester asked for SupportedAlgorithms (GET_CAPABILITIES
        // Param1) and both peers support CHUNK_CAP, return the algorithms block in CAPABILITIES.
        let supported_algorithms = if self.common.negotiate_info.spdm_version_sel
            >= SpdmVersion::SpdmVersion13
            && supported_algos_requested
            && self
                .common
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::CHUNK_CAP)
            && self
                .common
                .config_info
                .rsp_capabilities
                .contains(SpdmResponseCapabilityFlags::CHUNK_CAP)
        {
            Some(self.build_supported_algorithms_block())
        } else {
            None
        };

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCapabilities,
            },
            payload: SpdmMessagePayload::SpdmCapabilitiesResponse(
                SpdmCapabilitiesResponsePayload {
                    ct_exponent: self.common.config_info.rsp_ct_exponent,
                    flags: self.common.config_info.rsp_capabilities,
                    data_transfer_size: self.common.config_info.data_transfer_size,
                    max_spdm_msg_size: self.common.config_info.max_spdm_msg_size,
                    ex_flags: SpdmResponseCapabilityExFlags::default(),
                    supported_algorithms,
                },
            ),
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

    // Build the SupportedAlgorithms block from the Responder configuration. This mirrors the
    // NEGOTIATE_ALGORITHMS request body construction in the Requester so both messages report
    // the same supported algorithms.
    fn build_supported_algorithms_block(&self) -> SpdmSupportedAlgorithmsBlock {
        let mel_specification =
            if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13 {
                self.common.config_info.mel_specification
            } else {
                SpdmMelSpecification::empty()
            };

        let mut alg_struct_count = 0usize;
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

        SpdmSupportedAlgorithmsBlock {
            measurement_specification: self.common.config_info.measurement_specification,
            other_params_support: self.common.config_info.other_params_support,
            base_asym_algo: self.common.config_info.base_asym_algo,
            base_hash_algo: self.common.config_info.base_hash_algo,
            pqc_asym_algo,
            mel_specification,
            alg_struct_count: alg_struct_count as u8,
            alg_struct,
        }
    }
}
