// Copyright (c) 2020, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::message::*;

/// Base size (in bytes) of the SupportedAlgorithms block header, i.e. the size of
/// libspdm's `spdm_supported_algorithms_block_t`. This is the NEGOTIATE_ALGORITHMS
/// request body without the 2-byte SPDM message header, so its internal `Length`
/// field is `SUPPORTED_ALGO_BLOCK_FIXED_LEN + (2 + AlgFixedCount) * AlgStructCount`.
const SUPPORTED_ALGO_BLOCK_FIXED_LEN: u16 = 30;

/// DSP0274 1.3+ SupportedAlgorithms block. It is requested by the Requester via the
/// GET_CAPABILITIES Param1 `SUPPORTED_ALGOS_EXT_CAP` bit and returned by the Responder
/// appended to the CAPABILITIES response (after MaxSPDMmsgSize). Its on-wire layout is
/// identical to the NEGOTIATE_ALGORITHMS request body, except the block's `Length` field
/// excludes the 2-byte SPDM message header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpdmSupportedAlgorithmsBlock {
    pub measurement_specification: SpdmMeasurementSpecification,
    pub other_params_support: SpdmAlgoOtherParams,
    pub base_asym_algo: SpdmBaseAsymAlgo,
    pub base_hash_algo: SpdmBaseHashAlgo,
    pub pqc_asym_algo: SpdmPqcAsymAlgo, // SpdmVersion14
    pub mel_specification: SpdmMelSpecification,
    pub alg_struct_count: u8,
    pub alg_struct: [SpdmAlgStruct; MAX_SUPPORTED_ALG_STRUCTURE_COUNT],
}

impl SpdmCodec for SpdmSupportedAlgorithmsBlock {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .alg_struct_count
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1 (number of alg struct tables)
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        let alg_fixed_count = 2u16;
        let length =
            SUPPORTED_ALGO_BLOCK_FIXED_LEN + (2 + alg_fixed_count) * self.alg_struct_count as u16;
        cnt += length.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        cnt += self
            .measurement_specification
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .other_params_support
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .base_asym_algo
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .base_hash_algo
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
            cnt += self
                .pqc_asym_algo
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            for _i in 0..4 {
                cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved
            }
        }

        for _i in 0..8 {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved2
        }

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // ext_asym_count
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // ext_hash_count
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved3
        cnt += self
            .mel_specification
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        for algo in self.alg_struct.iter().take(self.alg_struct_count as usize) {
            cnt += algo.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmSupportedAlgorithmsBlock> {
        let alg_struct_count = u8::read(r)?; // param1 (number of alg struct tables)
        if alg_struct_count > MAX_SUPPORTED_ALG_STRUCTURE_COUNT as u8 {
            return None;
        }
        u8::read(r)?; // param2
        let length = u16::read(r)?;

        let measurement_specification = SpdmMeasurementSpecification::read(r)?;
        let other_params_support = SpdmAlgoOtherParams::read(r)?;
        let base_asym_algo = SpdmBaseAsymAlgo::read(r)?;
        let base_hash_algo = SpdmBaseHashAlgo::read(r)?;

        let pqc_asym_algo = if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14
        {
            SpdmPqcAsymAlgo::read(r)?
        } else {
            for _i in 0..4 {
                u8::read(r)?; // reserved
            }
            SpdmPqcAsymAlgo::default()
        };

        for _i in 0..8 {
            u8::read(r)?; // reserved2
        }

        let ext_asym_count = u8::read(r)?;
        if ext_asym_count != 0 {
            return None;
        }
        let ext_hash_count = u8::read(r)?;
        if ext_hash_count != 0 {
            return None;
        }
        u8::read(r)?; // reserved3
        let mel_specification = SpdmMelSpecification::read(r)?;

        let mut alg_struct =
            gen_array_clone(SpdmAlgStruct::default(), MAX_SUPPORTED_ALG_STRUCTURE_COUNT);
        let mut current_type = SpdmAlgType::Unknown(0);
        for algo in alg_struct.iter_mut().take(alg_struct_count as usize) {
            let alg = SpdmAlgStruct::read(r)?;
            // AlgStruct tables must be present in ascending AlgType order with no duplicates.
            if current_type.get_u8() >= alg.alg_type.get_u8() {
                return None;
            }
            current_type = alg.alg_type;
            *algo = alg;
        }

        let alg_fixed_count = 2u16;
        let calc_length =
            SUPPORTED_ALGO_BLOCK_FIXED_LEN + (2 + alg_fixed_count) * alg_struct_count as u16;
        if length != calc_length {
            return None;
        }

        Some(SpdmSupportedAlgorithmsBlock {
            measurement_specification,
            other_params_support,
            base_asym_algo,
            base_hash_algo,
            pqc_asym_algo,
            mel_specification,
            alg_struct_count,
            alg_struct,
        })
    }
}

// Version-independent Codec used to serialize the block inside a stored SpdmContext
// (SpdmPeerInfo export/import). Unlike spdm_encode, this is NOT the on-wire CAPABILITIES
// format: every field is stored unconditionally so a round-trip preserves the struct.
impl Codec for SpdmSupportedAlgorithmsBlock {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += self.measurement_specification.encode(writer)?;
        size += self.other_params_support.encode(writer)?;
        size += self.base_asym_algo.encode(writer)?;
        size += self.base_hash_algo.encode(writer)?;
        size += self.pqc_asym_algo.encode(writer)?;
        size += self.mel_specification.encode(writer)?;
        size += self.alg_struct_count.encode(writer)?;
        for algo in self.alg_struct.iter().take(self.alg_struct_count as usize) {
            size += algo.encode(writer)?;
        }
        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let measurement_specification = SpdmMeasurementSpecification::read(reader)?;
        let other_params_support = SpdmAlgoOtherParams::read(reader)?;
        let base_asym_algo = SpdmBaseAsymAlgo::read(reader)?;
        let base_hash_algo = SpdmBaseHashAlgo::read(reader)?;
        let pqc_asym_algo = SpdmPqcAsymAlgo::read(reader)?;
        let mel_specification = SpdmMelSpecification::read(reader)?;
        let alg_struct_count = u8::read(reader)?;
        if alg_struct_count > MAX_SUPPORTED_ALG_STRUCTURE_COUNT as u8 {
            return None;
        }
        let mut alg_struct =
            gen_array_clone(SpdmAlgStruct::default(), MAX_SUPPORTED_ALG_STRUCTURE_COUNT);
        for algo in alg_struct.iter_mut().take(alg_struct_count as usize) {
            *algo = SpdmAlgStruct::read(reader)?;
        }
        Some(SpdmSupportedAlgorithmsBlock {
            measurement_specification,
            other_params_support,
            base_asym_algo,
            base_hash_algo,
            pqc_asym_algo,
            mel_specification,
            alg_struct_count,
            alg_struct,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmGetCapabilitiesRequestPayload {
    pub ct_exponent: u8,
    pub flags: SpdmRequestCapabilityFlags,
    // New fields from SpdmVersion12
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
    // New fields from SpdmVersion14
    pub ex_flags: SpdmRequestCapabilityExFlags,
    // SpdmVersion13: request the Responder to return its SupportedAlgorithms in CAPABILITIES.
    // Drives the Param1 SUPPORTED_ALGOS_EXT_CAP bit; requires CHUNK_CAP.
    pub supported_algos_requested: bool,
}

impl SpdmCodec for SpdmGetCapabilitiesRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        let mut param1 = SpdmCapabilityParam1::empty();
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13
            && self.supported_algos_requested
        {
            param1.insert(SpdmCapabilityParam1::SUPPORTED_ALGOS_EXT_CAP);
        }
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved
            cnt += self
                .ct_exponent
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
                cnt += self
                    .ex_flags
                    .encode(bytes)
                    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            } else {
                cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
                // reserved2
            }
            cnt += self
                .flags
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            cnt += self
                .data_transfer_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += self
                .max_spdm_msg_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetCapabilitiesRequestPayload> {
        let mut supported_algos_requested = false;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13 {
            let param1 = SpdmCapabilityParam1::read(r)?; // param1
            supported_algos_requested =
                param1.contains(SpdmCapabilityParam1::SUPPORTED_ALGOS_EXT_CAP);
        } else {
            u8::read(r)?; // param1
        }
        u8::read(r)?; // param2

        let mut ct_exponent = 0;
        let mut flags = SpdmRequestCapabilityFlags::default();
        let mut ex_flags = SpdmRequestCapabilityExFlags::default();
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            u8::read(r)?; // reserved
            ct_exponent = u8::read(r)?;
            if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
                ex_flags = SpdmRequestCapabilityExFlags::read(r)?;
            } else {
                u16::read(r)?; // reserved2
            }
            flags = SpdmRequestCapabilityFlags::read(r)?;

            // check req_capability
            if flags.contains(SpdmRequestCapabilityFlags::PSK_RSVD) {
                return None;
            }
            if flags.contains(SpdmRequestCapabilityFlags::KEY_EX_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::PSK_CAP)
            {
                if !flags.contains(SpdmRequestCapabilityFlags::MAC_CAP) {
                    return None;
                }
            } else {
                if flags.contains(SpdmRequestCapabilityFlags::MAC_CAP)
                    || flags.contains(SpdmRequestCapabilityFlags::ENCRYPT_CAP)
                    || flags.contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
                    || flags.contains(SpdmRequestCapabilityFlags::HBEAT_CAP)
                    || flags.contains(SpdmRequestCapabilityFlags::KEY_UPD_CAP)
                {
                    return None;
                }
                if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13
                    && flags.contains(SpdmRequestCapabilityFlags::EVENT_CAP)
                {
                    return None;
                }
            }
            if !flags.contains(SpdmRequestCapabilityFlags::KEY_EX_CAP)
                && flags.contains(SpdmRequestCapabilityFlags::PSK_CAP)
                && flags.contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            {
                return None;
            }
            if flags.contains(SpdmRequestCapabilityFlags::CERT_CAP)
                || flags.contains(SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP)
            {
                if flags.contains(SpdmRequestCapabilityFlags::CERT_CAP)
                    && flags.contains(SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP)
                {
                    return None;
                }
                if !flags.contains(SpdmRequestCapabilityFlags::CHAL_CAP)
                    && !flags.contains(SpdmRequestCapabilityFlags::KEY_EX_CAP)
                {
                    return None;
                }
            } else {
                if flags.contains(SpdmRequestCapabilityFlags::CHAL_CAP)
                    || flags.contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP)
                {
                    return None;
                }
                if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13
                    && flags.contains(SpdmRequestCapabilityFlags::EP_INFO_CAP_SIG)
                {
                    return None;
                }
            }

            if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion11
                && flags.contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP)
                && !flags.contains(SpdmRequestCapabilityFlags::ENCAP_CAP)
            {
                return None;
            }

            if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13 {
                if flags.contains(SpdmRequestCapabilityFlags::EP_INFO_CAP_NO_SIG)
                    && flags.contains(SpdmRequestCapabilityFlags::EP_INFO_CAP_SIG)
                {
                    return None;
                }
                if flags.contains(SpdmRequestCapabilityFlags::MULTI_KEY_CAP_ONLY)
                    && flags.contains(SpdmRequestCapabilityFlags::MULTI_KEY_CAP_CONN_SEL)
                {
                    return None;
                }
                if flags.contains(SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP)
                    && (flags.contains(SpdmRequestCapabilityFlags::MULTI_KEY_CAP_ONLY)
                        || flags.contains(SpdmRequestCapabilityFlags::MULTI_KEY_CAP_CONN_SEL))
                {
                    return None;
                }
            }
        }

        let mut data_transfer_size = 0;
        let mut max_spdm_msg_size = 0;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            data_transfer_size = u32::read(r)?;
            max_spdm_msg_size = u32::read(r)?;
            if data_transfer_size < 42 || max_spdm_msg_size < data_transfer_size {
                log::error!(
                    "responder: data_transfer_size < 42 or max_spdm_msg_size < data_transfer_size"
                );
                return None;
            }
        }

        Some(SpdmGetCapabilitiesRequestPayload {
            ct_exponent,
            flags,
            data_transfer_size,
            max_spdm_msg_size,
            ex_flags,
            supported_algos_requested,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmCapabilitiesResponsePayload {
    pub ct_exponent: u8,
    pub flags: SpdmResponseCapabilityFlags,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
    // New fields from SpdmVersion14
    pub ex_flags: SpdmResponseCapabilityExFlags,
    // SpdmVersion13: SupportedAlgorithms block, present iff the Requester set the
    // Param1 SUPPORTED_ALGOS_EXT_CAP bit and both peers support CHUNK_CAP.
    pub supported_algorithms: Option<SpdmSupportedAlgorithmsBlock>,
}

impl SpdmCodec for SpdmCapabilitiesResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        let mut param1 = SpdmCapabilityParam1::empty();
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13
            && self.supported_algorithms.is_some()
        {
            param1.insert(SpdmCapabilityParam1::SUPPORTED_ALGOS_EXT_CAP);
        }
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved
        cnt += self
            .ct_exponent
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
            cnt += self
                .ex_flags
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved2
        }
        cnt += self
            .flags
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            cnt += self
                .data_transfer_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += self
                .max_spdm_msg_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13 {
            if let Some(supported_algorithms) = &self.supported_algorithms {
                cnt += supported_algorithms.spdm_encode(context, bytes)?;
            }
        }

        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmCapabilitiesResponsePayload> {
        let param1 = if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13 {
            SpdmCapabilityParam1::read(r)? // param1
        } else {
            u8::read(r)?; // param1
            SpdmCapabilityParam1::empty()
        };
        u8::read(r)?; // param2

        u8::read(r)?; // reserved
        let ct_exponent = u8::read(r)?;
        let mut ex_flags = SpdmResponseCapabilityExFlags::default();
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
            ex_flags = SpdmResponseCapabilityExFlags::read(r)?;
        } else {
            u16::read(r)?; // reserved2
        }
        let flags = SpdmResponseCapabilityFlags::read(r)?;

        // check rsp_capability
        if flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_NO_SIG)
            && flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
        {
            return None;
        }
        if (!flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_NO_SIG)
            && !flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG))
            && flags.contains(SpdmResponseCapabilityFlags::MEAS_FRESH_CAP)
        {
            return None;
        }
        if context.negotiate_info.spdm_version_sel < SpdmVersion::SpdmVersion11 {
            if !flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG) {
                if flags.contains(SpdmResponseCapabilityFlags::CERT_CAP)
                    != flags.contains(SpdmResponseCapabilityFlags::CHAL_CAP)
                {
                    return None;
                }
            } else if !flags.contains(SpdmResponseCapabilityFlags::CERT_CAP) {
                return None;
            }
        } else {
            if flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                && flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT)
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                || flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT)
            {
                if !flags.contains(SpdmResponseCapabilityFlags::MAC_CAP) {
                    return None;
                }
            } else {
                if flags.contains(SpdmResponseCapabilityFlags::MAC_CAP)
                    || flags.contains(SpdmResponseCapabilityFlags::ENCRYPT_CAP)
                    || flags.contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
                    || flags.contains(SpdmResponseCapabilityFlags::HBEAT_CAP)
                    || flags.contains(SpdmResponseCapabilityFlags::KEY_UPD_CAP)
                {
                    return None;
                }
                if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13
                    && flags.contains(SpdmResponseCapabilityFlags::EVENT_CAP)
                {
                    return None;
                }
            }
            if !flags.contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                && (flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                    || flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT))
                && flags.contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::CERT_CAP)
                || flags.contains(SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP)
            {
                if flags.contains(SpdmResponseCapabilityFlags::CERT_CAP)
                    && flags.contains(SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP)
                {
                    return None;
                }
                if !flags.contains(SpdmResponseCapabilityFlags::CHAL_CAP)
                    && !flags.contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                    && !flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
                {
                    return None;
                }
            } else {
                if flags.contains(SpdmResponseCapabilityFlags::CHAL_CAP)
                    || flags.contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                    || flags.contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
                    || flags.contains(SpdmResponseCapabilityFlags::MUT_AUTH_CAP)
                {
                    return None;
                }
                if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13
                    && flags.contains(SpdmResponseCapabilityFlags::EP_INFO_CAP_SIG)
                {
                    return None;
                }
            }
        }
        if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion11
            && flags.contains(SpdmResponseCapabilityFlags::MUT_AUTH_CAP)
            && !flags.contains(SpdmResponseCapabilityFlags::ENCAP_CAP)
        {
            return None;
        }
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            if !flags.contains(SpdmResponseCapabilityFlags::CERT_CAP)
                && (flags.contains(SpdmResponseCapabilityFlags::ALIAS_CERT_CAP)
                    || flags.contains(SpdmResponseCapabilityFlags::SET_CERT_CAP))
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::CSR_CAP)
                && !flags.contains(SpdmResponseCapabilityFlags::SET_CERT_CAP)
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::CERT_INSTALL_RESET_CAP)
                && !flags.contains(SpdmResponseCapabilityFlags::CSR_CAP)
                && !flags.contains(SpdmResponseCapabilityFlags::SET_CERT_CAP)
            {
                return None;
            }
        }

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion13 {
            if flags.contains(SpdmResponseCapabilityFlags::EP_INFO_CAP_NO_SIG)
                && flags.contains(SpdmResponseCapabilityFlags::EP_INFO_CAP_SIG)
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY)
                && flags.contains(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_CONN_SEL)
            {
                return None;
            }
            if flags.contains(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_ONLY)
                || flags.contains(SpdmResponseCapabilityFlags::MULTI_KEY_CAP_CONN_SEL)
            {
                if flags.contains(SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP) {
                    return None;
                }
                if !flags.contains(SpdmResponseCapabilityFlags::GET_KEY_PAIR_INFO_CAP) {
                    return None;
                }
            }
        }

        let mut data_transfer_size = 0u32;
        let mut max_spdm_msg_size = 0u32;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            data_transfer_size = u32::read(r)?;
            max_spdm_msg_size = u32::read(r)?;
            if data_transfer_size < 42 || max_spdm_msg_size < data_transfer_size {
                log::error!(
                    "requester: data_transfer_size < 42 or max_spdm_msg_size < data_transfer_size"
                );
                return None;
            }
        }

        let supported_algorithms = if context.negotiate_info.spdm_version_sel
            >= SpdmVersion::SpdmVersion13
            && param1.contains(SpdmCapabilityParam1::SUPPORTED_ALGOS_EXT_CAP)
        {
            Some(SpdmSupportedAlgorithmsBlock::spdm_read(context, r)?)
        } else {
            None
        };

        Some(SpdmCapabilitiesResponsePayload {
            ct_exponent,
            flags,
            data_transfer_size,
            max_spdm_msg_size,
            ex_flags,
            supported_algorithms,
        })
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};
    extern crate alloc;

    #[test]
    fn test_case0_spdm_response_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmResponseCapabilityFlags::all();
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            SpdmResponseCapabilityFlags::all()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_response_capability_flags() {
        let value = SpdmResponseCapabilityFlags::CACHE_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::KEY_UPD_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::HBEAT_CAP;
        new_spdm_response_capability_flags(value);
    }
    #[test]
    fn test_case2_spdm_response_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmResponseCapabilityFlags::empty();
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            SpdmResponseCapabilityFlags::empty()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_request_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRequestCapabilityFlags::all();
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            SpdmRequestCapabilityFlags::all()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_request_capability_flags() {
        let value = SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::CERT_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::CHAL_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::ENCRYPT_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::MAC_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
        new_spdm_request_capability_flags(value);
    }
    #[test]
    fn test_case3_spdm_request_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRequestCapabilityFlags::empty();
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            SpdmRequestCapabilityFlags::empty()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload {
            ct_exponent: 7,
            flags: SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
            ex_flags: SpdmRequestCapabilityExFlags::default(),
            supported_algos_requested: false,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_get_capabilities_request_payload =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_capabilities_request_payload.ct_exponent, 7);
        assert_eq!(
            spdm_get_capabilities_request_payload.flags,
            SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case1_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload {
            ct_exponent: 0,
            flags: SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
            ex_flags: SpdmRequestCapabilityExFlags::default(),
            supported_algos_requested: false,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_get_capabilities_request_payload =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_capabilities_request_payload.ct_exponent, 0);
        assert_eq!(
            spdm_get_capabilities_request_payload.flags,
            SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case2_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload::default();

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader);
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload {
            ct_exponent: 7,
            flags: SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
            ex_flags: SpdmResponseCapabilityExFlags::default(),
            supported_algorithms: None,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 7);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case1_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload {
            ct_exponent: 0,
            flags: SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
            ex_flags: SpdmResponseCapabilityExFlags::default(),
            supported_algorithms: None,
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 0);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case2_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload::default();

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 0);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::empty()
        );
        assert_eq!(2, reader.left());
    }

    fn new_spdm_response_capability_flags(value: SpdmResponseCapabilityFlags) {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            value
        );
        assert_eq!(0, reader.left())
    }

    fn new_spdm_request_capability_flags(value: SpdmRequestCapabilityFlags) {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            value
        );
        assert_eq!(0, reader.left())
    }
}

#[cfg(test)]
#[path = "capability_test.rs"]
mod capability_test;
