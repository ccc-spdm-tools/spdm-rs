// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::spdm_codec::*;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::protocol::*;
use crate::{common, error::SpdmStatus};

use codec::{Codec, Reader, Writer};

use self::common::SpdmOpaqueSupport;

pub const MAX_SUPPORTED_ALG_STRUCTURE_COUNT: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct SpdmNegotiateAlgorithmsRequestPayload {
    pub measurement_specification: SpdmMeasurementSpecification,
    pub other_params_support: SpdmOpaqueSupport,
    pub base_asym_algo: SpdmBaseAsymAlgo,
    pub base_hash_algo: SpdmBaseHashAlgo,
    pub alg_struct_count: u8,
    pub alg_struct: [SpdmAlgStruct; MAX_SUPPORTED_ALG_STRUCTURE_COUNT],
}

impl SpdmCodec for SpdmNegotiateAlgorithmsRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            cnt += self
                .alg_struct_count
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        } else {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        }

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        let mut length: u16 = 32;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            let alg_fixed_count = 2u8;
            length += ((2 + alg_fixed_count) * self.alg_struct_count) as u16;
        }
        cnt += length.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        cnt += self
            .measurement_specification
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            cnt += self
                .other_params_support
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; //OtherParamsSupport
        } else {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }

        cnt += self
            .base_asym_algo
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .base_hash_algo
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for _i in 0..12 {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved2
        }

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // ext_asym_count

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // ext_hash_count

        cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved3

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            for algo in self.alg_struct.iter().take(self.alg_struct_count as usize) {
                cnt += algo.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            }
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmNegotiateAlgorithmsRequestPayload> {
        let mut alg_struct_count = 0;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            alg_struct_count = u8::read(r)?; // param1
            if alg_struct_count > 4 {
                return None;
            }
        } else {
            u8::read(r)?; // param1
        }
        u8::read(r)?; // param2

        let length = u16::read(r)?;
        let measurement_specification = SpdmMeasurementSpecification::read(r)?;

        let other_params_support =
            if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
                SpdmOpaqueSupport::read(r)?
            } else {
                u8::read(r)?;
                SpdmOpaqueSupport::default()
            };

        let base_asym_algo = SpdmBaseAsymAlgo::read(r)?;
        let base_hash_algo = SpdmBaseHashAlgo::read(r)?;

        for _i in 0..12 {
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

        u16::read(r)?; // reserved3

        let mut alg_struct = gen_array_clone(SpdmAlgStruct::default(), 4);
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            let mut dhe_present = false;
            let mut aead_present = false;
            let mut req_asym_present = false;
            let mut key_schedule_present = false;
            let mut current_type = SpdmAlgType::Unknown(0);
            for algo in alg_struct.iter_mut().take(alg_struct_count as usize) {
                let alg = SpdmAlgStruct::read(r)?;
                if current_type.get_u8() >= alg.alg_type.get_u8() {
                    return None;
                }
                current_type = alg.alg_type;
                match alg.alg_supported {
                    SpdmAlg::SpdmAlgoDhe(_) => {
                        if dhe_present {
                            return None;
                        }
                        dhe_present = true;
                    }
                    SpdmAlg::SpdmAlgoAead(_) => {
                        if aead_present {
                            return None;
                        }
                        aead_present = true;
                    }
                    SpdmAlg::SpdmAlgoReqAsym(_) => {
                        if req_asym_present {
                            return None;
                        }
                        req_asym_present = true;
                    }
                    SpdmAlg::SpdmAlgoKeySchedule(_) => {
                        if key_schedule_present {
                            return None;
                        }
                        key_schedule_present = true;
                    }
                    SpdmAlg::SpdmAlgoUnknown(_) => {
                        return None;
                    }
                }
                *algo = alg;
            }
        }

        //
        // check length
        //
        let mut calc_length: u16 = 32;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            let alg_fixed_count = 2u8;
            calc_length += ((2 + alg_fixed_count) * alg_struct_count) as u16;
        }

        if length != calc_length {
            return None;
        }

        Some(SpdmNegotiateAlgorithmsRequestPayload {
            measurement_specification,
            other_params_support,
            base_asym_algo,
            base_hash_algo,
            alg_struct_count,
            alg_struct,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmAlgorithmsResponsePayload {
    pub measurement_specification_sel: SpdmMeasurementSpecification,
    pub other_params_selection: SpdmOpaqueSupport,
    pub measurement_hash_algo: SpdmMeasurementHashAlgo,
    pub base_asym_sel: SpdmBaseAsymAlgo,
    pub base_hash_sel: SpdmBaseHashAlgo,
    pub alg_struct_count: u8,
    pub alg_struct: [SpdmAlgStruct; 4],
}

impl SpdmCodec for SpdmAlgorithmsResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            cnt += self
                .alg_struct_count
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        } else {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        }

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2

        let mut length: u16 = 36;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            let alg_fixed_count = 2u8;
            length += ((2 + alg_fixed_count) * self.alg_struct_count) as u16;
        }
        cnt += length.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        cnt += self
            .measurement_specification_sel
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            cnt += self
                .other_params_selection
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }

        cnt += self
            .measurement_hash_algo
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .base_asym_sel
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .base_hash_sel
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for _i in 0..12 {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved2
        }

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // ext_asym_count

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // ext_hash_count

        cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved3

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            for algo in self.alg_struct.iter().take(self.alg_struct_count as usize) {
                cnt += algo.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            }
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmAlgorithmsResponsePayload> {
        let mut alg_struct_count = 0;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            alg_struct_count = u8::read(r)?; // param1
            if alg_struct_count > 4 {
                return None;
            }
        } else {
            u8::read(r)?; // param1
        }
        u8::read(r)?; // param2

        let length = u16::read(r)?;

        let measurement_specification_sel = SpdmMeasurementSpecification::read(r)?;
        if !measurement_specification_sel.is_no_more_than_one_selected() {
            return None;
        }
        if (context
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::MEAS_CAP_NO_SIG)
            || context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG))
            && !measurement_specification_sel.is_valid_one_select()
        {
            return None;
        }

        let other_params_selection =
            if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
                SpdmOpaqueSupport::read(r)?
            } else {
                u8::read(r)?;
                SpdmOpaqueSupport::default()
            };
        if !other_params_selection.is_no_more_than_one_selected() {
            return None;
        }
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12
            && (context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                || context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                || context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT))
            && !other_params_selection.is_valid_one_select()
        {
            return None;
        }

        let measurement_hash_algo = SpdmMeasurementHashAlgo::read(r)?;
        if !measurement_hash_algo.is_no_more_than_one_selected() {
            return None;
        }
        if (context
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::MEAS_CAP_NO_SIG)
            || context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG))
            && !measurement_hash_algo.is_valid_one_select()
        {
            return None;
        }

        let base_asym_sel = SpdmBaseAsymAlgo::read(r)?;
        if !base_asym_sel.is_no_more_than_one_selected() {
            return None;
        }
        if (context
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::CERT_CAP)
            || context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::CHAL_CAP)
            || context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
            || (context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::KEY_EX_CAP)))
            && !base_asym_sel.is_valid_one_select()
        {
            return None;
        }

        let base_hash_sel = SpdmBaseHashAlgo::read(r)?;
        if !base_hash_sel.is_no_more_than_one_selected() {
            return None;
        }
        if (context
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::CERT_CAP)
            || context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::CHAL_CAP)
            || context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
            || (context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::KEY_EX_CAP))
            || ((context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                || context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT))
                && context
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::PSK_CAP)))
            && !base_hash_sel.is_valid_one_select()
        {
            return None;
        }

        for _i in 0..12 {
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

        u16::read(r)?; // reserved3

        let mut alg_struct = gen_array_clone(SpdmAlgStruct::default(), 4);
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            let mut dhe_present = false;
            let mut aead_present = false;
            let mut req_asym_present = false;
            let mut key_schedule_present = false;
            let mut current_type = SpdmAlgType::Unknown(0);
            for algo in alg_struct.iter_mut().take(alg_struct_count as usize) {
                let alg = SpdmAlgStruct::read(r)?;
                if current_type.get_u8() >= alg.alg_type.get_u8() {
                    return None;
                }
                current_type = alg.alg_type;
                match alg.alg_supported {
                    SpdmAlg::SpdmAlgoDhe(v) => {
                        if dhe_present {
                            return None;
                        }
                        dhe_present = true;
                        let dhe_sel = v;
                        if !dhe_sel.is_no_more_than_one_selected() {
                            return None;
                        }
                        if (context
                            .negotiate_info
                            .rsp_capabilities_sel
                            .contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                            && context
                                .negotiate_info
                                .req_capabilities_sel
                                .contains(SpdmRequestCapabilityFlags::KEY_EX_CAP))
                            && !dhe_sel.is_valid_one_select()
                        {
                            return None;
                        }
                    }
                    SpdmAlg::SpdmAlgoAead(v) => {
                        if aead_present {
                            return None;
                        }
                        aead_present = true;
                        let aead_sel = v;
                        if !aead_sel.is_no_more_than_one_selected() {
                            return None;
                        }
                        if ((context
                            .negotiate_info
                            .rsp_capabilities_sel
                            .contains(SpdmResponseCapabilityFlags::ENCRYPT_CAP)
                            && context
                                .negotiate_info
                                .req_capabilities_sel
                                .contains(SpdmRequestCapabilityFlags::ENCRYPT_CAP))
                            || (context
                                .negotiate_info
                                .rsp_capabilities_sel
                                .contains(SpdmResponseCapabilityFlags::MAC_CAP)
                                && context
                                    .negotiate_info
                                    .req_capabilities_sel
                                    .contains(SpdmRequestCapabilityFlags::MAC_CAP)))
                            && !aead_sel.is_valid_one_select()
                        {
                            return None;
                        }
                    }
                    SpdmAlg::SpdmAlgoReqAsym(v) => {
                        if req_asym_present {
                            return None;
                        }
                        req_asym_present = true;
                        let req_asym_sel = v;
                        if !req_asym_sel.is_no_more_than_one_selected() {
                            return None;
                        }
                        if (context
                            .negotiate_info
                            .rsp_capabilities_sel
                            .contains(SpdmResponseCapabilityFlags::MUT_AUTH_CAP)
                            && context
                                .negotiate_info
                                .req_capabilities_sel
                                .contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP))
                            && !req_asym_sel.is_valid_one_select()
                        {
                            return None;
                        }
                    }
                    SpdmAlg::SpdmAlgoKeySchedule(v) => {
                        if key_schedule_present {
                            return None;
                        }
                        key_schedule_present = true;
                        let key_schedule_sel = v;
                        if !key_schedule_sel.is_no_more_than_one_selected() {
                            return None;
                        }
                        if ((context
                            .negotiate_info
                            .rsp_capabilities_sel
                            .contains(SpdmResponseCapabilityFlags::KEY_EX_CAP)
                            && context
                                .negotiate_info
                                .req_capabilities_sel
                                .contains(SpdmRequestCapabilityFlags::KEY_EX_CAP))
                            || ((context
                                .negotiate_info
                                .rsp_capabilities_sel
                                .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT)
                                || context
                                    .negotiate_info
                                    .rsp_capabilities_sel
                                    .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT))
                                && context
                                    .negotiate_info
                                    .req_capabilities_sel
                                    .contains(SpdmRequestCapabilityFlags::PSK_CAP)))
                            && !key_schedule_sel.is_valid_one_select()
                        {
                            return None;
                        }
                    }
                    SpdmAlg::SpdmAlgoUnknown(_v) => {
                        return None;
                    }
                }
                *algo = alg;
            }
        }

        let mut calc_length: u16 = 36;
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion11 {
            let alg_fixed_count = 2u8;
            calc_length += ((2 + alg_fixed_count) * alg_struct_count) as u16;
        }

        if length != calc_length {
            return None;
        }

        Some(SpdmAlgorithmsResponsePayload {
            measurement_specification_sel,
            other_params_selection,
            measurement_hash_algo,
            base_asym_sel,
            base_hash_sel,
            alg_struct_count,
            alg_struct,
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
    fn test_case0_spdm_negotiate_algorithms_request_payload() {
        let u8_slice = &mut [0u8; 48];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmNegotiateAlgorithmsRequestPayload {
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            other_params_support: SpdmOpaqueSupport::empty(),
            base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            alg_struct_count: 4,
            alg_struct: [
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                    alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                    alg_supported: SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                    alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                        SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                    ),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                    alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
                    ),
                },
            ],
        };
        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(48, reader.left());
        let spdm_sturct_data =
            SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            spdm_sturct_data.measurement_specification,
            SpdmMeasurementSpecification::DMTF
        );
        assert_eq!(
            spdm_sturct_data.base_asym_algo,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        );
        assert_eq!(
            spdm_sturct_data.base_hash_algo,
            SpdmBaseHashAlgo::TPM_ALG_SHA_256
        );
        assert_eq!(spdm_sturct_data.alg_struct_count, 4);
        assert_eq!(
            spdm_sturct_data.alg_struct[0].alg_type,
            SpdmAlgType::SpdmAlgTypeDHE
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[0].alg_supported,
            SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[1].alg_type,
            SpdmAlgType::SpdmAlgTypeAEAD
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[1].alg_supported,
            SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[2].alg_type,
            SpdmAlgType::SpdmAlgTypeReqAsym
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[2].alg_supported,
            SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[3].alg_type,
            SpdmAlgType::SpdmAlgTypeKeySchedule
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[3].alg_supported,
            SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,)
        );
        assert_eq!(2, reader.left());
    }

    #[test]
    fn test_case1_spdm_negotiate_algorithms_request_payload() {
        let u8_slice = &mut [0u8; 48];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmNegotiateAlgorithmsRequestPayload {
            measurement_specification: SpdmMeasurementSpecification::empty(),
            other_params_support: SpdmOpaqueSupport::empty(),
            base_asym_algo: SpdmBaseAsymAlgo::empty(),
            base_hash_algo: SpdmBaseHashAlgo::empty(),
            alg_struct_count: 0,
            alg_struct: gen_array_clone(SpdmAlgStruct::default(), 4),
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(48, reader.left());
        let spdm_sturct_data =
            SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            spdm_sturct_data.measurement_specification,
            SpdmMeasurementSpecification::empty()
        );
        assert_eq!(spdm_sturct_data.base_asym_algo, SpdmBaseAsymAlgo::empty());
        assert_eq!(spdm_sturct_data.base_hash_algo, SpdmBaseHashAlgo::empty());
        assert_eq!(spdm_sturct_data.alg_struct_count, 0);
        assert_eq!(18, reader.left());
    }
    #[test]
    fn test_case2_spdm_negotiate_algorithms_request_payload() {
        let u8_slice = &mut [0u8; 48];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmNegotiateAlgorithmsRequestPayload {
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            other_params_support: SpdmOpaqueSupport::empty(),
            base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            alg_struct_count: 0,
            alg_struct: gen_array_clone(SpdmAlgStruct::default(), 4),
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        u8_slice[26] = 1;
        u8_slice[31] = 1;
        let mut reader = Reader::init(u8_slice);
        assert_eq!(48, reader.left());
        let spdm_negotiate_algorithms_request_payload =
            SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut context, &mut reader);
        assert_eq!(spdm_negotiate_algorithms_request_payload.is_none(), true);
    }
    #[test]
    fn test_case0_spdm_algorithms_response_payload() {
        let u8_slice = &mut [0u8; 50];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAlgorithmsResponsePayload {
            measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
            other_params_selection: SpdmOpaqueSupport::empty(),
            measurement_hash_algo: SpdmMeasurementHashAlgo::RAW_BIT_STREAM,
            base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
            base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            alg_struct_count: 4,
            alg_struct: [
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                    alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                    alg_supported: SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                    alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                        SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                    ),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                    alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
                    ),
                },
            ],
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        context.config_info.measurement_specification = SpdmMeasurementSpecification::DMTF;
        context.config_info.measurement_hash_algo = SpdmMeasurementHashAlgo::RAW_BIT_STREAM;
        context.config_info.base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048;
        context.config_info.base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(50, reader.left());
        let spdm_sturct_data =
            SpdmAlgorithmsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            spdm_sturct_data.measurement_specification_sel,
            SpdmMeasurementSpecification::DMTF
        );
        assert_eq!(
            spdm_sturct_data.measurement_hash_algo,
            SpdmMeasurementHashAlgo::RAW_BIT_STREAM
        );
        assert_eq!(
            spdm_sturct_data.base_asym_sel,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        );
        assert_eq!(
            spdm_sturct_data.base_hash_sel,
            SpdmBaseHashAlgo::TPM_ALG_SHA_256
        );
        assert_eq!(spdm_sturct_data.alg_struct_count, 4);
        assert_eq!(
            spdm_sturct_data.alg_struct[0].alg_type,
            SpdmAlgType::SpdmAlgTypeDHE
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[0].alg_supported,
            SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[1].alg_type,
            SpdmAlgType::SpdmAlgTypeAEAD
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[1].alg_supported,
            SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[2].alg_type,
            SpdmAlgType::SpdmAlgTypeReqAsym
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[2].alg_supported,
            SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[3].alg_type,
            SpdmAlgType::SpdmAlgTypeKeySchedule
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[3].alg_supported,
            SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,)
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_algorithms_response_payload() {
        let u8_slice = &mut [0u8; 48];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAlgorithmsResponsePayload {
            measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
            other_params_selection: SpdmOpaqueSupport::empty(),
            measurement_hash_algo: SpdmMeasurementHashAlgo::RAW_BIT_STREAM,
            base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
            base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            alg_struct_count: 0,
            alg_struct: gen_array_clone(SpdmAlgStruct::default(), 4),
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());

        u8_slice[30] = 1;
        u8_slice[35] = 1;

        let mut reader = Reader::init(u8_slice);
        assert_eq!(48, reader.left());
        let spdm_algorithms_response_payload =
            SpdmAlgorithmsResponsePayload::spdm_read(&mut context, &mut reader);
        assert_eq!(spdm_algorithms_response_payload.is_none(), true);
    }
    #[test]
    fn test_case2_spdm_algorithms_response_payload() {
        let u8_slice = &mut [0u8; 50];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAlgorithmsResponsePayload {
            measurement_specification_sel: SpdmMeasurementSpecification::empty(),
            other_params_selection: SpdmOpaqueSupport::empty(),
            measurement_hash_algo: SpdmMeasurementHashAlgo::empty(),
            base_asym_sel: SpdmBaseAsymAlgo::empty(),
            base_hash_sel: SpdmBaseHashAlgo::empty(),
            alg_struct_count: 0,
            alg_struct: gen_array_clone(SpdmAlgStruct::default(), 4),
        };

        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(50, reader.left());
        let spdm_sturct_data =
            SpdmAlgorithmsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            spdm_sturct_data.measurement_specification_sel,
            SpdmMeasurementSpecification::empty()
        );
        assert_eq!(
            spdm_sturct_data.measurement_hash_algo,
            SpdmMeasurementHashAlgo::empty()
        );
        assert_eq!(spdm_sturct_data.base_asym_sel, SpdmBaseAsymAlgo::empty());
        assert_eq!(spdm_sturct_data.base_hash_sel, SpdmBaseHashAlgo::empty());
        assert_eq!(spdm_sturct_data.alg_struct_count, 0);
        assert_eq!(16, reader.left());
    }
}

#[cfg(test)]
#[path = "algorithm_test.rs"]
mod algorithm_test;
