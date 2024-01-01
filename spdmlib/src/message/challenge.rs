// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::opaque::SpdmOpaqueStruct;
use crate::common::spdm_codec::SpdmCodec;
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::{
    SpdmDigestStruct, SpdmMeasurementSummaryHashType, SpdmNonceStruct, SpdmResponseCapabilityFlags,
    SpdmSignatureStruct,
};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
pub struct SpdmChallengeRequestPayload {
    pub slot_id: u8,
    pub measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    pub nonce: SpdmNonceStruct,
}

impl SpdmCodec for SpdmChallengeRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .slot_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += self
            .measurement_summary_hash_type
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .nonce
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmChallengeRequestPayload> {
        let slot_id = u8::read(r)?;
        let measurement_summary_hash_type = SpdmMeasurementSummaryHashType::read(r)?;
        match measurement_summary_hash_type {
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone => {}
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll
            | SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb => {
                if !context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
                    && !context
                        .negotiate_info
                        .rsp_capabilities_sel
                        .contains(SpdmResponseCapabilityFlags::MEAS_CAP_NO_SIG)
                {
                    return None;
                }
            }
            SpdmMeasurementSummaryHashType::Unknown(_) => return None,
        }
        let nonce = SpdmNonceStruct::read(r)?;

        Some(SpdmChallengeRequestPayload {
            slot_id,
            measurement_summary_hash_type,
            nonce,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmChallengeAuthAttribute: u8 {
        const BASIC_MUT_AUTH_REQ = 0b10000000;
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmChallengeAuthResponsePayload {
    pub slot_id: u8,
    pub slot_mask: u8,
    pub challenge_auth_attribute: SpdmChallengeAuthAttribute,
    pub cert_chain_hash: SpdmDigestStruct,
    pub nonce: SpdmNonceStruct,
    pub measurement_summary_hash: SpdmDigestStruct,
    pub opaque: SpdmOpaqueStruct,
    pub signature: SpdmSignatureStruct,
}

impl SpdmCodec for SpdmChallengeAuthResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        let param1 = self.slot_id + self.challenge_auth_attribute.bits();
        cnt += param1.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .slot_mask
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self.cert_chain_hash.spdm_encode(context, bytes)?;
        cnt += self
            .nonce
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        if context.runtime_info.need_measurement_summary_hash {
            cnt += self.measurement_summary_hash.spdm_encode(context, bytes)?;
        }
        cnt += self.opaque.spdm_encode(context, bytes)?;
        cnt += self.signature.spdm_encode(context, bytes)?;
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmChallengeAuthResponsePayload> {
        let param1 = u8::read(r)?;
        let slot_id = param1 & 0xF;
        let challenge_auth_attribute = SpdmChallengeAuthAttribute::from_bits(param1 & 0xF0)?;
        let slot_mask = u8::read(r)?; // param2
        let cert_chain_hash = SpdmDigestStruct::spdm_read(context, r)?;
        let nonce = SpdmNonceStruct::read(r)?;
        let measurement_summary_hash = if context.runtime_info.need_measurement_summary_hash {
            SpdmDigestStruct::spdm_read(context, r)?
        } else {
            SpdmDigestStruct::default()
        };
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        let signature = SpdmSignatureStruct::spdm_read(context, r)?;
        Some(SpdmChallengeAuthResponsePayload {
            slot_id,
            slot_mask,
            challenge_auth_attribute,
            cert_chain_hash,
            nonce,
            measurement_summary_hash,
            opaque,
            signature,
        })
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::opaque::MAX_SPDM_OPAQUE_SIZE;
    use crate::common::SpdmOpaqueSupport;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use crate::protocol::*;
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};
    extern crate alloc;

    #[test]
    fn test_case0_spdm_challenge_request_payload() {
        let u8_slice = &mut [0u8; 2 + SPDM_NONCE_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmChallengeRequestPayload {
            slot_id: 100,
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(34, reader.left());
        let spdm_challenge_request_payload =
            SpdmChallengeRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_challenge_request_payload.slot_id, 100);
        assert_eq!(
            spdm_challenge_request_payload.measurement_summary_hash_type,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
        );
        for i in 0..SPDM_NONCE_SIZE {
            assert_eq!(spdm_challenge_request_payload.nonce.data[i], 100u8);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_challenge_auth_response_payload() {
        let u8_slice = &mut [0u8; 2
            + SPDM_MAX_HASH_SIZE
            + SPDM_NONCE_SIZE
            + SPDM_MAX_HASH_SIZE
            + 2
            + MAX_SPDM_OPAQUE_SIZE
            + SPDM_MAX_ASYM_KEY_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmChallengeAuthResponsePayload {
            slot_id: 0x0f,
            slot_mask: 100,
            challenge_auth_attribute: SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ,
            cert_chain_hash: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([0xAAu8; SPDM_MAX_HASH_SIZE]),
            },
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            measurement_summary_hash: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([0x55u8; SPDM_MAX_HASH_SIZE]),
            },
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [0xAAu8; MAX_SPDM_OPAQUE_SIZE],
            },
            signature: SpdmSignatureStruct {
                data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
                data: [0x55u8; SPDM_MAX_ASYM_KEY_SIZE],
            },
        };

        create_spdm_context!(context);

        context.runtime_info.need_measurement_summary_hash = true;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);

        assert_eq!(
            2 + SPDM_MAX_HASH_SIZE
                + SPDM_NONCE_SIZE
                + SPDM_MAX_HASH_SIZE
                + 2
                + MAX_SPDM_OPAQUE_SIZE
                + SPDM_MAX_ASYM_KEY_SIZE,
            reader.left()
        );
        let spdm_read_data =
            SpdmChallengeAuthResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(0, reader.left());
        assert_eq!(spdm_read_data.slot_id, 0x0f);
        assert_eq!(spdm_read_data.slot_mask, 100);
        assert_eq!(
            spdm_read_data.challenge_auth_attribute,
            SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ
        );

        assert_eq!(
            spdm_read_data.cert_chain_hash.data_size,
            SHA512_DIGEST_SIZE as u16
        );
        assert_eq!(
            spdm_read_data.measurement_summary_hash.data_size,
            SHA512_DIGEST_SIZE as u16
        );
        assert_eq!(spdm_read_data.opaque.data_size, MAX_SPDM_OPAQUE_SIZE as u16);
        assert_eq!(
            spdm_read_data.signature.data_size,
            RSASSA_4096_KEY_SIZE as u16
        );

        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(spdm_read_data.cert_chain_hash.data[i], 0xAAu8);
        }
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(spdm_read_data.opaque.data[i], 0xAAu8);
        }
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(spdm_read_data.measurement_summary_hash.data[i], 0x55u8);
        }
        for i in 0..SPDM_NONCE_SIZE {
            assert_eq!(spdm_read_data.nonce.data[i], 100u8);
        }
        for i in 0..RSASSA_4096_KEY_SIZE {
            assert_eq!(spdm_read_data.signature.data[i], 0x55u8);
        }
    }
    #[test]
    fn test_case1_spdm_challenge_auth_response_payload() {
        let u8_slice = &mut [0u8; 2
            + SPDM_MAX_HASH_SIZE
            + SPDM_NONCE_SIZE
            + 2
            + MAX_SPDM_OPAQUE_SIZE
            + SPDM_MAX_ASYM_KEY_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmChallengeAuthResponsePayload {
            slot_id: 0x0f,
            slot_mask: 100,
            challenge_auth_attribute: SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ,
            cert_chain_hash: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([0xAAu8; SPDM_MAX_HASH_SIZE]),
            },
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            measurement_summary_hash: SpdmDigestStruct::default(),
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [0xAAu8; MAX_SPDM_OPAQUE_SIZE],
            },
            signature: SpdmSignatureStruct {
                data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
                data: [0x55u8; SPDM_MAX_ASYM_KEY_SIZE],
            },
        };

        create_spdm_context!(context);

        context.runtime_info.need_measurement_summary_hash = false;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

        assert_eq!(
            2 + SPDM_MAX_HASH_SIZE
                + SPDM_NONCE_SIZE
                + 2
                + MAX_SPDM_OPAQUE_SIZE
                + SPDM_MAX_ASYM_KEY_SIZE,
            writer.left()
        );
        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        assert_eq!(0, writer.left());

        let mut reader = Reader::init(u8_slice);

        assert_eq!(
            2 + SPDM_MAX_HASH_SIZE
                + SPDM_NONCE_SIZE
                + 2
                + MAX_SPDM_OPAQUE_SIZE
                + SPDM_MAX_ASYM_KEY_SIZE,
            reader.left()
        );
        let spdm_read_data =
            SpdmChallengeAuthResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(0, reader.left());
        assert_eq!(spdm_read_data.measurement_summary_hash.data_size, 0);
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(spdm_read_data.measurement_summary_hash.data[i], 0);
        }
    }
}

#[cfg(test)]
#[path = "challenge_test.rs"]
mod challenge_test;
