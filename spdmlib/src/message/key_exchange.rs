// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::opaque::SpdmOpaqueStruct;
use crate::common::spdm_codec::SpdmCodec;
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::{
    SpdmDheExchangeStruct, SpdmDigestStruct, SpdmMeasurementSummaryHashType, SpdmRandomStruct,
    SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmSignatureStruct,
};
use codec::{Codec, Reader, Writer};

use super::SpdmVersion;

pub const KEY_EXCHANGE_REQUESTER_SESSION_POLICY_TERMINATION_POLICY_MASK: u8 = 0b0000_0001;
pub const KEY_EXCHANGE_REQUESTER_SESSION_POLICY_TERMINATION_POLICY_VALUE: u8 = 0b0000_0001;

#[derive(Debug, Clone, Default)]
pub struct SpdmKeyExchangeRequestPayload {
    pub measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    pub slot_id: u8,
    pub req_session_id: u16,
    pub session_policy: u8,
    pub random: SpdmRandomStruct,
    pub exchange: SpdmDheExchangeStruct,
    pub opaque: SpdmOpaqueStruct,
}

impl SpdmCodec for SpdmKeyExchangeRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .measurement_summary_hash_type
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += self
            .slot_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .req_session_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            cnt += self
                .session_policy
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved
        }

        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved

        cnt += self
            .random
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self.exchange.spdm_encode(context, bytes)?;
        cnt += self.opaque.spdm_encode(context, bytes)?;
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmKeyExchangeRequestPayload> {
        let measurement_summary_hash_type = SpdmMeasurementSummaryHashType::read(r)?; // param1
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
        let slot_id = u8::read(r)?; // param2
        let req_session_id = u16::read(r)?;
        let session_policy = u8::read(r)?;
        u8::read(r)?;

        let random = SpdmRandomStruct::read(r)?;
        let exchange = SpdmDheExchangeStruct::spdm_read(context, r)?;
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;

        Some(SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type,
            slot_id,
            req_session_id,
            session_policy,
            random,
            exchange,
            opaque,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmKeyExchangeMutAuthAttributes: u8 {
        const MUT_AUTH_REQ = 0b00000001;
        const MUT_AUTH_REQ_WITH_ENCAP_REQUEST = 0b00000010;
        const MUT_AUTH_REQ_WITH_GET_DIGESTS = 0b00000100;
    }
}

impl Codec for SpdmKeyExchangeMutAuthAttributes {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmKeyExchangeMutAuthAttributes> {
        let bits = u8::read(r)?;

        SpdmKeyExchangeMutAuthAttributes::from_bits(bits)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmKeyExchangeResponsePayload {
    pub heartbeat_period: u8,
    pub rsp_session_id: u16,
    pub mut_auth_req: SpdmKeyExchangeMutAuthAttributes,
    pub req_slot_id: u8,
    pub random: SpdmRandomStruct,
    pub exchange: SpdmDheExchangeStruct,
    pub measurement_summary_hash: SpdmDigestStruct,
    pub opaque: SpdmOpaqueStruct,
    pub signature: SpdmSignatureStruct,
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmKeyExchangeResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .heartbeat_period
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .rsp_session_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .mut_auth_req
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .req_slot_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        cnt += self
            .random
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self.exchange.spdm_encode(context, bytes)?;
        if context.runtime_info.need_measurement_summary_hash {
            cnt += self.measurement_summary_hash.spdm_encode(context, bytes)?;
        }
        cnt += self.opaque.spdm_encode(context, bytes)?;
        cnt += self.signature.spdm_encode(context, bytes)?;

        let in_clear_text = context
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);
        if !in_clear_text {
            cnt += self.verify_data.spdm_encode(context, bytes)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmKeyExchangeResponsePayload> {
        let heartbeat_period = u8::read(r)?; // param1
        u8::read(r)?; // param2

        let rsp_session_id = u16::read(r)?; // reserved
        let mut_auth_req = SpdmKeyExchangeMutAuthAttributes::read(r)?;
        let req_slot_id = u8::read(r)?;

        if !mut_auth_req.is_empty()
            && mut_auth_req != SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ
            && mut_auth_req != SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_ENCAP_REQUEST
            && mut_auth_req != SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS
        {
            return None;
        }

        let random = SpdmRandomStruct::read(r)?;
        let exchange = SpdmDheExchangeStruct::spdm_read(context, r)?;
        let measurement_summary_hash = if context.runtime_info.need_measurement_summary_hash {
            SpdmDigestStruct::spdm_read(context, r)?
        } else {
            SpdmDigestStruct::default()
        };
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        let signature = SpdmSignatureStruct::spdm_read(context, r)?;
        let in_clear_text = context
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);
        let verify_data = if !in_clear_text {
            SpdmDigestStruct::spdm_read(context, r)?
        } else {
            SpdmDigestStruct::default()
        };

        Some(SpdmKeyExchangeResponsePayload {
            heartbeat_period,
            rsp_session_id,
            mut_auth_req,
            req_slot_id,
            random,
            exchange,
            measurement_summary_hash,
            opaque,
            signature,
            verify_data,
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
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use crate::protocol::*;
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};
    extern crate alloc;

    #[test]
    fn test_case0_spdm_key_exchange_mut_auth_attributes() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ;
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmKeyExchangeMutAuthAttributes::read(&mut reader).unwrap(),
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ
        );
        assert_eq!(3, reader.left());
    }
    #[test]
    fn test_case0_spdm_key_exchange_request_payload() {
        let u8_slice =
            &mut [0u8; 6 + SPDM_RANDOM_SIZE + SPDM_MAX_DHE_KEY_SIZE + 2 + MAX_SPDM_OPAQUE_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            slot_id: 100u8,
            req_session_id: 100u16,
            session_policy: 1,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct {
                data_size: SPDM_MAX_DHE_KEY_SIZE as u16,
                data: [100u8; SPDM_MAX_DHE_KEY_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(
            6 + SPDM_RANDOM_SIZE + SPDM_MAX_DHE_KEY_SIZE + 2 + MAX_SPDM_OPAQUE_SIZE,
            reader.left()
        );
        let exchange_request_payload =
            SpdmKeyExchangeRequestPayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(
            exchange_request_payload.measurement_summary_hash_type,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
        );
        assert_eq!(exchange_request_payload.slot_id, 100);
        for i in 0..SPDM_RANDOM_SIZE {
            assert_eq!(exchange_request_payload.random.data[i], 100);
        }
        assert_eq!(
            exchange_request_payload.exchange.data_size,
            ECDSA_ECC_NIST_P384_KEY_SIZE as u16
        );
        for i in 0..ECDSA_ECC_NIST_P384_KEY_SIZE {
            assert_eq!(exchange_request_payload.exchange.data[i], 100);
        }
        assert_eq!(
            exchange_request_payload.opaque.data_size,
            MAX_SPDM_OPAQUE_SIZE as u16
        );
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(exchange_request_payload.opaque.data[i], 100);
        }
    }

    #[test]
    fn test_case0_spdm_key_exchange_response_payload() {
        let u8_slice = &mut [0u8; 6
            + SPDM_RANDOM_SIZE
            + SPDM_MAX_DHE_KEY_SIZE
            + SPDM_MAX_HASH_SIZE
            + 2
            + MAX_SPDM_OPAQUE_SIZE
            + SPDM_MAX_ASYM_KEY_SIZE
            + SPDM_MAX_HASH_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyExchangeResponsePayload {
            heartbeat_period: 100u8,
            rsp_session_id: 100u16,
            mut_auth_req: SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ,
            req_slot_id: 100u8,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct {
                data_size: SPDM_MAX_DHE_KEY_SIZE as u16,
                data: [0xa5u8; SPDM_MAX_DHE_KEY_SIZE],
            },
            measurement_summary_hash: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([0x11u8; SPDM_MAX_HASH_SIZE]),
            },
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [0x22u8; MAX_SPDM_OPAQUE_SIZE],
            },
            signature: SpdmSignatureStruct {
                data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
                data: [0x5au8; SPDM_MAX_ASYM_KEY_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([0x33u8; SPDM_MAX_HASH_SIZE]),
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096;
        context.runtime_info.need_measurement_summary_hash = true;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(
            6 + SPDM_RANDOM_SIZE
                + SPDM_MAX_DHE_KEY_SIZE
                + SPDM_MAX_HASH_SIZE
                + 2
                + MAX_SPDM_OPAQUE_SIZE
                + SPDM_MAX_ASYM_KEY_SIZE
                + SPDM_MAX_HASH_SIZE,
            reader.left()
        );
        let exchange_request_payload =
            SpdmKeyExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(exchange_request_payload.heartbeat_period, 100);
        assert_eq!(exchange_request_payload.rsp_session_id, 100);
        assert_eq!(
            exchange_request_payload.mut_auth_req,
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ
        );
        assert_eq!(exchange_request_payload.req_slot_id, 100);
        for i in 0..SPDM_RANDOM_SIZE {
            assert_eq!(exchange_request_payload.random.data[i], 100);
        }

        assert_eq!(
            exchange_request_payload.exchange.data_size,
            ECDSA_ECC_NIST_P384_KEY_SIZE as u16
        );
        for i in 0..ECDSA_ECC_NIST_P384_KEY_SIZE {
            assert_eq!(exchange_request_payload.exchange.data[i], 0xa5);
        }

        assert_eq!(
            exchange_request_payload.signature.data_size,
            RSAPSS_4096_KEY_SIZE as u16
        );
        for i in 0..RSAPSS_4096_KEY_SIZE {
            assert_eq!(exchange_request_payload.signature.data[i], 0x5a);
        }

        assert_eq!(
            exchange_request_payload.measurement_summary_hash.data_size,
            SHA512_DIGEST_SIZE as u16
        );
        assert_eq!(
            exchange_request_payload.verify_data.data_size,
            SHA512_DIGEST_SIZE as u16
        );
        assert_eq!(
            exchange_request_payload.opaque.data_size,
            MAX_SPDM_OPAQUE_SIZE as u16
        );
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(
                exchange_request_payload.measurement_summary_hash.data[i],
                0x11
            );
        }
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(exchange_request_payload.opaque.data[i], 0x22);
        }
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(exchange_request_payload.verify_data.data[i], 0x33);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_key_exchange_response_payload() {
        let u8_slice = &mut [0u8; 6
            + SPDM_RANDOM_SIZE
            + SPDM_MAX_DHE_KEY_SIZE
            + 2
            + MAX_SPDM_OPAQUE_SIZE
            + SPDM_MAX_ASYM_KEY_SIZE
            + SPDM_MAX_HASH_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyExchangeResponsePayload {
            heartbeat_period: 100u8,
            rsp_session_id: 100u16,
            mut_auth_req: SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ,
            req_slot_id: 100u8,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct {
                data_size: SPDM_MAX_DHE_KEY_SIZE as u16,
                data: [0xa5u8; SPDM_MAX_DHE_KEY_SIZE],
            },
            measurement_summary_hash: SpdmDigestStruct::default(),
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [0x22u8; MAX_SPDM_OPAQUE_SIZE],
            },
            signature: SpdmSignatureStruct {
                data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
                data: [0x5au8; SPDM_MAX_ASYM_KEY_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([0x33u8; SPDM_MAX_HASH_SIZE]),
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096;
        context.runtime_info.need_measurement_summary_hash = false;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(
            6 + SPDM_RANDOM_SIZE
                + SPDM_MAX_DHE_KEY_SIZE
                + 2
                + MAX_SPDM_OPAQUE_SIZE
                + SPDM_MAX_ASYM_KEY_SIZE
                + SPDM_MAX_HASH_SIZE,
            reader.left()
        );
        let exchange_request_payload =
            SpdmKeyExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(exchange_request_payload.heartbeat_period, 100);
        assert_eq!(exchange_request_payload.rsp_session_id, 100);
        assert_eq!(
            exchange_request_payload.mut_auth_req,
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ
        );
        assert_eq!(exchange_request_payload.req_slot_id, 100);
        for i in 0..SPDM_RANDOM_SIZE {
            assert_eq!(exchange_request_payload.random.data[i], 100);
        }

        assert_eq!(
            exchange_request_payload.exchange.data_size,
            ECDSA_ECC_NIST_P384_KEY_SIZE as u16
        );
        for i in 0..ECDSA_ECC_NIST_P384_KEY_SIZE {
            assert_eq!(exchange_request_payload.exchange.data[i], 0xa5);
        }

        assert_eq!(
            exchange_request_payload.signature.data_size,
            RSAPSS_4096_KEY_SIZE as u16
        );
        for i in 0..RSAPSS_4096_KEY_SIZE {
            assert_eq!(exchange_request_payload.signature.data[i], 0x5a);
        }

        assert_eq!(
            exchange_request_payload.measurement_summary_hash.data_size,
            0
        );
        assert_eq!(
            exchange_request_payload.verify_data.data_size,
            SHA512_DIGEST_SIZE as u16
        );
        assert_eq!(
            exchange_request_payload.opaque.data_size,
            MAX_SPDM_OPAQUE_SIZE as u16
        );
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(exchange_request_payload.measurement_summary_hash.data[i], 0);
        }
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(exchange_request_payload.opaque.data[i], 0x22);
        }
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(exchange_request_payload.verify_data.data[i], 0x33);
        }
        assert_eq!(0, reader.left());
    }
}

#[cfg(test)]
#[path = "key_exchange_test.rs"]
mod key_exchange_test;
