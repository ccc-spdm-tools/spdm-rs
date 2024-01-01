// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, TestSpdmMessage};
use codec::{Codec, Reader, Writer};
use log::debug;
use spdmlib::common::*;
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_handle_spdm_algorithm() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion11,
            request_response_code: SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
        };
        assert!(value.encode(&mut writer).is_ok());

        let negotiate_algorithms = &mut [0u8; 1024];
        let mut writer = Writer::init(negotiate_algorithms);
        let value = SpdmNegotiateAlgorithmsRequestPayload {
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            other_params_support: SpdmOpaqueSupport::empty(),
            base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
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
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&negotiate_algorithms[0..1022]);

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        context.handle_spdm_algorithm(bytes, &mut writer);

        let data = context.common.runtime_info.message_a.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut reader = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
        );
        debug!("u8_slice: {:02X?}\n", u8_slice);
        let u8_slice = &u8_slice[2..];
        debug!("u8_slice: {:02X?}\n", u8_slice);
        let mut reader = Reader::init(u8_slice);
        let spdm_sturct_data =
            SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut context.common, &mut reader)
                .unwrap();
        assert_eq!(
            spdm_sturct_data.measurement_specification,
            SpdmMeasurementSpecification::DMTF
        );
        assert_eq!(
            spdm_sturct_data.base_asym_algo,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        );
        assert_eq!(
            spdm_sturct_data.base_hash_algo,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384
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

        let u8_slice = &u8_slice[46..];
        debug!("u8_slice: {:02X?}\n", u8_slice);
        let mut reader = Reader::init(u8_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();

        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseAlgorithms
        );
        if let SpdmMessagePayload::SpdmAlgorithmsResponse(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_specification_sel,
                SpdmMeasurementSpecification::DMTF
            );
            assert_eq!(
                payload.measurement_hash_algo,
                SpdmMeasurementHashAlgo::TPM_ALG_SHA_384
            );
            assert_eq!(
                payload.base_asym_sel,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
            );
            assert_eq!(payload.base_hash_sel, SpdmBaseHashAlgo::TPM_ALG_SHA_384);
            assert_eq!(payload.alg_struct_count, 4);

            assert_eq!(payload.alg_struct[0].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
            assert_eq!(
                payload.alg_struct[0].alg_supported,
                SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::empty())
            );

            assert_eq!(payload.alg_struct[1].alg_type, SpdmAlgType::SpdmAlgTypeAEAD);
            assert_eq!(
                payload.alg_struct[1].alg_supported,
                SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::empty())
            );

            assert_eq!(
                payload.alg_struct[2].alg_type,
                SpdmAlgType::SpdmAlgTypeReqAsym
            );
            assert_eq!(
                payload.alg_struct[2].alg_supported,
                SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::empty())
            );

            assert_eq!(
                payload.alg_struct[3].alg_type,
                SpdmAlgType::SpdmAlgTypeKeySchedule
            );
            assert_eq!(
                payload.alg_struct[3].alg_supported,
                SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE)
            );
        }
    };

    executor::block_on(future);
}

pub fn consturct_algorithm_positive() -> (TestSpdmMessage, TestSpdmMessage) {
    use crate::protocol;
    let (config_info, provision_info) = create_info();
    let negotiate_algorithm_msg = TestSpdmMessage {
        message: protocol::Message::NEGOTIATE_ALGORITHMS(
            protocol::algorithm::NEGOTIATE_ALGORITHMS {
                SPDMVersion: 0x12,
                RequestResponseCode: 0xE3,
                Param1: 4,
                Param2: 0,
                Length: 48,
                MeasurementSpecification: config_info.measurement_specification.bits(),
                OtherParamsSupport: config_info.opaque_support.bits(),
                BaseAsymAlgo: config_info.base_asym_algo.bits(),
                BaseHashAlgo: config_info.base_hash_algo.bits(),
                _Reserved1: [0u8; 12],
                ExtAsymCount: 0,
                ExtHashCount: 0,
                _Reserved2: [0u8; 2],
                ExtAsym: Vec::new(),
                Exthash: Vec::new(),
                AlgStruct: vec![
                    [0x02, 0x20, 0x10, 0x00],
                    [0x03, 0x20, 0x02, 0x00],
                    [0x04, 0x20, 0x02, 0x00],
                    [0x05, 0x20, 0x01, 0x00],
                ],
            },
        ),
        secure: 0,
    };

    let algorithm_msg = TestSpdmMessage {
        message: protocol::Message::ALGORITHMS(protocol::algorithm::ALGORITHMS {
            SPDMVersion: 0x12,
            RequestResponseCode: 0x63,
            Param1: 4,
            Param2: 0,
            Length: 52,
            MeasurementSpecification: config_info.measurement_specification.bits(),
            OtherParamsSupport: config_info.opaque_support.bits(),
            MeasurementHashAlgo: config_info.measurement_hash_algo.bits(),
            BaseAsymAlgo: config_info.base_asym_algo.bits(),
            BaseHashAlgo: config_info.base_hash_algo.bits(),
            _Reserved1: [0u8; 12],
            ExtAsymCount: 0,
            ExtHashCount: 0,
            _Reserved2: [0u8; 2],
            ExtAsym: Vec::new(),
            Exthash: Vec::new(),
            AlgStruct: vec![
                [0x02, 0x20, 0x10, 0x00],
                [0x03, 0x20, 0x02, 0x00],
                [0x04, 0x20, 0x02, 0x00],
                [0x05, 0x20, 0x01, 0x00],
            ],
        }),
        secure: 0,
    };
    (negotiate_algorithm_msg, algorithm_msg)
}
