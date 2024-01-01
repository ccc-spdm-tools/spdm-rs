// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{self, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, ResponderRunner, TestCase, TestSpdmMessage};
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmCodec;
use spdmlib::common::SpdmConnectionState;
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_handle_spdm_measurement() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
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

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.measurement_specification_sel =
            SpdmMeasurementSpecification::DMTF;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let measurements_struct = &mut [0u8; 1024];
        let mut writer = Writer::init(measurements_struct);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementAttributes::empty(),
            measurement_operation: SpdmMeasurementOperation::Unknown(1),
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0,
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&measurements_struct[0..1022]);
        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, send_buffer) = context.handle_spdm_measurement(None, bytes, &mut writer);

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            let data = context.common.runtime_info.message_m.as_ref();
            let u8_slice = &mut [0u8; 2048];
            for (i, data) in data.iter().enumerate() {
                u8_slice[i] = *data;
            }

            let mut message_header_slice = Reader::init(u8_slice);
            let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
            assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
            assert_eq!(
                spdm_message_header.request_response_code,
                SpdmRequestResponseCode::SpdmRequestChallenge
            );

            let spdm_struct_slice = &u8_slice[2..];
            let mut reader = Reader::init(spdm_struct_slice);
            let get_measurements =
                SpdmGetMeasurementsRequestPayload::spdm_read(&mut context.common, &mut reader)
                    .unwrap();
            assert_eq!(
                get_measurements.measurement_attributes,
                SpdmMeasurementAttributes::empty()
            );
            assert_eq!(
                get_measurements.measurement_operation,
                SpdmMeasurementOperation::Unknown(1)
            );

            let spdm_message_slice = &u8_slice[4..];
            let mut reader = Reader::init(spdm_message_slice);
            let spdm_message: SpdmMessage =
                SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
            assert_eq!(
                spdm_message.header.request_response_code,
                SpdmRequestResponseCode::SpdmResponseMeasurements
            );
            if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
                //assert_eq!(payload.number_of_measurement, 0);
                assert_eq!(payload.slot_id, 0);
                assert_eq!(payload.measurement_record.number_of_blocks, 1);
            }
        }
    };
    executor::block_on(future);
}

#[test]
fn test_case1_handle_spdm_measurement() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
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

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.measurement_specification_sel =
            SpdmMeasurementSpecification::DMTF;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let measurements_struct = &mut [0u8; 1024];
        let mut writer = Writer::init(measurements_struct);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementAttributes::empty(),
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0,
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&measurements_struct[0..1022]);
        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, send_buffer) = context.handle_spdm_measurement(None, bytes, &mut writer);

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            let data = context.common.runtime_info.message_m.as_ref();
            let u8_slice = &mut [0u8; 2048];
            for (i, data) in data.iter().enumerate() {
                u8_slice[i] = *data;
            }

            let mut message_header_slice = Reader::init(u8_slice);
            let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
            assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
            assert_eq!(
                spdm_message_header.request_response_code,
                SpdmRequestResponseCode::SpdmRequestChallenge
            );

            let spdm_struct_slice = &u8_slice[2..];
            let mut reader = Reader::init(spdm_struct_slice);
            let get_measurements =
                SpdmGetMeasurementsRequestPayload::spdm_read(&mut context.common, &mut reader)
                    .unwrap();
            assert_eq!(
                get_measurements.measurement_attributes,
                SpdmMeasurementAttributes::empty()
            );
            assert_eq!(
                get_measurements.measurement_operation,
                SpdmMeasurementOperation::SpdmMeasurementRequestAll
            );

            let spdm_message_slice = &u8_slice[4..];
            let mut reader = Reader::init(spdm_message_slice);
            let spdm_message: SpdmMessage =
                SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
            assert_eq!(
                spdm_message.header.request_response_code,
                SpdmRequestResponseCode::SpdmResponseMeasurements
            );

            if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
                //assert_eq!(payload.number_of_measurement, 10);
                //if measurement_attributes == 0, it means responder donot need append signature,
                //and slot_id should be 0.
                assert_eq!(payload.slot_id, 0);
                assert_eq!(payload.measurement_record.number_of_blocks, 10);
            }
        }
    };
    executor::block_on(future);
}

fn test_handle_spdm_measurement_runner(
    get_measurement_msg: TestSpdmMessage,
    measurement_msg: TestSpdmMessage,
) {
    let mut input = Vec::new();
    let mut expected = Vec::new();

    let (get_version_msg, version_msg) = super::version_rsp::construct_version_positive();
    let (get_capabilities_msg, capabilities_msg) =
        super::capability_rsp::consturct_capability_positive();
    let (negotiate_algorithm_msg, algorithm_msg) =
        super::algorithm_rsp::consturct_algorithm_positive();
    let (get_certificate_msg, certificate_msg) =
        super::certificate_rsp::construct_certificate_positive();

    input.push(get_version_msg);
    expected.push(version_msg);
    input.push(get_capabilities_msg);
    expected.push(capabilities_msg);
    input.push(negotiate_algorithm_msg);
    expected.push(algorithm_msg);
    input.extend(get_certificate_msg);
    expected.extend(certificate_msg);

    input.push(get_measurement_msg);
    expected.push(measurement_msg);

    let case = TestCase { input, expected };
    assert!(ResponderRunner::run(
        case,
        device_io::test_header_generater_callback
    ));
}

#[test]
fn test_case2_handle_spdm_measurements() {
    use crate::common::secret_callback::SECRET_MEASUREMENT_IMPL_INSTANCE;
    use crate::protocol;
    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

    let get_measurement_msg = TestSpdmMessage {
        message: protocol::Message::GET_MEASUREMENTS(protocol::measurement::GET_MEASUREMENTS {
            SPDMVersion: 0x12,
            RequestResponseCode: 0xE0,
            Param1: 0,
            Param2: 0x0, // shall query the Responder for the total number of measurement blocks avaiable
            Nonce: None,
            SlotIDParam: None,
        }),
        secure: 0,
    };

    let (config_info, _provision_info) = create_info();
    let measurement_record_structure = secret::measurement::measurement_collection(
        SpdmVersion::SpdmVersion12,
        SpdmMeasurementSpecification::DMTF,
        config_info.measurement_hash_algo,
        SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber.get_u8() as usize,
    )
    .unwrap();

    let siglen = config_info.base_asym_algo.get_size() as usize;
    let measurement_msg = TestSpdmMessage {
        message: protocol::Message::MEASUREMENTS(protocol::measurement::MEASUREMENTS {
            SPDMVersion: 0x12,
            RequestResponseCode: 0x60,
            Param1: measurement_record_structure.number_of_blocks,
            Param2: 0,
            NumberOfBlocks: 0,
            MeasurementRecordLength: measurement_record_structure.measurement_record_length.get(),
            MeasurementRecordData: measurement_record_structure.measurement_record_data
                [0..(measurement_record_structure.measurement_record_length.get() as usize)]
                .to_vec(),
            Nonce: [0xffu8; 32],
            OpaqueDataLength: 0,
            OpaqueData: Vec::new(),
            Signature: Vec::new(),
        }),
        secure: 0,
    };

    test_handle_spdm_measurement_runner(get_measurement_msg, measurement_msg);
}
