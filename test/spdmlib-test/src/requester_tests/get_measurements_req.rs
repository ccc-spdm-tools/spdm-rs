// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, get_rsp_cert_chain_buff};
use ring::signature;
use spdmlib::common::{ManagedBufferL1L2, SpdmConnectionState};
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD};
use spdmlib::message::{SpdmMeasurementAttributes, SpdmMeasurementOperation};
use spdmlib::requester::RequesterContext;
use spdmlib::{config, responder, secret};
use spdmlib::{crypto, protocol::*};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_send_receive_spdm_measurement() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_m = &[0];
        #[cfg(not(feature = "hashed-transcript-data"))]
        responder
            .common
            .runtime_info
            .message_m
            .append_message(message_m);
        responder.common.reset_runtime_info();
        responder.common.provision_info.my_cert_chain = [
            Some(SpdmCertChainBuffer {
                data_size: 512u16,
                data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
            }),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.reset_runtime_info();

        let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber;
        let mut total_number: u8 = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_ok();
        assert!(status);

        let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementRequestAll;
        let mut content_changed = None;
        let mut transcript_meas = None;

        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_ok();
        assert!(status);

        let measurement_operation = SpdmMeasurementOperation::Unknown(1);
        let mut content_changed = None;
        let mut transcript_meas = None;

        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_ok();
        assert!(status);

        let measurement_operation = SpdmMeasurementOperation::Unknown(5);
        let mut content_changed = None;
        let mut transcript_meas = None;

        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_err();
        assert!(status);
    };
    executor::block_on(future);
}

#[test]
fn test_handle_spdm_measurement_record_response() {
    struct Tc<'a> {
        name: &'a str,
        request_slot_id: u8,
        attributes: SpdmMeasurementAttributes,
        operation: SpdmMeasurementOperation,
        receive_buffer: Box<[u8]>,
        expected_result: SpdmResult<u8>,
    }
    let fixed_block: &[u8] = &[
        0xFE, 0x01, 0x33, 0x00, 0x01, 0x30, 0x00, 0x90, 0x6D, 0x9F, 0xE9, 0x2A, 0x5E, 0x0A, 0xD7,
        0xE0, 0x20, 0x84, 0x21, 0x27, 0xF7, 0x97, 0x0B, 0x7D, 0x2A, 0xDF, 0xF3, 0xA9, 0x11, 0x06,
        0x92, 0x7B, 0x59, 0x2C, 0xF1, 0x57, 0x63, 0x3D, 0x86, 0xD0, 0xBE, 0x6A, 0xB7, 0x8F, 0x5D,
        0x39, 0x8E, 0x53, 0xF7, 0x05, 0x64, 0x3C, 0xCB, 0xFB, 0x78,
    ];
    let tt: [Tc; 8] = [
        Tc {
            name: "requested total number and success",
            request_slot_id: 0u8,
            attributes: SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
            operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            receive_buffer: (|| -> Box<[u8]> {
                let mut v = vec![0x12, 0x60, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
                v.extend_from_slice(&[0xFF; 32]); // Nonce
                v.extend_from_slice(&[0x10, 0x00]); // OpaqueDataLength
                v.extend_from_slice(&[0x02; 16]); // OpaqueData
                v.into_boxed_slice()
            })(),
            expected_result: Ok(5),
        },
        Tc {
            name: "requested total number but attached record",
            request_slot_id: 0u8,
            attributes: SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
            operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            receive_buffer: (|| -> Box<[u8]> {
                let mut v = vec![0x12, 0x60, 0x01, 0x00, 0x01, 0x37, 0x00, 0x00];
                v.extend_from_slice(fixed_block); // MeasurementRecordData
                v.extend_from_slice(&[0xFF; 32]);
                v.extend_from_slice(&[0x10, 0x00]);
                v.extend_from_slice(&[0x02; 16]);
                v.into_boxed_slice()
            })(),
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
        Tc {
            name: "requested certain index (0x05) but returned mismatch (0xFE)",
            request_slot_id: 0u8,
            attributes: SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
            operation: SpdmMeasurementOperation::Unknown(0x05),
            receive_buffer: (|| -> Box<[u8]> {
                let mut v = vec![0x12, 0x60, 0x01, 0x00, 0x01, 0x37, 0x00, 0x00];
                v.extend_from_slice(fixed_block);
                v.extend_from_slice(&[0xFF; 32]);
                v.extend_from_slice(&[0x10, 0x00]);
                v.extend_from_slice(&[0x02; 16]);
                v.into_boxed_slice()
            })(),
            expected_result: Ok(1), // should expect Err?
        },
        Tc {
            name: "requested certain index but returned many",
            request_slot_id: 0u8,
            attributes: SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
            operation: SpdmMeasurementOperation::Unknown(0x05),
            receive_buffer: (|| -> Box<[u8]> {
                let mut v = vec![0x12, 0x60, 0x00, 0x00, 0x02, 0x6E, 0x00, 0x00];
                v.extend_from_slice(fixed_block);
                v.extend_from_slice(fixed_block);
                v.extend_from_slice(&[0xFF; 32]);
                v.extend_from_slice(&[0x10, 0x00]);
                v.extend_from_slice(&[0x02; 16]);
                v.into_boxed_slice()
            })(),
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
        Tc {
            name: "requested certain index and success",
            request_slot_id: 0u8,
            attributes: SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
            operation: SpdmMeasurementOperation::Unknown(0xFF),
            receive_buffer: (|| -> Box<[u8]> {
                let mut v = vec![0x12, 0x60, 0x01, 0x00, 0x01, 0x37, 0x00, 0x00];
                v.extend_from_slice(fixed_block);
                v.extend_from_slice(&[0xFF; 32]);
                v.extend_from_slice(&[0x10, 0x00]);
                v.extend_from_slice(&[0x02; 16]);
                v.into_boxed_slice()
            })(),
            expected_result: Ok(1),
        },
        Tc {
            name: "request all without signature and success",
            request_slot_id: 0u8,
            attributes: SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
            operation: SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            receive_buffer: (|| -> Box<[u8]> {
                let mut v = vec![0x12, 0x60, 0x01, 0x00, 0x01, 0x37, 0x00, 0x00];
                v.extend_from_slice(fixed_block);
                v.extend_from_slice(&[0xFF; 32]);
                v.extend_from_slice(&[0x10, 0x00]);
                v.extend_from_slice(&[0x02; 16]);
                v.into_boxed_slice()
            })(),
            expected_result: Ok(1),
        },
        Tc {
            name: "request all and no measurements returned",
            request_slot_id: 0u8,
            attributes: SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
            operation: SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            receive_buffer: (|| -> Box<[u8]> {
                let mut v = vec![0x12, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                v.extend_from_slice(&[0xFF; 32]);
                v.extend_from_slice(&[0x10, 0x00]);
                v.extend_from_slice(&[0x02; 16]);
                v.into_boxed_slice()
            })(),
            expected_result: Ok(0),
        },
        Tc {
            name: "request all but returned blocks have the same index",
            request_slot_id: 0u8,
            attributes: SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            operation: SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            receive_buffer: (|| -> Box<[u8]> {
                let mut v = vec![0x12, 0x60, 0x00, 0x00, 0x02, 0x6E, 0x00, 0x00];
                v.extend_from_slice(fixed_block);
                v.extend_from_slice(fixed_block);
                v.extend_from_slice(&[0xFF; 32]);
                v.extend_from_slice(&[0x10, 0x00]);
                v.extend_from_slice(&[0x02; 16]);
                v.extend_from_slice(&[0xFF; 96]); // Signature
                v.into_boxed_slice()
            })(),
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
    ];
    for tc in tt {
        executor::add_task(async move {
            let (req_config_info, req_provision_info) = create_info();
            let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
            let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
                SharedBuffer::new(),
            ))));
            let mut requester = RequesterContext::new(
                device_io,
                pcidoe_transport_encap,
                req_config_info,
                req_provision_info,
            );
            requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
            requester.common.negotiate_info.req_ct_exponent_sel = 0;
            requester.common.negotiate_info.req_capabilities_sel =
                SpdmRequestCapabilityFlags::CERT_CAP;
            requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
            requester.common.negotiate_info.rsp_capabilities_sel =
                SpdmResponseCapabilityFlags::CERT_CAP;
            requester
                .common
                .negotiate_info
                .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
            requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            requester.common.negotiate_info.base_asym_sel =
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
            requester.common.negotiate_info.measurement_hash_sel =
                SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
            requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
            requester.common.reset_runtime_info();

            let session_id = None;
            let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
            let send_buffer = [0u8; MAX_SPDM_MSG_SIZE];
            let mut content_changed = None;
            let mut transcript_meas = None;
            let result = requester.handle_spdm_measurement_record_response(
                session_id,
                tc.request_slot_id,
                tc.attributes,
                tc.operation,
                &mut content_changed,
                &mut spdm_measurement_record_structure,
                &send_buffer,
                &*tc.receive_buffer,
                &mut transcript_meas,
            );
            assert!(
                result == tc.expected_result,
                "tc '{}' expect {:?} got {:?}",
                tc.name,
                tc.expected_result,
                result
            );
        })
    }
    executor::poll_tasks();
}

#[test]
fn test_case1_send_receive_spdm_measurement() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_m = &[0];
        #[cfg(not(feature = "hashed-transcript-data"))]
        responder
            .common
            .runtime_info
            .message_m
            .append_message(message_m);
        responder.common.reset_runtime_info();
        responder.common.provision_info.my_cert_chain = [
            Some(SpdmCertChainBuffer {
                data_size: 512u16,
                data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
            }),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);
        responder
            .common
            .append_message_a(b"transcript_vca")
            .unwrap();

        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.reset_runtime_info();
        requester
            .common
            .append_message_a(b"transcript_vca")
            .unwrap();

        let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber;
        let mut total_number: u8 = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_ok();
        assert!(status);

        let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementRequestAll;
        let mut content_changed = None;
        let mut transcript_meas = None;

        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_ok();
        assert!(status);

        let transcript_meas = transcript_meas.unwrap();
        let transcript_meas_len = transcript_meas.as_ref().len();
        let mut message_l1l2 = ManagedBufferL1L2::default();
        message_l1l2.append_message(b"transcript_vca").unwrap();
        message_l1l2
            .append_message(&transcript_meas.as_ref()[..transcript_meas_len - 96])
            .unwrap();
        let mut spdm_signature_struct = SpdmSignatureStruct::default();
        spdm_signature_struct.data_size = 96;
        spdm_signature_struct.data[..96]
            .copy_from_slice(&transcript_meas.as_ref()[transcript_meas_len - 96..]);
        let message_l1l2_hash =
            crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_384, message_l1l2.as_ref())
                .unwrap();
        message_l1l2.reset_message();
        message_l1l2
            .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
            .unwrap();
        message_l1l2
            .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_6)
            .unwrap();
        message_l1l2
            .append_message(&SPDM_MEASUREMENTS_SIGN_CONTEXT)
            .unwrap();
        message_l1l2
            .append_message(message_l1l2_hash.as_ref())
            .unwrap();

        let cert_chain_data = &requester.common.peer_info.peer_cert_chain[0 as usize]
            .as_ref()
            .unwrap()
            .data[(4usize
            + requester.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(requester.common.peer_info.peer_cert_chain[0 as usize]
                .as_ref()
                .unwrap()
                .data_size as usize)];

        let result = crypto::asym_verify::verify(
            requester.common.negotiate_info.base_hash_sel,
            requester.common.negotiate_info.base_asym_sel,
            cert_chain_data,
            message_l1l2.as_ref(),
            &spdm_signature_struct,
        );

        assert!(result.is_ok());
    };
    executor::block_on(future);
}

#[test]
fn test_case3_send_receive_spdm_measurement() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_m = &[0];
        #[cfg(not(feature = "hashed-transcript-data"))]
        responder
            .common
            .runtime_info
            .message_m
            .append_message(message_m);
        responder.common.reset_runtime_info();
        responder.common.provision_info.my_cert_chain = [
            Some(SpdmCertChainBuffer {
                data_size: 512u16,
                data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
            }),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);
        responder
            .common
            .append_message_a(b"transcript_vca")
            .unwrap();

        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.reset_runtime_info();
        requester
            .common
            .append_message_a(b"transcript_vca")
            .unwrap();

        let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber;
        let mut total_number: u8 = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_ok();
        assert!(status);

        let mut content_changed = None;
        let mut transcript_meas = None;
        let mut dummy_total_number = 0;

        let mut counter = 0;
        for i in 0..255 {
            let status = requester
                .send_receive_spdm_measurement(
                    None,
                    0,
                    if counter == total_number - 1 {
                        SpdmMeasurementAttributes::SIGNATURE_REQUESTED
                    } else {
                        SpdmMeasurementAttributes::empty()
                    },
                    SpdmMeasurementOperation::Unknown(i),
                    &mut content_changed,
                    &mut dummy_total_number,
                    &mut spdm_measurement_record_structure,
                    &mut transcript_meas,
                )
                .await
                .is_ok();

            if status {
                counter += 1;
            } else {
                continue;
            }

            if counter == total_number {
                let transcript_meas = transcript_meas.clone().unwrap();
                let transcript_meas_len = transcript_meas.as_ref().len();
                let mut message_l1l2 = ManagedBufferL1L2::default();
                message_l1l2.append_message(b"transcript_vca").unwrap();
                message_l1l2
                    .append_message(&transcript_meas.as_ref()[..transcript_meas_len - 96])
                    .unwrap();
                let mut spdm_signature_struct = SpdmSignatureStruct::default();
                spdm_signature_struct.data_size = 96;
                spdm_signature_struct.data[..96]
                    .copy_from_slice(&transcript_meas.as_ref()[transcript_meas_len - 96..]);
                let message_l1l2_hash = crypto::hash::hash_all(
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    message_l1l2.as_ref(),
                )
                .unwrap();
                message_l1l2.reset_message();
                message_l1l2
                    .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                    .unwrap();
                message_l1l2
                    .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_6)
                    .unwrap();
                message_l1l2
                    .append_message(&SPDM_MEASUREMENTS_SIGN_CONTEXT)
                    .unwrap();
                message_l1l2
                    .append_message(message_l1l2_hash.as_ref())
                    .unwrap();

                let cert_chain_data = &requester.common.peer_info.peer_cert_chain[0 as usize]
                    .as_ref()
                    .unwrap()
                    .data[(4usize
                    + requester.common.negotiate_info.base_hash_sel.get_size() as usize)
                    ..(requester.common.peer_info.peer_cert_chain[0 as usize]
                        .as_ref()
                        .unwrap()
                        .data_size as usize)];

                let result = crypto::asym_verify::verify(
                    requester.common.negotiate_info.base_hash_sel,
                    requester.common.negotiate_info.base_asym_sel,
                    cert_chain_data,
                    message_l1l2.as_ref(),
                    &spdm_signature_struct,
                );

                assert!(result.is_ok());
                break;
            } else {
                continue;
            }
        }
    };
    executor::block_on(future);
}
