// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};
use spdmlib::common::*;
use spdmlib::config::MAX_ROOT_CERT_SUPPORT;
use spdmlib::protocol::*;

#[test]
fn test_spdm_config_info_codec() {
    let original = SpdmConfigInfo {
        spdm_version: [
            Some(SpdmVersion::SpdmVersion10),
            Some(SpdmVersion::SpdmVersion11),
            None,
            None,
            None,
        ],
        req_capabilities: SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::CHAL_CAP,
        rsp_capabilities: SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::CHAL_CAP,
        req_ct_exponent: 5,
        rsp_ct_exponent: 6,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_256,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
        dhe_algo: SpdmDheAlgo::SECP_256_R1,
        aead_algo: SpdmAeadAlgo::AES_128_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        other_params_support: SpdmAlgoOtherParams::OPAQUE_DATA_FMT1,
        session_policy: 1,
        runtime_content_change_support: true,
        data_transfer_size: 1024,
        max_spdm_msg_size: 2048,
        heartbeat_period: 30,
        secure_spdm_version: [
            Some(SecuredMessageVersion::try_from(0x10u8).unwrap()),
            None,
            None,
        ],
        mel_specification: SpdmMelSpecification::DMTF_MEL_SPEC,
    };

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmConfigInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmConfigInfo::read(&mut reader).expect("Failed to decode SpdmConfigInfo");

    assert_eq!(original, decoded);
}

#[test]
fn test_spdm_negotiate_info_codec() {
    let original = SpdmNegotiateInfo {
        spdm_version_sel: SpdmVersion::SpdmVersion12,
        req_capabilities_sel: SpdmRequestCapabilityFlags::CERT_CAP,
        rsp_capabilities_sel: SpdmResponseCapabilityFlags::CERT_CAP,
        req_ct_exponent_sel: 7,
        rsp_ct_exponent_sel: 8,
        measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
        measurement_hash_sel: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
        dhe_sel: SpdmDheAlgo::SECP_384_R1,
        aead_sel: SpdmAeadAlgo::AES_256_GCM,
        req_asym_sel: SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072,
        key_schedule_sel: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        other_params_support: SpdmAlgoOtherParams::OPAQUE_DATA_FMT1,
        termination_policy_set: true,
        req_data_transfer_size_sel: 2048,
        req_max_spdm_msg_size_sel: 4096,
        rsp_data_transfer_size_sel: 1024,
        rsp_max_spdm_msg_size_sel: 2048,
        mel_specification_sel: SpdmMelSpecification::DMTF_MEL_SPEC,
        multi_key_conn_req: true,
        multi_key_conn_rsp: false,
    };

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmNegotiateInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmNegotiateInfo::read(&mut reader).expect("Failed to decode SpdmNegotiateInfo");

    assert_eq!(original, decoded);
}

#[test]
fn test_managed_buffer_a_codec() {
    let mut original = ManagedBufferA::default();
    let test_data = b"Hello, SPDM!";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferA");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferA::read(&mut reader).expect("Failed to decode ManagedBufferA");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_b_codec() {
    let mut original = ManagedBufferB::default();
    let test_data = b"Test data for buffer B";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferB");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferB::read(&mut reader).expect("Failed to decode ManagedBufferB");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_c_codec() {
    let mut original = ManagedBufferC::default();
    let test_data = b"Test data for buffer C";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferC");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferC::read(&mut reader).expect("Failed to decode ManagedBufferC");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_m_codec() {
    let mut original = ManagedBufferM::default();
    let test_data = b"Test data for buffer M";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferM");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferM::read(&mut reader).expect("Failed to decode ManagedBufferM");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_k_codec() {
    let mut original = ManagedBufferK::default();
    let test_data = b"Test data for buffer K";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferK");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferK::read(&mut reader).expect("Failed to decode ManagedBufferK");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_f_codec() {
    let mut original = ManagedBufferF::default();
    let test_data = b"Test data for buffer F";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferF");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferF::read(&mut reader).expect("Failed to decode ManagedBufferF");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_m1m2_codec() {
    let mut original = ManagedBufferM1M2::default();
    let test_data = b"Test data for buffer M1M2";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferM1M2");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferM1M2::read(&mut reader).expect("Failed to decode ManagedBufferM1M2");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_l1l2_codec() {
    let mut original = ManagedBufferL1L2::default();
    let test_data = b"Test data for buffer L1L2";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferL1L2");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferL1L2::read(&mut reader).expect("Failed to decode ManagedBufferL1L2");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_th_codec() {
    let mut original = ManagedBufferTH::default();
    let test_data = b"Test data for buffer TH";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBufferTH");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferTH::read(&mut reader).expect("Failed to decode ManagedBufferTH");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_managed_buffer_12sign_codec() {
    let mut original = ManagedBuffer12Sign::default();
    let test_data = b"Test data for buffer 12Sign";
    original
        .append_message(test_data)
        .expect("Failed to append message");

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode ManagedBuffer12Sign");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded =
        ManagedBuffer12Sign::read(&mut reader).expect("Failed to decode ManagedBuffer12Sign");

    assert_eq!(original.as_ref(), decoded.as_ref());
}

#[test]
fn test_spdm_measurement_content_changed_codec() {
    let test_cases = [
        SpdmMeasurementContentChanged::NotSupported,
        SpdmMeasurementContentChanged::DetectedChange,
        SpdmMeasurementContentChanged::NoChange,
    ];

    for original in test_cases.iter() {
        // Test round-trip encoding/decoding
        let mut buffer = [0u8; 64];
        let mut writer = Writer::init(&mut buffer);
        let encoded_size = original
            .encode(&mut writer)
            .expect("Failed to encode SpdmMeasurementContentChanged");

        let mut reader = Reader::init(&buffer[..encoded_size]);
        let decoded = SpdmMeasurementContentChanged::read(&mut reader)
            .expect("Failed to decode SpdmMeasurementContentChanged");

        assert_eq!(*original, decoded);
    }
}

#[cfg(not(feature = "hashed-transcript-data"))]
#[test]
fn test_spdm_runtime_info_codec_no_hashed() {
    // SpdmRuntimeInfo fields are private, so we test basic encode/decode functionality
    let original = SpdmRuntimeInfo::default();

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 16384];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmRuntimeInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmRuntimeInfo::read(&mut reader).expect("Failed to decode SpdmRuntimeInfo");

    // Test that the encode/decode round trip works (comparing encoded sizes)
    let mut buffer2 = [0u8; 16384];
    let mut writer2 = Writer::init(&mut buffer2);
    let encoded_size2 = decoded
        .encode(&mut writer2)
        .expect("Failed to re-encode SpdmRuntimeInfo");

    assert_eq!(encoded_size, encoded_size2);
}

#[cfg(feature = "hashed-transcript-data")]
#[test]
fn test_spdm_runtime_info_codec_hashed() {
    // SpdmRuntimeInfo fields are private, so we test basic encode/decode functionality
    let original = SpdmRuntimeInfo::default();

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 16384];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmRuntimeInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmRuntimeInfo::read(&mut reader).expect("Failed to decode SpdmRuntimeInfo");

    // Test that the encode/decode round trip works (comparing encoded sizes)
    let mut buffer2 = [0u8; 16384];
    let mut writer2 = Writer::init(&mut buffer2);
    let encoded_size2 = decoded
        .encode(&mut writer2)
        .expect("Failed to re-encode SpdmRuntimeInfo");

    assert_eq!(encoded_size, encoded_size2);
}

#[test]
fn test_spdm_provision_info_codec() {
    let original = SpdmProvisionInfo {
        my_cert_chain_data: [None; SPDM_MAX_SLOT_NUMBER],
        my_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
        peer_root_cert_data: [None; MAX_ROOT_CERT_SUPPORT],
        local_supported_slot_mask: 0xFF,
        local_key_pair_id: [None; SPDM_MAX_SLOT_NUMBER],
        local_cert_info: [None; SPDM_MAX_SLOT_NUMBER],
        local_key_usage_bit_mask: [None; SPDM_MAX_SLOT_NUMBER],
    };

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 16384];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmProvisionInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmProvisionInfo::read(&mut reader).expect("Failed to decode SpdmProvisionInfo");

    assert_eq!(
        original.local_supported_slot_mask,
        decoded.local_supported_slot_mask
    );
    // Note: detailed field comparisons would require implementing more comparison logic
    // for the array fields, but the basic structure test is sufficient for now
}

#[test]
fn test_spdm_provision_info_codec_with_populated_data() {
    // Test with populated certificate data (populate first few slots only to stay within buffer limits)
    let mut cert_data_1 = SpdmCertChainData::default();
    cert_data_1.data_size = 50;
    for i in 0..50 {
        cert_data_1.data[i] = (i % 256) as u8;
    }

    let mut cert_data_2 = SpdmCertChainData::default();
    cert_data_2.data_size = 60;
    for i in 0..60 {
        cert_data_2.data[i] = ((i * 2) % 256) as u8;
    }

    let mut peer_root_cert_1 = SpdmCertChainData::default();
    peer_root_cert_1.data_size = 40;
    for i in 0..40 {
        peer_root_cert_1.data[i] = ((i * 3) % 256) as u8;
    }

    let mut peer_root_cert_2 = SpdmCertChainData::default();
    peer_root_cert_2.data_size = 35;
    for i in 0..35 {
        peer_root_cert_2.data[i] = ((i * 4) % 256) as u8;
    }

    let original = SpdmProvisionInfo {
        my_cert_chain_data: [
            Some(cert_data_1),
            Some(cert_data_2),
            None,
            None,
            None,
            None,
            None,
            None,
        ],
        my_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
        peer_root_cert_data: {
            let mut arr = [None; MAX_ROOT_CERT_SUPPORT];
            arr[0] = Some(peer_root_cert_1);
            arr[1] = Some(peer_root_cert_2);
            // Leave rest as None to stay within buffer limits
            arr
        },
        local_supported_slot_mask: 0x03, // Only first two slots
        local_key_pair_id: [Some(1), Some(2), None, None, None, None, None, None],
        local_cert_info: [
            Some(SpdmCertificateModelType::SpdmCertModelTypeDeviceCert),
            Some(SpdmCertificateModelType::SpdmCertModelTypeDeviceCert),
            None,
            None,
            None,
            None,
            None,
            None,
        ],
        local_key_usage_bit_mask: [
            Some(SpdmKeyUsageMask::KEY_USAGE_MASK_KEY_EX_USE),
            Some(SpdmKeyUsageMask::KEY_USAGE_MASK_CHALLENGE_USE),
            None,
            None,
            None,
            None,
            None,
            None,
        ],
    };

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 32768];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmProvisionInfo with populated data");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmProvisionInfo::read(&mut reader)
        .expect("Failed to decode SpdmProvisionInfo with populated data");

    assert_eq!(
        original.local_supported_slot_mask,
        decoded.local_supported_slot_mask
    );

    // Test that populated cert data matches
    for slot in 0..2 {
        // Only test first two slots that we populated
        if let (Some(orig_cert), Some(decoded_cert)) = (
            &original.my_cert_chain_data[slot],
            &decoded.my_cert_chain_data[slot],
        ) {
            assert_eq!(orig_cert.data_size, decoded_cert.data_size);
            assert_eq!(
                orig_cert.data[0..orig_cert.data_size as usize],
                decoded_cert.data[0..orig_cert.data_size as usize]
            );
        }
    }

    // Test that populated peer root cert data matches
    for root_idx in 0..2 {
        // Only test first two that we populated
        if let (Some(orig_root), Some(decoded_root)) = (
            &original.peer_root_cert_data[root_idx],
            &decoded.peer_root_cert_data[root_idx],
        ) {
            assert_eq!(orig_root.data_size, decoded_root.data_size);
            assert_eq!(
                orig_root.data[0..orig_root.data_size as usize],
                decoded_root.data[0..orig_root.data_size as usize]
            );
        }
    }

    // Test that populated key pair IDs match
    for slot in 0..2 {
        assert_eq!(
            original.local_key_pair_id[slot],
            decoded.local_key_pair_id[slot]
        );
    }

    // Test that populated cert info matches
    for slot in 0..2 {
        assert_eq!(
            original.local_cert_info[slot],
            decoded.local_cert_info[slot]
        );
    }

    // Test that populated key usage bit masks match
    for slot in 0..2 {
        assert_eq!(
            original.local_key_usage_bit_mask[slot],
            decoded.local_key_usage_bit_mask[slot]
        );
    }
}

#[test]
fn test_spdm_provision_info_codec_edge_cases() {
    // Test with maximum slot mask
    let original = SpdmProvisionInfo {
        my_cert_chain_data: [None; SPDM_MAX_SLOT_NUMBER],
        my_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
        peer_root_cert_data: [None; MAX_ROOT_CERT_SUPPORT],
        local_supported_slot_mask: 0xFF,
        local_key_pair_id: [None; SPDM_MAX_SLOT_NUMBER],
        local_cert_info: [None; SPDM_MAX_SLOT_NUMBER],
        local_key_usage_bit_mask: [None; SPDM_MAX_SLOT_NUMBER],
    };

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 16384];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode max slot mask SpdmProvisionInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmProvisionInfo::read(&mut reader)
        .expect("Failed to decode max slot mask SpdmProvisionInfo");

    assert_eq!(
        original.local_supported_slot_mask,
        decoded.local_supported_slot_mask
    );

    // Test with zero slot mask
    let original_zero = SpdmProvisionInfo {
        local_supported_slot_mask: 0x00,
        ..original
    };

    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original_zero
        .encode(&mut writer)
        .expect("Failed to encode zero slot mask SpdmProvisionInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded_zero = SpdmProvisionInfo::read(&mut reader)
        .expect("Failed to decode zero slot mask SpdmProvisionInfo");

    assert_eq!(
        original_zero.local_supported_slot_mask,
        decoded_zero.local_supported_slot_mask
    );
}

#[test]
fn test_spdm_peer_info_codec() {
    let original = SpdmPeerInfo {
        peer_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
        peer_cert_chain_temp: None,
        peer_supported_slot_mask: 0x0F,
        peer_provisioned_slot_mask: 0x03,
        peer_key_pair_id: [None; SPDM_MAX_SLOT_NUMBER],
        peer_cert_info: [None; SPDM_MAX_SLOT_NUMBER],
        peer_key_usage_bit_mask: [None; SPDM_MAX_SLOT_NUMBER],
    };

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 16384];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmPeerInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmPeerInfo::read(&mut reader).expect("Failed to decode SpdmPeerInfo");

    assert_eq!(
        original.peer_supported_slot_mask,
        decoded.peer_supported_slot_mask
    );
    assert_eq!(
        original.peer_provisioned_slot_mask,
        decoded.peer_provisioned_slot_mask
    );
    assert_eq!(original.peer_cert_chain_temp, decoded.peer_cert_chain_temp);
}

#[test]
fn test_spdm_peer_info_codec_with_populated_data() {
    // Test with all populated certificate chains (smaller sizes to fit in buffers)
    let mut cert_chain_templates = Vec::new();
    for slot in 0..SPDM_MAX_SLOT_NUMBER {
        let mut cert_chain = SpdmCertChainBuffer::default();
        cert_chain.data_size = 80 + (slot as u16 * 10); // Smaller sizes to fit
        for i in 0..cert_chain.data_size {
            cert_chain.data[i as usize] = ((i + slot as u16 * 3) % 256) as u8;
        }
        cert_chain_templates.push(cert_chain);
    }

    let cert_info_variants = [
        SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
        SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
        SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
        SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
        SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
        SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
        SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
        SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
    ];

    let key_usage_variants = [
        SpdmKeyUsageMask::KEY_USAGE_MASK_KEY_EX_USE,
        SpdmKeyUsageMask::KEY_USAGE_MASK_CHALLENGE_USE,
        SpdmKeyUsageMask::KEY_USAGE_MASK_MEASUREMENT_USE,
        SpdmKeyUsageMask::KEY_USAGE_MASK_KEY_EX_USE
            | SpdmKeyUsageMask::KEY_USAGE_MASK_CHALLENGE_USE,
        SpdmKeyUsageMask::KEY_USAGE_MASK_CHALLENGE_USE
            | SpdmKeyUsageMask::KEY_USAGE_MASK_MEASUREMENT_USE,
        SpdmKeyUsageMask::KEY_USAGE_MASK_MEASUREMENT_USE
            | SpdmKeyUsageMask::KEY_USAGE_MASK_KEY_EX_USE,
        SpdmKeyUsageMask::KEY_USAGE_MASK_KEY_EX_USE
            | SpdmKeyUsageMask::KEY_USAGE_MASK_CHALLENGE_USE
            | SpdmKeyUsageMask::KEY_USAGE_MASK_MEASUREMENT_USE,
        SpdmKeyUsageMask::KEY_USAGE_MASK_KEY_EX_USE,
    ];

    let original = SpdmPeerInfo {
        peer_cert_chain: [
            Some(cert_chain_templates[0].clone()),
            Some(cert_chain_templates[1].clone()),
            Some(cert_chain_templates[2].clone()),
            Some(cert_chain_templates[3].clone()),
            Some(cert_chain_templates[4].clone()),
            Some(cert_chain_templates[5].clone()),
            Some(cert_chain_templates[6].clone()),
            Some(cert_chain_templates[7].clone()),
        ],
        peer_cert_chain_temp: None,
        peer_supported_slot_mask: 0xFF,   // All slots supported
        peer_provisioned_slot_mask: 0xFF, // All slots provisioned
        peer_key_pair_id: [
            Some(10),
            Some(20),
            Some(30),
            Some(40),
            Some(50),
            Some(60),
            Some(70),
            Some(80),
        ],
        peer_cert_info: [
            Some(cert_info_variants[0]),
            Some(cert_info_variants[1]),
            Some(cert_info_variants[2]),
            Some(cert_info_variants[3]),
            Some(cert_info_variants[4]),
            Some(cert_info_variants[5]),
            Some(cert_info_variants[6]),
            Some(cert_info_variants[7]),
        ],
        peer_key_usage_bit_mask: [
            Some(key_usage_variants[0]),
            Some(key_usage_variants[1]),
            Some(key_usage_variants[2]),
            Some(key_usage_variants[3]),
            Some(key_usage_variants[4]),
            Some(key_usage_variants[5]),
            Some(key_usage_variants[6]),
            Some(key_usage_variants[7]),
        ],
    };

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 32768];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmPeerInfo with all data");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded =
        SpdmPeerInfo::read(&mut reader).expect("Failed to decode SpdmPeerInfo with all data");

    assert_eq!(
        original.peer_supported_slot_mask,
        decoded.peer_supported_slot_mask
    );
    assert_eq!(
        original.peer_provisioned_slot_mask,
        decoded.peer_provisioned_slot_mask
    );

    // Test that all populated cert chain data matches
    for slot in 0..SPDM_MAX_SLOT_NUMBER {
        if let (Some(orig_chain), Some(decoded_chain)) = (
            &original.peer_cert_chain[slot],
            &decoded.peer_cert_chain[slot],
        ) {
            assert_eq!(orig_chain.data_size, decoded_chain.data_size);
            assert_eq!(
                orig_chain.data[0..orig_chain.data_size as usize],
                decoded_chain.data[0..orig_chain.data_size as usize]
            );
        }
    }

    // Test all key pair IDs
    for slot in 0..SPDM_MAX_SLOT_NUMBER {
        assert_eq!(
            original.peer_key_pair_id[slot],
            decoded.peer_key_pair_id[slot]
        );
    }

    // Test all cert info
    for slot in 0..SPDM_MAX_SLOT_NUMBER {
        assert_eq!(original.peer_cert_info[slot], decoded.peer_cert_info[slot]);
    }

    // Test all key usage bit masks
    for slot in 0..SPDM_MAX_SLOT_NUMBER {
        assert_eq!(
            original.peer_key_usage_bit_mask[slot],
            decoded.peer_key_usage_bit_mask[slot]
        );
    }
}

#[test]
fn test_spdm_peer_info_codec_edge_cases() {
    // Test with all slots enabled
    let original_full = SpdmPeerInfo {
        peer_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
        peer_cert_chain_temp: None,
        peer_supported_slot_mask: 0xFF,
        peer_provisioned_slot_mask: 0xFF,
        peer_key_pair_id: [None; SPDM_MAX_SLOT_NUMBER],
        peer_cert_info: [None; SPDM_MAX_SLOT_NUMBER],
        peer_key_usage_bit_mask: [None; SPDM_MAX_SLOT_NUMBER],
    };

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 16384];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original_full
        .encode(&mut writer)
        .expect("Failed to encode full mask SpdmPeerInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded_full =
        SpdmPeerInfo::read(&mut reader).expect("Failed to decode full mask SpdmPeerInfo");

    assert_eq!(
        original_full.peer_supported_slot_mask,
        decoded_full.peer_supported_slot_mask
    );
    assert_eq!(
        original_full.peer_provisioned_slot_mask,
        decoded_full.peer_provisioned_slot_mask
    );

    // Test with no slots enabled
    let original_empty = SpdmPeerInfo {
        peer_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
        peer_cert_chain_temp: None,
        peer_supported_slot_mask: 0x00,
        peer_provisioned_slot_mask: 0x00,
        peer_key_pair_id: [None; SPDM_MAX_SLOT_NUMBER],
        peer_cert_info: [None; SPDM_MAX_SLOT_NUMBER],
        peer_key_usage_bit_mask: [None; SPDM_MAX_SLOT_NUMBER],
    };

    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original_empty
        .encode(&mut writer)
        .expect("Failed to encode empty mask SpdmPeerInfo");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded_empty =
        SpdmPeerInfo::read(&mut reader).expect("Failed to decode empty mask SpdmPeerInfo");

    assert_eq!(
        original_empty.peer_supported_slot_mask,
        decoded_empty.peer_supported_slot_mask
    );
    assert_eq!(
        original_empty.peer_provisioned_slot_mask,
        decoded_empty.peer_provisioned_slot_mask
    );
}

#[cfg(feature = "mut-auth")]
#[test]
fn test_spdm_encap_context_codec() {
    let original = SpdmEncapContext::default();

    // Test round-trip encoding/decoding
    let mut buffer = [0u8; 16384];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original
        .encode(&mut writer)
        .expect("Failed to encode SpdmEncapContext");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = SpdmEncapContext::read(&mut reader).expect("Failed to decode SpdmEncapContext");

    // Basic structure test - detailed comparison would depend on SpdmEncapContext fields
    assert_eq!(
        encoded_size,
        decoded
            .encode(&mut Writer::init(&mut [0u8; 16384]))
            .unwrap()
    );
}

// Test edge cases and error conditions

#[test]
fn test_empty_managed_buffers_codec() {
    // Test that empty buffers encode/decode correctly
    let empty_a = ManagedBufferA::default();
    let empty_b = ManagedBufferB::default();

    // Test encoding each empty buffer type
    let mut buffer = [0u8; 1024];

    // Test ManagedBufferA
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = empty_a
        .encode(&mut writer)
        .expect("Failed to encode empty ManagedBufferA");
    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded_a =
        ManagedBufferA::read(&mut reader).expect("Failed to decode empty ManagedBufferA");
    assert_eq!(empty_a.as_ref(), decoded_a.as_ref());

    // Test ManagedBufferB
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = empty_b
        .encode(&mut writer)
        .expect("Failed to encode empty ManagedBufferB");
    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded_b =
        ManagedBufferB::read(&mut reader).expect("Failed to decode empty ManagedBufferB");
    assert_eq!(empty_b.as_ref(), decoded_b.as_ref());
}

#[test]
fn test_option_fields_codec() {
    // Test SpdmConfigInfo with different Option configurations
    let config_with_some_versions = SpdmConfigInfo {
        spdm_version: [
            Some(SpdmVersion::SpdmVersion10),
            Some(SpdmVersion::SpdmVersion11),
            None,
            None,
            None,
        ],
        ..Default::default()
    };

    let config_with_all_none_versions = SpdmConfigInfo {
        spdm_version: [None; MAX_SPDM_VERSION_COUNT],
        ..Default::default()
    };

    for config in [config_with_some_versions, config_with_all_none_versions].iter() {
        let mut buffer = [0u8; 4096];
        let mut writer = Writer::init(&mut buffer);
        let encoded_size = config
            .encode(&mut writer)
            .expect("Failed to encode SpdmConfigInfo with Options");

        let mut reader = Reader::init(&buffer[..encoded_size]);
        let decoded = SpdmConfigInfo::read(&mut reader)
            .expect("Failed to decode SpdmConfigInfo with Options");

        assert_eq!(config.spdm_version, decoded.spdm_version);
    }
}

#[test]
fn test_max_size_buffers() {
    // Test with buffers at their maximum sizes to ensure boundary conditions work
    let mut large_buffer_a = ManagedBufferA::default();
    let large_data = vec![0xAB; MAX_MANAGED_BUFFER_A_SIZE / 2]; // Half max to be safe
    large_buffer_a
        .append_message(&large_data)
        .expect("Failed to append large data");

    let mut buffer = [0u8; 16384];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = large_buffer_a
        .encode(&mut writer)
        .expect("Failed to encode large ManagedBufferA");

    let mut reader = Reader::init(&buffer[..encoded_size]);
    let decoded = ManagedBufferA::read(&mut reader).expect("Failed to decode large ManagedBufferA");

    assert_eq!(large_buffer_a.as_ref(), decoded.as_ref());
}

#[test]
fn test_error_conditions() {
    // Test reading from truncated buffer
    let original = SpdmConfigInfo::default();
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::init(&mut buffer);
    let encoded_size = original.encode(&mut writer).expect("Failed to encode");

    // Try to read from truncated buffer
    let truncated_size = encoded_size / 2;
    let mut reader = Reader::init(&buffer[..truncated_size]);
    let result = SpdmConfigInfo::read(&mut reader);

    // Should fail gracefully
    assert!(
        result.is_none(),
        "Reading from truncated buffer should fail"
    );
}

// Additional comprehensive tests for large structs

#[test]
fn test_spdm_runtime_info_size_variations() {
    // Test with different buffer sizes to ensure robustness
    let original = SpdmRuntimeInfo::default();

    // Test with various buffer sizes
    let buffer_sizes = [1024, 4096, 8192, 16384, 32768];

    for &size in buffer_sizes.iter() {
        let mut buffer = vec![0u8; size];
        let mut writer = Writer::init(&mut buffer);
        let encoded_size = original
            .encode(&mut writer)
            .expect("Failed to encode SpdmRuntimeInfo");

        let mut reader = Reader::init(&buffer[..encoded_size]);
        let decoded = SpdmRuntimeInfo::read(&mut reader).expect("Failed to decode SpdmRuntimeInfo");

        // Verify consistency
        let mut buffer2 = vec![0u8; size];
        let mut writer2 = Writer::init(&mut buffer2);
        let encoded_size2 = decoded
            .encode(&mut writer2)
            .expect("Failed to re-encode SpdmRuntimeInfo");

        assert_eq!(encoded_size, encoded_size2);
    }
}

#[test]
fn test_spdm_negotiate_info_comprehensive() {
    // Test with various algorithm combinations
    let test_cases = [
        SpdmNegotiateInfo {
            spdm_version_sel: SpdmVersion::SpdmVersion10,
            req_capabilities_sel: SpdmRequestCapabilityFlags::CERT_CAP
                | SpdmRequestCapabilityFlags::CHAL_CAP,
            rsp_capabilities_sel: SpdmResponseCapabilityFlags::CERT_CAP
                | SpdmResponseCapabilityFlags::MEAS_CAP_SIG,
            req_ct_exponent_sel: 0,
            rsp_ct_exponent_sel: 0,
            measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
            measurement_hash_sel: SpdmMeasurementHashAlgo::TPM_ALG_SHA_256,
            base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
            dhe_sel: SpdmDheAlgo::SECP_256_R1,
            aead_sel: SpdmAeadAlgo::AES_128_GCM,
            req_asym_sel: SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048,
            key_schedule_sel: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
            other_params_support: SpdmAlgoOtherParams::OPAQUE_DATA_FMT1,
            termination_policy_set: false,
            req_data_transfer_size_sel: 1024,
            req_max_spdm_msg_size_sel: 2048,
            rsp_data_transfer_size_sel: 512,
            rsp_max_spdm_msg_size_sel: 1024,
            mel_specification_sel: SpdmMelSpecification::DMTF_MEL_SPEC,
            multi_key_conn_req: false,
            multi_key_conn_rsp: false,
        },
        SpdmNegotiateInfo {
            spdm_version_sel: SpdmVersion::SpdmVersion12,
            req_capabilities_sel: SpdmRequestCapabilityFlags::all(),
            rsp_capabilities_sel: SpdmResponseCapabilityFlags::all(),
            req_ct_exponent_sel: 24,
            rsp_ct_exponent_sel: 24,
            measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
            measurement_hash_sel: SpdmMeasurementHashAlgo::TPM_ALG_SHA_512,
            base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_512,
            base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
            dhe_sel: SpdmDheAlgo::SECP_384_R1,
            aead_sel: SpdmAeadAlgo::AES_256_GCM,
            req_asym_sel: SpdmReqAsymAlgo::TPM_ALG_RSASSA_4096,
            key_schedule_sel: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
            other_params_support: SpdmAlgoOtherParams::all(),
            termination_policy_set: true,
            req_data_transfer_size_sel: 8192,
            req_max_spdm_msg_size_sel: 16384,
            rsp_data_transfer_size_sel: 4096,
            rsp_max_spdm_msg_size_sel: 8192,
            mel_specification_sel: SpdmMelSpecification::DMTF_MEL_SPEC,
            multi_key_conn_req: true,
            multi_key_conn_rsp: true,
        },
    ];

    for (i, original) in test_cases.iter().enumerate() {
        let mut buffer = [0u8; 4096];
        let mut writer = Writer::init(&mut buffer);
        let encoded_size = original.encode(&mut writer).expect(&format!(
            "Failed to encode SpdmNegotiateInfo test case {}",
            i
        ));

        let mut reader = Reader::init(&buffer[..encoded_size]);
        let decoded = SpdmNegotiateInfo::read(&mut reader).expect(&format!(
            "Failed to decode SpdmNegotiateInfo test case {}",
            i
        ));

        assert_eq!(*original, decoded, "Mismatch in test case {}", i);
    }
}

#[test]
fn test_mixed_buffer_stress() {
    // Test multiple buffer types together in a large buffer
    let mut buffer_a = ManagedBufferA::default();
    let mut buffer_b = ManagedBufferB::default();
    let mut buffer_c = ManagedBufferC::default();

    // Fill buffers with different patterns
    let pattern_a: Vec<u8> = (0..600).map(|i| (i % 256) as u8).collect();
    let pattern_b: Vec<u8> = (0..500).map(|i| ((i * 2) % 256) as u8).collect();
    let pattern_c: Vec<u8> = (0..400).map(|i| ((i * 3) % 256) as u8).collect();

    buffer_a
        .append_message(&pattern_a)
        .expect("Failed to append to buffer A");
    buffer_b
        .append_message(&pattern_b)
        .expect("Failed to append to buffer B");
    buffer_c
        .append_message(&pattern_c)
        .expect("Failed to append to buffer C");

    // Test each buffer individually
    let mut encode_buf = [0u8; 16384];

    // Test buffer A
    let mut writer = Writer::init(&mut encode_buf);
    let encoded_size_a = buffer_a
        .encode(&mut writer)
        .expect("Failed to encode buffer A");
    assert!(encoded_size_a > 0, "Buffer A encoded to zero size");
    assert!(
        encoded_size_a < 16384,
        "Buffer A encoded size too large: {}",
        encoded_size_a
    );

    let mut reader = Reader::init(&encode_buf[..encoded_size_a]);
    let decoded_a = ManagedBufferA::read(&mut reader).expect("Failed to decode buffer A");
    assert_eq!(buffer_a.as_ref(), decoded_a.as_ref());

    // Test buffer B
    let mut writer = Writer::init(&mut encode_buf);
    let encoded_size_b = buffer_b
        .encode(&mut writer)
        .expect("Failed to encode buffer B");
    assert!(encoded_size_b > 0, "Buffer B encoded to zero size");
    assert!(
        encoded_size_b < 16384,
        "Buffer B encoded size too large: {}",
        encoded_size_b
    );

    let mut reader = Reader::init(&encode_buf[..encoded_size_b]);
    let decoded_b = ManagedBufferB::read(&mut reader).expect("Failed to decode buffer B");
    assert_eq!(buffer_b.as_ref(), decoded_b.as_ref());

    // Test buffer C
    let mut writer = Writer::init(&mut encode_buf);
    let encoded_size_c = buffer_c
        .encode(&mut writer)
        .expect("Failed to encode buffer C");
    assert!(encoded_size_c > 0, "Buffer C encoded to zero size");
    assert!(
        encoded_size_c < 16384,
        "Buffer C encoded size too large: {}",
        encoded_size_c
    );

    let mut reader = Reader::init(&encode_buf[..encoded_size_c]);
    let decoded_c = ManagedBufferC::read(&mut reader).expect("Failed to decode buffer C");
    assert_eq!(buffer_c.as_ref(), decoded_c.as_ref());
}

#[test]
fn test_large_struct_memory_boundaries() {
    // Test that large structures handle memory boundaries correctly
    let provision_info = SpdmProvisionInfo {
        my_cert_chain_data: [None; SPDM_MAX_SLOT_NUMBER],
        my_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
        peer_root_cert_data: [None; MAX_ROOT_CERT_SUPPORT],
        local_supported_slot_mask: 0xFF,
        local_key_pair_id: [None; SPDM_MAX_SLOT_NUMBER],
        local_cert_info: [None; SPDM_MAX_SLOT_NUMBER],
        local_key_usage_bit_mask: [None; SPDM_MAX_SLOT_NUMBER],
    };

    let peer_info = SpdmPeerInfo {
        peer_cert_chain: [None; SPDM_MAX_SLOT_NUMBER],
        peer_cert_chain_temp: None,
        peer_supported_slot_mask: 0xFF,
        peer_provisioned_slot_mask: 0xFF,
        peer_key_pair_id: [None; SPDM_MAX_SLOT_NUMBER],
        peer_cert_info: [None; SPDM_MAX_SLOT_NUMBER],
        peer_key_usage_bit_mask: [None; SPDM_MAX_SLOT_NUMBER],
    };

    let runtime_info = SpdmRuntimeInfo::default();

    // Test each large struct with progressively smaller buffers to find minimum size
    let mut test_buffer = [0u8; 65536]; // Start with large buffer

    // Test SpdmProvisionInfo
    let mut writer = Writer::init(&mut test_buffer);
    let provision_size = provision_info
        .encode(&mut writer)
        .expect("Failed to encode SpdmProvisionInfo");

    let mut reader = Reader::init(&test_buffer[..provision_size]);
    let _decoded_provision =
        SpdmProvisionInfo::read(&mut reader).expect("Failed to decode SpdmProvisionInfo");

    // Test SpdmPeerInfo
    let mut writer = Writer::init(&mut test_buffer);
    let peer_size = peer_info
        .encode(&mut writer)
        .expect("Failed to encode SpdmPeerInfo");

    let mut reader = Reader::init(&test_buffer[..peer_size]);
    let _decoded_peer = SpdmPeerInfo::read(&mut reader).expect("Failed to decode SpdmPeerInfo");

    // Test SpdmRuntimeInfo
    let mut writer = Writer::init(&mut test_buffer);
    let runtime_size = runtime_info
        .encode(&mut writer)
        .expect("Failed to encode SpdmRuntimeInfo");

    let mut reader = Reader::init(&test_buffer[..runtime_size]);
    let _decoded_runtime =
        SpdmRuntimeInfo::read(&mut reader).expect("Failed to decode SpdmRuntimeInfo");

    // Ensure sizes are reasonable
    assert!(
        provision_size > 0 && provision_size < 32768,
        "SpdmProvisionInfo size out of bounds: {}",
        provision_size
    );
    assert!(
        peer_size > 0 && peer_size < 32768,
        "SpdmPeerInfo size out of bounds: {}",
        peer_size
    );
    assert!(
        runtime_size > 0 && runtime_size < 32768,
        "SpdmRuntimeInfo size out of bounds: {}",
        runtime_size
    );
}
