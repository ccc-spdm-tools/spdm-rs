// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::MySpdmDeviceIo;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::new_context;
use codec::{u24, Codec, Reader, Writer};
use spdmlib::common::opaque::*;
use spdmlib::common::SpdmCodec;
use spdmlib::config::{MAX_SPDM_MEASUREMENT_RECORD_SIZE, MAX_SPDM_MEASUREMENT_VALUE_LEN};
use spdmlib::protocol::*;
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_spdm_opaque_struct() {
    let u8_slice = &mut [0u8; 2 + MAX_SPDM_OPAQUE_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmOpaqueStruct {
        data_size: MAX_SPDM_OPAQUE_SIZE as u16,
        data: [100u8; MAX_SPDM_OPAQUE_SIZE],
    };

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(2 + MAX_SPDM_OPAQUE_SIZE, reader.left());
    let spdm_opaque_struct = SpdmOpaqueStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_opaque_struct.data_size, MAX_SPDM_OPAQUE_SIZE as u16);
    for i in 0..MAX_SPDM_OPAQUE_SIZE {
        assert_eq!(spdm_opaque_struct.data[i], 100);
    }
    assert_eq!(0, reader.left());
}

#[test]
fn test_case0_spdm_digest_struct() {
    let u8_slice = &mut [0u8; SPDM_MAX_HASH_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmDigestStruct {
        data_size: SPDM_MAX_HASH_SIZE as u16,
        data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
    };

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(SPDM_MAX_HASH_SIZE, reader.left());
    let spdm_digest_struct = SpdmDigestStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_digest_struct.data_size, SPDM_MAX_HASH_SIZE as u16);
    for i in 0..SPDM_MAX_HASH_SIZE {
        assert_eq!(spdm_digest_struct.data[i], 100u8);
    }
    assert_eq!(0, reader.left());
}
#[test]
fn test_case0_spdm_signature_struct() {
    let u8_slice = &mut [0u8; RSASSA_4096_SIG_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmSignatureStruct {
        data_size: RSASSA_4096_SIG_SIZE as u16,
        data: [100u8; SPDM_MAX_ASYM_SIG_SIZE],
    };

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(RSASSA_4096_SIG_SIZE, reader.left());
    let spdm_signature_struct = SpdmSignatureStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_signature_struct.data_size, RSASSA_4096_SIG_SIZE as u16);
    for i in 0..RSASSA_4096_SIG_SIZE {
        assert_eq!(spdm_signature_struct.data[i], 100);
    }
}
#[test]
fn test_case0_spdm_measurement_record_structure() {
    let u8_slice = &mut [0u8; 512];
    let mut writer = Writer::init(u8_slice);
    let mut spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
        index: 1u8,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_size: 3 + SHA512_DIGEST_SIZE as u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: SHA512_DIGEST_SIZE as u16,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let mut measurement_record_data = [0u8; MAX_SPDM_MEASUREMENT_RECORD_SIZE];
    let mut measurement_record_data_writer = Writer::init(&mut measurement_record_data);

    for _i in 0..5 {
        assert!(spdm_measurement_block_structure
            .encode(&mut measurement_record_data_writer)
            .is_ok());
        spdm_measurement_block_structure.index += 1;
    }

    let value = SpdmMeasurementRecordStructure {
        number_of_blocks: 5,
        measurement_record_length: u24::new(measurement_record_data_writer.used() as u32),
        measurement_record_data,
    };

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
    context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;
    context.negotiate_info.measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(512, reader.left());
    let measurement_record =
        SpdmMeasurementRecordStructure::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(measurement_record.number_of_blocks, 5);
}

#[test]
fn test_case1_spdm_measurement_record_structure() {
    let u8_slice = &mut [0u8; 512];
    let mut writer = Writer::init(u8_slice);
    let mut spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
        index: 1u8,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_size: 3 + SHA512_DIGEST_SIZE as u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: SHA512_DIGEST_SIZE as u16,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let mut measurement_record_data = [0u8; MAX_SPDM_MEASUREMENT_RECORD_SIZE];
    let mut measurement_record_data_writer = Writer::init(&mut measurement_record_data);

    for _i in 0..5 {
        assert!(spdm_measurement_block_structure
            .encode(&mut measurement_record_data_writer)
            .is_ok());
        spdm_measurement_block_structure.index += 1;
    }

    let value = SpdmMeasurementRecordStructure {
        number_of_blocks: 5,
        measurement_record_length: u24::new(measurement_record_data_writer.used() as u32),
        measurement_record_data,
    };

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
}
#[test]
fn test_case0_spdm_dhe_exchange_struct() {
    let u8_slice = &mut [0u8; SECP_384_R1_KEY_SIZE];
    let mut writer = Writer::init(u8_slice);
    SpdmDheExchangeStruct::default();
    let value = SpdmDheExchangeStruct {
        data_size: SECP_384_R1_KEY_SIZE as u16,
        data: [100u8; SPDM_MAX_DHE_KEY_SIZE],
    };

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(SECP_384_R1_KEY_SIZE, reader.left());
    let spdm_dhe_exchange_struct =
        SpdmDheExchangeStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(
        spdm_dhe_exchange_struct.data_size,
        SECP_384_R1_KEY_SIZE as u16
    );
    for i in 0..SECP_384_R1_KEY_SIZE {
        assert_eq!(spdm_dhe_exchange_struct.data[i], 100);
    }
    assert_eq!(0, reader.left());
}
#[test]
fn test_case0_spdm_dmtf_measurement_structure() {
    let mut value = SpdmDmtfMeasurementStructure::default();
    let r#type = [
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest,
    ];
    let representation = [
        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
    ];
    value.value_size = SHA512_DIGEST_SIZE as u16;
    value.value = [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN];

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;

    for i in 0..5 {
        value.r#type = r#type[i];
        if i < 2 {
            value.representation = representation[i];
        }
        let u8_slice = &mut [0u8; 3 + SPDM_MAX_HASH_SIZE];
        let mut writer = Writer::init(u8_slice);
        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(3 + SPDM_MAX_HASH_SIZE, reader.left());
        let spdm_dmtf_measurement_structure =
            SpdmDmtfMeasurementStructure::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_dmtf_measurement_structure.r#type, r#type[i]);
        if i < 2 {
            assert_eq!(
                spdm_dmtf_measurement_structure.representation,
                representation[i]
            );
        }
        assert_eq!(
            spdm_dmtf_measurement_structure.value_size,
            SHA512_DIGEST_SIZE as u16
        );
        for j in 0..SHA512_DIGEST_SIZE {
            assert_eq!(spdm_dmtf_measurement_structure.value[j], 100);
        }
        assert_eq!(0, reader.left());
    }
}
#[test]
fn test_case0_spdm_measurement_block_structure() {
    let u8_slice = &mut [0u8; 4 + 3 + SPDM_MAX_HASH_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmMeasurementBlockStructure {
        index: 1u8,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_size: 3 + SHA512_DIGEST_SIZE as u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: SHA512_DIGEST_SIZE as u16,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(4 + 3 + SPDM_MAX_HASH_SIZE, reader.left());
    let spdm_block_structure =
        SpdmMeasurementBlockStructure::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_block_structure.index, 1);
    assert_eq!(
        spdm_block_structure.measurement_specification,
        SpdmMeasurementSpecification::DMTF
    );
    assert_eq!(
        spdm_block_structure.measurement_size,
        3 + SHA512_DIGEST_SIZE as u16
    );
    assert_eq!(
        spdm_block_structure.measurement.r#type,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
    );
    assert_eq!(
        spdm_block_structure.measurement.representation,
        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
    );
    assert_eq!(
        spdm_block_structure.measurement.value_size,
        SHA512_DIGEST_SIZE as u16
    );
    for i in 0..SHA512_DIGEST_SIZE {
        assert_eq!(spdm_block_structure.measurement.value[i], 100);
    }
    assert_eq!(0, reader.left());
}

#[test]
fn test_case0_spdm_context_export_import() {
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut original_context =
        new_context(my_spdm_device_io.clone(), pcidoe_transport_encap.clone());

    // Populate context with some test data to verify round-trip
    original_context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    original_context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    original_context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    original_context.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
    original_context.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;
    original_context.negotiate_info.rsp_capabilities_sel =
        SpdmResponseCapabilityFlags::CERT_CAP | SpdmResponseCapabilityFlags::CHAL_CAP;
    original_context
        .runtime_info
        .set_connection_state(spdmlib::common::SpdmConnectionState::SpdmConnectionNegotiated);

    // Export the context
    let exported_data = original_context.export().expect("Export should succeed");
    assert!(
        !exported_data.is_empty(),
        "Exported data should not be empty"
    );

    // Create a new context and import the data
    let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io2 = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut imported_context = new_context(my_spdm_device_io2, pcidoe_transport_encap2);

    // Import should succeed
    imported_context
        .import(&exported_data)
        .expect("Import should succeed");

    // Verify that the imported data matches the original
    assert_eq!(
        imported_context.negotiate_info.spdm_version_sel,
        original_context.negotiate_info.spdm_version_sel
    );
    assert_eq!(
        imported_context.negotiate_info.base_hash_sel,
        original_context.negotiate_info.base_hash_sel
    );
    assert_eq!(
        imported_context.negotiate_info.base_asym_sel,
        original_context.negotiate_info.base_asym_sel
    );
    assert_eq!(
        imported_context.negotiate_info.aead_sel,
        original_context.negotiate_info.aead_sel
    );
    assert_eq!(
        imported_context.negotiate_info.req_capabilities_sel,
        original_context.negotiate_info.req_capabilities_sel
    );
    assert_eq!(
        imported_context.negotiate_info.rsp_capabilities_sel,
        original_context.negotiate_info.rsp_capabilities_sel
    );
    assert_eq!(
        imported_context.runtime_info.get_connection_state(),
        original_context.runtime_info.get_connection_state()
    );

    // Test edge case: empty data should fail
    let mut empty_context = new_context(
        Arc::new(Mutex::new(MySpdmDeviceIo)),
        Arc::new(Mutex::new(PciDoeTransportEncap {})),
    );
    assert!(
        empty_context.import(&[]).is_err(),
        "Import of empty data should fail"
    );

    // Test edge case: truncated data should fail
    let truncated_data = &exported_data[..10];
    let mut truncated_context = new_context(
        Arc::new(Mutex::new(MySpdmDeviceIo)),
        Arc::new(Mutex::new(PciDoeTransportEncap {})),
    );
    assert!(
        truncated_context.import(truncated_data).is_err(),
        "Import of truncated data should fail"
    );
}

#[test]
fn test_case1_spdm_context_export_import_with_cert_data() {
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut original_context =
        new_context(my_spdm_device_io.clone(), pcidoe_transport_encap.clone());

    // Populate context with comprehensive test data including certificates
    original_context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;
    original_context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    original_context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048;
    original_context.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
    original_context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
    original_context.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048;
    original_context.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
    original_context.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP;
    original_context.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP;
    original_context
        .negotiate_info
        .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
    original_context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_256;
    original_context
        .runtime_info
        .set_connection_state(spdmlib::common::SpdmConnectionState::SpdmConnectionAuthenticated);
    original_context
        .runtime_info
        .set_local_used_cert_chain_slot_id(0);
    original_context
        .runtime_info
        .set_peer_used_cert_chain_slot_id(1);

    // Populate provision info with mock certificate data - different for each slot
    let mut cert_chain_data_slot0 = spdmlib::protocol::SpdmCertChainData {
        data_size: 512,
        data: [0u8; spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    // Fill slot 0 with pattern starting at 0x42
    for i in 0..512 {
        cert_chain_data_slot0.data[i] = ((i % 256) as u8).wrapping_add(0x42);
    }

    let mut cert_chain_data_slot1 = spdmlib::protocol::SpdmCertChainData {
        data_size: 768, // Different size for slot 1
        data: [0u8; spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    // Fill slot 1 with different pattern starting at 0x73
    for i in 0..768 {
        cert_chain_data_slot1.data[i] = ((i % 256) as u8).wrapping_add(0x73);
    }

    original_context.provision_info.my_cert_chain_data[0] = Some(cert_chain_data_slot0);
    original_context.provision_info.my_cert_chain_data[1] = Some(cert_chain_data_slot1);

    // Populate with mock certificate chain buffer - different for each slot
    let mut cert_chain_buffer_slot0 = spdmlib::protocol::SpdmCertChainBuffer {
        data_size: 600,
        data: [0u8; 4
            + spdmlib::protocol::SPDM_MAX_HASH_SIZE
            + spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    // Fill slot 0 with pattern starting at 0x84
    for i in 0..600 {
        cert_chain_buffer_slot0.data[i] = ((i % 256) as u8).wrapping_add(0x84);
    }

    let mut cert_chain_buffer_slot1 = spdmlib::protocol::SpdmCertChainBuffer {
        data_size: 900, // Different size for slot 1
        data: [0u8; 4
            + spdmlib::protocol::SPDM_MAX_HASH_SIZE
            + spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    // Fill slot 1 with different pattern starting at 0xC6
    for i in 0..900 {
        cert_chain_buffer_slot1.data[i] = ((i % 256) as u8).wrapping_add(0xC6);
    }

    original_context.provision_info.my_cert_chain[0] = Some(cert_chain_buffer_slot0);
    original_context.provision_info.my_cert_chain[1] = Some(cert_chain_buffer_slot1);

    // Populate peer info with mock peer certificate data - different for each slot
    let mut peer_cert_chain_slot0 = spdmlib::protocol::SpdmCertChainBuffer {
        data_size: 450,
        data: [0u8; 4
            + spdmlib::protocol::SPDM_MAX_HASH_SIZE
            + spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    // Fill slot 0 with pattern starting at 0xA1
    for i in 0..450 {
        peer_cert_chain_slot0.data[i] = ((i % 256) as u8).wrapping_add(0xA1);
    }

    let mut peer_cert_chain_slot1 = spdmlib::protocol::SpdmCertChainBuffer {
        data_size: 650, // Different size for slot 1
        data: [0u8; 4
            + spdmlib::protocol::SPDM_MAX_HASH_SIZE
            + spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
    };
    // Fill slot 1 with different pattern starting at 0xD7
    for i in 0..650 {
        peer_cert_chain_slot1.data[i] = ((i % 256) as u8).wrapping_add(0xD7);
    }

    original_context.peer_info.peer_cert_chain[0] = Some(peer_cert_chain_slot0);
    original_context.peer_info.peer_cert_chain[1] = Some(peer_cert_chain_slot1);

    // Set peer slot masks
    original_context.peer_info.peer_supported_slot_mask = 0b00000011; // slots 0 and 1
    original_context.peer_info.peer_provisioned_slot_mask = 0b00000011; // slots 0 and 1

    // Export the context with all the populated data
    let exported_data = original_context.export().expect("Export should succeed");
    assert!(
        !exported_data.is_empty(),
        "Exported data should not be empty"
    );

    // Create a new context and import the data
    let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io2 = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut imported_context = new_context(my_spdm_device_io2, pcidoe_transport_encap2);

    // Import should succeed
    imported_context
        .import(&exported_data)
        .expect("Import should succeed");

    // Verify negotiate_info fields
    assert_eq!(
        imported_context.negotiate_info.spdm_version_sel,
        original_context.negotiate_info.spdm_version_sel
    );
    assert_eq!(
        imported_context.negotiate_info.base_hash_sel,
        original_context.negotiate_info.base_hash_sel
    );
    assert_eq!(
        imported_context.negotiate_info.base_asym_sel,
        original_context.negotiate_info.base_asym_sel
    );
    assert_eq!(
        imported_context.negotiate_info.aead_sel,
        original_context.negotiate_info.aead_sel
    );
    assert_eq!(
        imported_context.negotiate_info.dhe_sel,
        original_context.negotiate_info.dhe_sel
    );
    assert_eq!(
        imported_context.negotiate_info.req_asym_sel,
        original_context.negotiate_info.req_asym_sel
    );
    assert_eq!(
        imported_context.negotiate_info.key_schedule_sel,
        original_context.negotiate_info.key_schedule_sel
    );
    assert_eq!(
        imported_context.negotiate_info.req_capabilities_sel,
        original_context.negotiate_info.req_capabilities_sel
    );
    assert_eq!(
        imported_context.negotiate_info.rsp_capabilities_sel,
        original_context.negotiate_info.rsp_capabilities_sel
    );
    assert_eq!(
        imported_context
            .negotiate_info
            .measurement_specification_sel,
        original_context
            .negotiate_info
            .measurement_specification_sel
    );
    assert_eq!(
        imported_context.negotiate_info.measurement_hash_sel,
        original_context.negotiate_info.measurement_hash_sel
    );

    // Verify runtime_info fields
    assert_eq!(
        imported_context.runtime_info.get_connection_state(),
        original_context.runtime_info.get_connection_state()
    );
    assert_eq!(
        imported_context
            .runtime_info
            .get_local_used_cert_chain_slot_id(),
        original_context
            .runtime_info
            .get_local_used_cert_chain_slot_id()
    );
    assert_eq!(
        imported_context
            .runtime_info
            .get_peer_used_cert_chain_slot_id(),
        original_context
            .runtime_info
            .get_peer_used_cert_chain_slot_id()
    );

    // Verify provision_info certificate data
    for slot in 0..2 {
        assert_eq!(
            imported_context.provision_info.my_cert_chain_data[slot].is_some(),
            original_context.provision_info.my_cert_chain_data[slot].is_some()
        );
        if let (Some(imported_cert), Some(original_cert)) = (
            &imported_context.provision_info.my_cert_chain_data[slot],
            &original_context.provision_info.my_cert_chain_data[slot],
        ) {
            assert_eq!(imported_cert.data_size, original_cert.data_size);
            assert_eq!(
                &imported_cert.data[..imported_cert.data_size as usize],
                &original_cert.data[..original_cert.data_size as usize]
            );
        }

        assert_eq!(
            imported_context.provision_info.my_cert_chain[slot].is_some(),
            original_context.provision_info.my_cert_chain[slot].is_some()
        );
        if let (Some(imported_chain), Some(original_chain)) = (
            &imported_context.provision_info.my_cert_chain[slot],
            &original_context.provision_info.my_cert_chain[slot],
        ) {
            assert_eq!(imported_chain.data_size, original_chain.data_size);
            assert_eq!(
                &imported_chain.data[..imported_chain.data_size as usize],
                &original_chain.data[..original_chain.data_size as usize]
            );
        }
    }

    // Verify peer_info certificate data
    for slot in 0..2 {
        assert_eq!(
            imported_context.peer_info.peer_cert_chain[slot].is_some(),
            original_context.peer_info.peer_cert_chain[slot].is_some()
        );
        if let (Some(imported_peer), Some(original_peer)) = (
            &imported_context.peer_info.peer_cert_chain[slot],
            &original_context.peer_info.peer_cert_chain[slot],
        ) {
            assert_eq!(imported_peer.data_size, original_peer.data_size);
            assert_eq!(
                &imported_peer.data[..imported_peer.data_size as usize],
                &original_peer.data[..original_peer.data_size as usize]
            );
        }
    }

    // Verify peer slot masks
    assert_eq!(
        imported_context.peer_info.peer_supported_slot_mask,
        original_context.peer_info.peer_supported_slot_mask
    );
    assert_eq!(
        imported_context.peer_info.peer_provisioned_slot_mask,
        original_context.peer_info.peer_provisioned_slot_mask
    );
}

#[test]
fn test_case2_spdm_context_export_import_with_sessions() {
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut original_context =
        new_context(my_spdm_device_io.clone(), pcidoe_transport_encap.clone());

    // Set up a comprehensive context with sessions
    original_context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    original_context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
    original_context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    original_context.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
    original_context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
    original_context.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    original_context.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
    original_context
        .runtime_info
        .set_connection_state(spdmlib::common::SpdmConnectionState::SpdmConnectionAuthenticated);

    // Populate message buffers with test data
    original_context
        .runtime_info
        .message_a
        .append_message(&[0x01, 0x02, 0x03, 0x04])
        .unwrap();
    #[cfg(not(feature = "hashed-transcript-data"))]
    {
        original_context
            .runtime_info
            .message_b
            .append_message(&[0x05, 0x06, 0x07, 0x08])
            .unwrap();
        original_context
            .runtime_info
            .message_c
            .append_message(&[0x09, 0x0A, 0x0B, 0x0C])
            .unwrap();
        original_context
            .runtime_info
            .message_m
            .append_message(&[0x0D, 0x0E, 0x0F, 0x10])
            .unwrap();
    }

    // Set up session data - simulate an active session
    if let Some(session) = original_context.get_session_via_id(0) {
        session.setup(0x12345678).unwrap();
        session.set_use_psk(false);
        session.heartbeat_period = 30;
        session
            .runtime_info
            .message_a
            .append_message(&[0x11, 0x12, 0x13, 0x14])
            .unwrap();
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            session
                .runtime_info
                .message_k
                .append_message(&[0x15, 0x16, 0x17, 0x18])
                .unwrap();
            session
                .runtime_info
                .message_f
                .append_message(&[0x19, 0x1A, 0x1B, 0x1C])
                .unwrap();
            session
                .runtime_info
                .message_m
                .append_message(&[0x1D, 0x1E, 0x1F, 0x20])
                .unwrap();
        }
    }

    // Export the context
    let exported_data = original_context.export().expect("Export should succeed");
    assert!(
        !exported_data.is_empty(),
        "Exported data should not be empty"
    );

    // Create a new context and import the data
    let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io2 = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut imported_context = new_context(my_spdm_device_io2, pcidoe_transport_encap2);

    // Import should succeed
    imported_context
        .import(&exported_data)
        .expect("Import should succeed");

    // Verify all fields match
    assert_eq!(
        imported_context.negotiate_info.spdm_version_sel,
        original_context.negotiate_info.spdm_version_sel
    );
    assert_eq!(
        imported_context.negotiate_info.base_hash_sel,
        original_context.negotiate_info.base_hash_sel
    );
    assert_eq!(
        imported_context.negotiate_info.base_asym_sel,
        original_context.negotiate_info.base_asym_sel
    );
    assert_eq!(
        imported_context.negotiate_info.aead_sel,
        original_context.negotiate_info.aead_sel
    );
    assert_eq!(
        imported_context.negotiate_info.dhe_sel,
        original_context.negotiate_info.dhe_sel
    );
    assert_eq!(
        imported_context.negotiate_info.req_asym_sel,
        original_context.negotiate_info.req_asym_sel
    );
    assert_eq!(
        imported_context.negotiate_info.key_schedule_sel,
        original_context.negotiate_info.key_schedule_sel
    );
    assert_eq!(
        imported_context.runtime_info.get_connection_state(),
        original_context.runtime_info.get_connection_state()
    );

    // Verify message buffers
    assert_eq!(
        imported_context.runtime_info.message_a.as_ref(),
        original_context.runtime_info.message_a.as_ref()
    );
    #[cfg(not(feature = "hashed-transcript-data"))]
    {
        assert_eq!(
            imported_context.runtime_info.message_b.as_ref(),
            original_context.runtime_info.message_b.as_ref()
        );
        assert_eq!(
            imported_context.runtime_info.message_c.as_ref(),
            original_context.runtime_info.message_c.as_ref()
        );
        assert_eq!(
            imported_context.runtime_info.message_m.as_ref(),
            original_context.runtime_info.message_m.as_ref()
        );
    }

    // Verify session data
    let imported_session = imported_context.get_immutable_session_via_id(0x12345678);
    let original_session = original_context.get_immutable_session_via_id(0x12345678);
    assert!(imported_session.is_some() && original_session.is_some());

    if let (Some(imp_sess), Some(orig_sess)) = (imported_session, original_session) {
        assert_eq!(imp_sess.get_session_id(), orig_sess.get_session_id());
        assert_eq!(imp_sess.get_use_psk(), orig_sess.get_use_psk());
        assert_eq!(imp_sess.heartbeat_period, orig_sess.heartbeat_period);
        assert_eq!(
            imp_sess.runtime_info.message_a.as_ref(),
            orig_sess.runtime_info.message_a.as_ref()
        );
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            assert_eq!(
                imp_sess.runtime_info.message_k.as_ref(),
                orig_sess.runtime_info.message_k.as_ref()
            );
            assert_eq!(
                imp_sess.runtime_info.message_f.as_ref(),
                orig_sess.runtime_info.message_f.as_ref()
            );
            assert_eq!(
                imp_sess.runtime_info.message_m.as_ref(),
                orig_sess.runtime_info.message_m.as_ref()
            );
        }
    }
}

#[test]
fn test_case3_spdm_context_export_import_boundary_conditions() {
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut original_context =
        new_context(my_spdm_device_io.clone(), pcidoe_transport_encap.clone());

    // Test maximum algorithm combinations
    original_context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;
    original_context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
    original_context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    original_context.negotiate_info.aead_sel = SpdmAeadAlgo::CHACHA20_POLY1305;
    original_context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
    original_context.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    original_context.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
    original_context
        .negotiate_info
        .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
    original_context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;

    // Maximum capability flags
    original_context.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PSK_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP;

    original_context.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
        | SpdmResponseCapabilityFlags::ENCAP_CAP
        | SpdmResponseCapabilityFlags::HBEAT_CAP
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP;

    // Populate all certificate slots with maximum data
    for slot in 0..spdmlib::protocol::SPDM_MAX_SLOT_NUMBER {
        let mut cert_chain_data = spdmlib::protocol::SpdmCertChainData {
            data_size: spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE as u32,
            data: [0u8; spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        };
        // Fill with pattern specific to slot
        for i in 0..spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE {
            cert_chain_data.data[i] = ((i + slot * 256) % 256) as u8;
        }
        original_context.provision_info.my_cert_chain_data[slot] = Some(cert_chain_data);

        let mut cert_chain_buffer = spdmlib::protocol::SpdmCertChainBuffer {
            data_size: (4
                + spdmlib::protocol::SPDM_MAX_HASH_SIZE
                + spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE) as u32,
            data: [0u8; 4
                + spdmlib::protocol::SPDM_MAX_HASH_SIZE
                + spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        };
        // Fill with pattern specific to slot
        for i in 0..(4
            + spdmlib::protocol::SPDM_MAX_HASH_SIZE
            + spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE)
        {
            cert_chain_buffer.data[i] = ((i + slot * 512) % 256) as u8;
        }
        original_context.provision_info.my_cert_chain[slot] = Some(cert_chain_buffer);
        original_context.peer_info.peer_cert_chain[slot] = Some(cert_chain_buffer);
    }

    // Set all slot masks
    original_context.provision_info.local_supported_slot_mask = 0xFF;
    original_context.peer_info.peer_supported_slot_mask = 0xFF;
    original_context.peer_info.peer_provisioned_slot_mask = 0xFF;

    // Fill message buffers to near capacity (but not full to avoid overflow)
    let large_message = vec![0xAB; 256]; // Reduced size to avoid buffer overflow
    original_context
        .runtime_info
        .message_a
        .append_message(&large_message)
        .unwrap();
    #[cfg(not(feature = "hashed-transcript-data"))]
    {
        original_context
            .runtime_info
            .message_b
            .append_message(&large_message)
            .unwrap();
        original_context
            .runtime_info
            .message_c
            .append_message(&large_message)
            .unwrap();
        original_context
            .runtime_info
            .message_m
            .append_message(&large_message)
            .unwrap();
    }

    original_context
        .runtime_info
        .set_connection_state(spdmlib::common::SpdmConnectionState::SpdmConnectionAuthenticated);

    // Export and test
    let exported_data = original_context
        .export()
        .expect("Export should succeed with maximum data");
    assert!(
        !exported_data.is_empty(),
        "Exported data should not be empty"
    );

    // Create a new context and import
    let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io2 = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut imported_context = new_context(my_spdm_device_io2, pcidoe_transport_encap2);

    imported_context
        .import(&exported_data)
        .expect("Import should succeed with maximum data");

    // Verify comprehensive data integrity
    assert_eq!(
        imported_context.negotiate_info.spdm_version_sel,
        original_context.negotiate_info.spdm_version_sel
    );
    assert_eq!(
        imported_context.negotiate_info.base_hash_sel,
        original_context.negotiate_info.base_hash_sel
    );
    assert_eq!(
        imported_context.negotiate_info.req_capabilities_sel,
        original_context.negotiate_info.req_capabilities_sel
    );
    assert_eq!(
        imported_context.negotiate_info.rsp_capabilities_sel,
        original_context.negotiate_info.rsp_capabilities_sel
    );
    assert_eq!(
        imported_context.provision_info.local_supported_slot_mask,
        original_context.provision_info.local_supported_slot_mask
    );
    assert_eq!(
        imported_context.peer_info.peer_supported_slot_mask,
        original_context.peer_info.peer_supported_slot_mask
    );
    assert_eq!(
        imported_context.peer_info.peer_provisioned_slot_mask,
        original_context.peer_info.peer_provisioned_slot_mask
    );

    // Verify all certificate slots
    for slot in 0..spdmlib::protocol::SPDM_MAX_SLOT_NUMBER {
        assert_eq!(
            imported_context.provision_info.my_cert_chain_data[slot].is_some(),
            original_context.provision_info.my_cert_chain_data[slot].is_some()
        );
        if let (Some(imported_cert), Some(original_cert)) = (
            &imported_context.provision_info.my_cert_chain_data[slot],
            &original_context.provision_info.my_cert_chain_data[slot],
        ) {
            assert_eq!(imported_cert.data_size, original_cert.data_size);
            assert_eq!(imported_cert.data, original_cert.data);
        }
    }

    // Verify message buffer integrity
    assert_eq!(
        imported_context.runtime_info.message_a.as_ref(),
        original_context.runtime_info.message_a.as_ref()
    );
    #[cfg(not(feature = "hashed-transcript-data"))]
    {
        assert_eq!(
            imported_context.runtime_info.message_b.as_ref(),
            original_context.runtime_info.message_b.as_ref()
        );
        assert_eq!(
            imported_context.runtime_info.message_c.as_ref(),
            original_context.runtime_info.message_c.as_ref()
        );
        assert_eq!(
            imported_context.runtime_info.message_m.as_ref(),
            original_context.runtime_info.message_m.as_ref()
        );
    }
}
