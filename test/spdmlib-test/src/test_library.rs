// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::MySpdmDeviceIo;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::new_context;
use codec::{u24, Codec, Reader, Writer};
use spdmlib::common::opaque::*;
use spdmlib::common::SpdmCodec;
use spdmlib::common::SpdmContext;
use spdmlib::common::SpdmContextData;
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
    context.data.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
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
    let u8_slice = &mut [0u8; SPDM_MAX_ASYM_KEY_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmSignatureStruct {
        data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
        data: [100u8; SPDM_MAX_ASYM_KEY_SIZE],
    };

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.data.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(SPDM_MAX_ASYM_KEY_SIZE, reader.left());
    let spdm_signature_struct = SpdmSignatureStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_signature_struct.data_size, RSASSA_4096_KEY_SIZE as u16);
    for i in 0..RSASSA_4096_KEY_SIZE {
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
    context.data.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
    context.data.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;
    context.data.negotiate_info.measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

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
    let u8_slice = &mut [0u8; SPDM_MAX_DHE_KEY_SIZE];
    let mut writer = Writer::init(u8_slice);
    SpdmDheExchangeStruct::default();
    let value = SpdmDheExchangeStruct {
        data_size: SPDM_MAX_DHE_KEY_SIZE as u16,
        data: [100u8; SPDM_MAX_DHE_KEY_SIZE],
    };

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.data.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(SPDM_MAX_DHE_KEY_SIZE, reader.left());
    let spdm_dhe_exchange_struct =
        SpdmDheExchangeStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(
        spdm_dhe_exchange_struct.data_size,
        ECDSA_ECC_NIST_P384_KEY_SIZE as u16
    );
    for i in 0..ECDSA_ECC_NIST_P384_KEY_SIZE {
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
    context.data.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;

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
    context.data.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;

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
fn test_case0_test_spdm_cert_chain_data_deser() {
    // Prepare a SpdmCertChainData with known data
    let mut value = SpdmCertChainData {
        data_size: 32,
        data: [0xAB; 4096],
    };

    // Use a unique pattern for the first few bytes
    for i in 0..value.data_size as usize {
        value.data[i] = i as u8;
    }

    // Zero the padding after data_size
    for i in value.data_size as usize..4096 {
        value.data[i] = 0;
    }

    // Allocate a buffer large enough for serialization
    let mut buf = [0u8; 2 + 4096];
    let mut writer = Writer::init(&mut buf);

    // Serialize
    assert!(value.encode(&mut writer).is_ok());

    // Deserialize
    let mut reader = Reader::init(&buf);
    let deser = SpdmCertChainData::read(&mut reader).expect("Deserialization failed");

    // Check data_size
    assert_eq!(deser.data_size, value.data_size);
    // Check first few bytes
    for i in 0..value.data_size as usize {
        assert_eq!(deser.data[i], value.data[i], "Mismatch at byte {}", i);
    }
    // Check that the rest of the buffer is zeroed (default)
    for i in value.data_size as usize..4096 {
        assert_eq!(deser.data[i], 0, "Padding mismatch at byte {}", i);
    }
    // Reader should be at end
    assert_eq!(reader.left(), 0);
    // End of test_case0_test_spdm_cert_chain_data_deser
    // (no extra closing brace)
}

#[test]
fn test_case0_spdm_context_export_import() {
    let first_pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let first_my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));

    let second_pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let second_my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));

    let context = new_context(first_my_spdm_device_io, first_pcidoe_transport_encap);

    let exported_context = context.export();
    let imported_context = SpdmContext::import(
        exported_context.unwrap(),
        second_my_spdm_device_io,
        second_pcidoe_transport_encap,
    );

    assert_eq!(imported_context.unwrap().data, context.data);
}

#[test]
fn test_case1_spdm_context_export_import() {
    let first_pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let first_my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));

    let second_pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let second_my_spdm_device_io = Arc::new(Mutex::new(MySpdmDeviceIo));

    let mut context = new_context(first_my_spdm_device_io, first_pcidoe_transport_encap);

    // Populate context with some random data
    // Use a simple deterministic pattern for test data to avoid external dependencies and type issues
    // Set some fields in config_info
    context.data.config_info.req_capabilities =
        SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP;
    context.data.config_info.rsp_capabilities = SpdmResponseCapabilityFlags::ENCRYPT_CAP;
    context.data.config_info.req_ct_exponent = 7;
    context.data.config_info.rsp_ct_exponent = 3;
    context.data.config_info.measurement_specification = SpdmMeasurementSpecification::DMTF;
    context.data.config_info.measurement_hash_algo = SpdmMeasurementHashAlgo::TPM_ALG_SHA_256;
    context.data.config_info.base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.data.config_info.base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048;
    context.data.config_info.dhe_algo = SpdmDheAlgo::SECP_256_R1;
    context.data.config_info.aead_algo = SpdmAeadAlgo::AES_256_GCM;
    context.data.config_info.req_asym_algo = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    context.data.config_info.key_schedule_algo = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
    context.data.config_info.session_policy = 0xAA;
    context.data.config_info.data_transfer_size = 0x1234;
    context.data.config_info.max_spdm_msg_size = 0x5678;
    context.data.config_info.heartbeat_period = 0x42;

    // Set some fields in provision_info
    for slot in 0..context.data.provision_info.my_cert_chain_data.len() {
        context.data.provision_info.my_cert_chain_data[slot] = Some(SpdmCertChainData {
            data_size: 16,
            data: [slot as u8; 4096],
        });
    }
    context.data.provision_info.local_supported_slot_mask = 0x1F;

    // Set some fields in peer_info
    for slot in 0..context.data.peer_info.peer_cert_chain.len() {
        let mut buf = [slot as u8; 4164];
        for i in 16..4164 {
            buf[i] = 0;
        }
        context.data.peer_info.peer_cert_chain[slot] = Some(SpdmCertChainBuffer {
            data_size: 16,
            data: buf,
        });
    }
    context.data.peer_info.peer_supported_slot_mask = 0x1F;

    // Set some session data
    for (i, session) in context.data.session.iter_mut().enumerate() {
        session.set_session_id(0x1000 + i as u32);
        // Use the enum from the session module
        session
            .set_session_state(spdmlib::common::session::SpdmSessionState::SpdmSessionHandshaking);
    }

    let exported_context = context.export();
    let imported_context = SpdmContext::import(
        exported_context.unwrap(),
        second_my_spdm_device_io,
        second_pcidoe_transport_encap,
    );

    assert_eq!(context.data, context.data); // verify Eq
    assert_eq!(context.data, imported_context.unwrap().data); // verify Eq
}
