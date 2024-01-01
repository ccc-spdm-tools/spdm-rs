// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![allow(dead_code)]
#![allow(unused_variables)]
use codec::u24;
use codec::Codec;
use codec::Writer;
use spdmlib::common::key_schedule::SpdmKeySchedule;
use spdmlib::config;
use spdmlib::crypto;
use spdmlib::crypto::hash;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::protocol::{
    SpdmBaseHashAlgo, SpdmDigestStruct, SpdmHkdfOutputKeyingMaterial,
    SpdmMeasurementRecordStructure, SpdmMeasurementSpecification, SpdmMeasurementSummaryHashType,
};
use spdmlib::secret::*;

pub static SECRET_MEASUREMENT_IMPL_INSTANCE: SpdmSecretMeasurement = SpdmSecretMeasurement {
    measurement_collection_cb: measurement_collection_impl,
    generate_measurement_summary_hash_cb: generate_measurement_summary_hash_impl,
};

pub static SECRET_PSK_IMPL_INSTANCE: SpdmSecretPsk = SpdmSecretPsk {
    handshake_secret_hkdf_expand_cb: handshake_secret_hkdf_expand_impl,
    master_secret_hkdf_expand_cb: master_secret_hkdf_expand_impl,
};

#[allow(clippy::field_reassign_with_default)]
fn measurement_collection_impl(
    spdm_version: SpdmVersion,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmMeasurementHashAlgo,
    measurement_index: usize,
) -> Option<SpdmMeasurementRecordStructure> {
    if measurement_specification != SpdmMeasurementSpecification::DMTF {
        None
    } else {
        let base_hash_algo = match measurement_hash_algo {
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_256 => SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384 => SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_512 => SpdmBaseHashAlgo::TPM_ALG_SHA_512,
            SpdmMeasurementHashAlgo::RAW_BIT_STREAM
            | SpdmMeasurementHashAlgo::TPM_ALG_SHA3_256
            | SpdmMeasurementHashAlgo::TPM_ALG_SHA3_384
            | SpdmMeasurementHashAlgo::TPM_ALG_SHA3_512
            | SpdmMeasurementHashAlgo::TPM_ALG_SM3 => return None,
            _ => return None,
        };
        let hashsize = base_hash_algo.get_size();
        if measurement_index
            == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber.get_u8() as usize
        {
            let mut dummy_spdm_measurement_record_structure =
                SpdmMeasurementRecordStructure::default();
            dummy_spdm_measurement_record_structure.number_of_blocks = 10;
            Some(dummy_spdm_measurement_record_structure)
        } else if measurement_index
            == SpdmMeasurementOperation::SpdmMeasurementRequestAll.get_u8() as usize
        {
            let mut firmware1: [u8; 8] = [0; 8];
            let mut firmware2: [u8; 8] = [0; 8];
            let mut firmware3: [u8; 8] = [0; 8];
            let mut firmware4: [u8; 8] = [0; 8];
            let mut firmware5: [u8; 8] = [0; 8];
            let mut firmware6: [u8; 8] = [0; 8];
            let mut firmware7: [u8; 8] = [0; 8];
            let mut firmware8: [u8; 8] = [0; 8];
            let mut firmware9: [u8; 8] = [0; 8];
            let mut firmware10: [u8; 8] = [0; 8];
            firmware1.copy_from_slice("deadbeef".as_bytes());
            firmware2.copy_from_slice("eadbeefd".as_bytes());
            firmware3.copy_from_slice("adbeefde".as_bytes());
            firmware4.copy_from_slice("dbeefdea".as_bytes());
            firmware5.copy_from_slice("beefdead".as_bytes());
            firmware6.copy_from_slice("deadbeef".as_bytes());
            firmware7.copy_from_slice("eadbeefd".as_bytes());
            firmware8.copy_from_slice("adbeefde".as_bytes());
            firmware9.copy_from_slice("dbeefdea".as_bytes());
            firmware10.copy_from_slice("beefdead".as_bytes());
            let digest1 = hash::hash_all(base_hash_algo, &firmware1).expect("hash_all failed!");
            let digest2 = hash::hash_all(base_hash_algo, &firmware2).expect("hash_all failed!");
            let digest3 = hash::hash_all(base_hash_algo, &firmware3).expect("hash_all failed!");
            let digest4 = hash::hash_all(base_hash_algo, &firmware4).expect("hash_all failed!");
            let digest5 = hash::hash_all(base_hash_algo, &firmware5).expect("hash_all failed!");
            let digest6 = hash::hash_all(base_hash_algo, &firmware6).expect("hash_all failed!");
            let digest7 = hash::hash_all(base_hash_algo, &firmware7).expect("hash_all failed!");
            let digest8 = hash::hash_all(base_hash_algo, &firmware8).expect("hash_all failed!");
            let digest9 = hash::hash_all(base_hash_algo, &firmware9).expect("hash_all failed!");
            let digest10 = hash::hash_all(base_hash_algo, &firmware10).expect("hash_all failed!");
            let mut digest_value1: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value2: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value3: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value4: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value5: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value6: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value7: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value8: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value9: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value10: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            digest_value1[..64].copy_from_slice(digest1.data.as_ref());
            digest_value2[..64].copy_from_slice(digest2.data.as_ref());
            digest_value3[..64].copy_from_slice(digest3.data.as_ref());
            digest_value4[..64].copy_from_slice(digest4.data.as_ref());
            digest_value5[..64].copy_from_slice(digest5.data.as_ref());
            digest_value6[..64].copy_from_slice(digest6.data.as_ref());
            digest_value7[..64].copy_from_slice(digest7.data.as_ref());
            digest_value8[..64].copy_from_slice(digest8.data.as_ref());
            digest_value9[..64].copy_from_slice(digest9.data.as_ref());
            digest_value10[..64].copy_from_slice(digest10.data.as_ref());

            let mut spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
                index: 1u8,
                measurement_specification,
                measurement_size: digest1.data_size + 3,
                measurement: SpdmDmtfMeasurementStructure {
                    r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
                    representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                    value_size: digest1.data_size,
                    value: digest_value1,
                },
            };

            let mut measurement_record_data = [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE];
            let mut writer = Writer::init(&mut measurement_record_data);
            for i in 0..10 {
                spdm_measurement_block_structure.encode(&mut writer).ok()?;
                spdm_measurement_block_structure.index += 1;
            }

            Some(SpdmMeasurementRecordStructure {
                number_of_blocks: 10,
                measurement_record_length: u24::new(writer.used() as u32),
                measurement_record_data,
            })
        } else if measurement_index > 10 {
            None
        } else {
            let mut firmware: [u8; 8] = [0; 8];
            firmware.copy_from_slice("deadbeef".as_bytes());

            let digest = hash::hash_all(base_hash_algo, &firmware)?;

            let mut digest_value: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            digest_value[(measurement_index) * SPDM_MAX_HASH_SIZE
                ..(measurement_index + 1) * SPDM_MAX_HASH_SIZE]
                .copy_from_slice(digest.data.as_ref());

            let spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
                index: measurement_index as u8,
                measurement_specification,
                measurement_size: digest.data_size + 3,
                measurement: SpdmDmtfMeasurementStructure {
                    r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
                    representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                    value_size: digest.data_size,
                    value: digest_value,
                },
            };

            let mut measurement_record_data = [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE];
            let mut writer = Writer::init(&mut measurement_record_data);
            spdm_measurement_block_structure.encode(&mut writer).ok()?;

            Some(SpdmMeasurementRecordStructure {
                number_of_blocks: 1,
                measurement_record_length: u24::new(writer.used() as u32),
                measurement_record_data,
            })
        }
    }
}

fn generate_measurement_summary_hash_impl(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmMeasurementHashAlgo,
    measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
) -> Option<SpdmDigestStruct> {
    match measurement_summary_hash_type {
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll => {
            let mut dummyall: [u8; 8] = [0; 8];
            dummyall.copy_from_slice("dummyall".as_bytes());
            let digest = hash::hash_all(base_hash_algo, &dummyall)?;
            Some(digest)
        }
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb => {
            let mut dummytcb: [u8; 8] = [0; 8];
            dummytcb.copy_from_slice("dummytcb".as_bytes());
            let digest = hash::hash_all(base_hash_algo, &dummytcb)?;
            Some(digest)
        }
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone => None,
        _ => None,
    }
}

const MAX_BIN_CONCAT_BUF_SIZE: usize = 2 + 8 + 12 + SPDM_MAX_HASH_SIZE;
const SALT_0: [u8; SPDM_MAX_HASH_SIZE] = [0u8; SPDM_MAX_HASH_SIZE];
const ZERO_FILLED: [u8; SPDM_MAX_HASH_SIZE] = [0u8; SPDM_MAX_HASH_SIZE];
const BIN_STR0_LABEL: &[u8] = b"derived";

fn handshake_secret_hkdf_expand_impl(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &SpdmPskHintStruct,
    info: &[u8],
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    let mut psk_key: SpdmDheFinalKeyStruct = SpdmDheFinalKeyStruct {
        data_size: b"TestPskData\0".len() as u16,
        data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
    };
    psk_key.data[0..(psk_key.data_size as usize)].copy_from_slice(b"TestPskData\0");

    let hs_sec = crypto::hkdf::hkdf_extract(
        base_hash_algo,
        &SALT_0[0..base_hash_algo.get_size() as usize],
        &SpdmHkdfInputKeyingMaterial::SpdmDheFinalKey(&psk_key),
    )?;
    crypto::hkdf::hkdf_expand(base_hash_algo, &hs_sec, info, base_hash_algo.get_size())
}

fn master_secret_hkdf_expand_impl(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &SpdmPskHintStruct,
    info: &[u8],
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    let mut psk_key: SpdmDheFinalKeyStruct = SpdmDheFinalKeyStruct {
        data_size: b"TestPskData\0".len() as u16,
        data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
    };
    psk_key.data[0..(psk_key.data_size as usize)].copy_from_slice(b"TestPskData\0");

    let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
    let bin_str0 = SpdmKeySchedule::binconcat(
        &SpdmKeySchedule,
        base_hash_algo.get_size(),
        spdm_version,
        BIN_STR0_LABEL,
        None,
        buffer,
    )?;

    let hs_sec = crypto::hkdf::hkdf_extract(
        base_hash_algo,
        &SALT_0[0..base_hash_algo.get_size() as usize],
        &SpdmHkdfInputKeyingMaterial::SpdmDheFinalKey(&psk_key),
    )?;
    let salt_1 =
        crypto::hkdf::hkdf_expand(base_hash_algo, &hs_sec, bin_str0, base_hash_algo.get_size())?;

    let mst_sec = crypto::hkdf::hkdf_extract(
        base_hash_algo,
        salt_1.as_ref(),
        &SpdmHkdfInputKeyingMaterial::SpdmZeroFilled(&SpdmZeroFilledStruct {
            data_size: base_hash_algo.get_size(),
            data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
        }),
    )?;
    crypto::hkdf::hkdf_expand(base_hash_algo, &mst_sec, info, base_hash_algo.get_size())
}

#[cfg(test)]
mod tests {
    use super::SECRET_MEASUREMENT_IMPL_INSTANCE;
    use codec::Codec;
    use spdmlib::protocol::{
        SpdmBaseHashAlgo, SpdmMeasurementBlockStructure, SpdmMeasurementSpecification, SpdmVersion,
    };

    #[test]
    fn test_case0_measurement_collection() {
        let reg_result = register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
        assert_eq!(reg_result, true);

        let records = measurement_collection(
            SpdmVersion::SpdmVersion11,
            SpdmMeasurementSpecification::DMTF,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
            1,
        );
        let deadbeefsha512 = [
            17, 58, 59, 199, 131, 216, 81, 252, 3, 115, 33, 75, 25, 234, 123, 233, 250, 61, 229,
            65, 236, 185, 254, 2, 109, 82, 198, 3, 232, 234, 25, 193, 116, 204, 14, 151, 5, 248,
            185, 13, 49, 34, 18, 192, 195, 166, 216, 69, 61, 223, 179, 227, 20, 20, 9, 207, 75,
            237, 200, 239, 3, 53, 144, 180,
        ];

        match records {
            Some(v) => {
                let spdm_measurement_block_structure =
                    SpdmMeasurementBlockStructure::read_bytes(&v.measurement_record_data).unwrap();
                assert_eq!(
                    deadbeefsha512,
                    &spdm_measurement_block_structure.measurement.value[0..SHA512_DIGEST_SIZE]
                );
            }
            None => {
                assert!(false)
            }
        }
    }
}
