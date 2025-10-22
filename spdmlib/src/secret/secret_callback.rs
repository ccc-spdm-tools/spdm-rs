// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::{
    common::SpdmContext,
    protocol::{
        SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDigestStruct, SpdmHkdfOutputKeyingMaterial,
        SpdmMeasurementHashAlgo, SpdmMeasurementRecordStructure, SpdmMeasurementSpecification,
        SpdmMeasurementSummaryHashType, SpdmPqcAsymAlgo, SpdmPskHintStruct, SpdmSignatureStruct,
        SpdmVersion,
    },
};

type SpdmMeasurementCollectionCbType = fn(
    spdm_version: SpdmVersion,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmMeasurementHashAlgo,
    measurement_index: usize,
) -> Option<SpdmMeasurementRecordStructure>;

type SpdmGenerateMeasurementSummaryHashCbType = fn(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmMeasurementHashAlgo,
    measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
) -> Option<SpdmDigestStruct>;

type SpdmPskHandshakeSecretHkdfExpandCbType = fn(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &SpdmPskHintStruct,
    info: &[u8],
) -> Option<SpdmHkdfOutputKeyingMaterial>;
type SpdmPskMasterSecretHkdfExpandCbType = fn(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &SpdmPskHintStruct,
    info: &[u8],
) -> Option<SpdmHkdfOutputKeyingMaterial>;

#[derive(Clone)]
pub struct SpdmSecretMeasurement {
    pub measurement_collection_cb: SpdmMeasurementCollectionCbType,

    pub generate_measurement_summary_hash_cb: SpdmGenerateMeasurementSummaryHashCbType,
}

#[derive(Clone)]
pub struct SpdmSecretPsk {
    pub handshake_secret_hkdf_expand_cb: SpdmPskHandshakeSecretHkdfExpandCbType,

    pub master_secret_hkdf_expand_cb: SpdmPskMasterSecretHkdfExpandCbType,
}

#[derive(Clone)]
pub struct SpdmSecretAsymSign {
    pub sign_cb: fn(
        spdm_context: &SpdmContext,
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        data: &[u8],
    ) -> Option<SpdmSignatureStruct>,
}

#[derive(Clone)]
pub struct SpdmSecretPqcAsymSign {
    pub sign_cb: fn(
        spdm_context: &SpdmContext,
        base_hash_algo: SpdmBaseHashAlgo,
        pqc_asym_algo: SpdmPqcAsymAlgo,
        data: &[u8],
    ) -> Option<SpdmSignatureStruct>,
}
