// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
mod secret_callback;

use conquer_once::spin::OnceCell;
pub use secret_callback::{SpdmSecretAsymSign, SpdmSecretMeasurement, SpdmSecretPsk};

static SECRET_MEASUREMENT_INSTANCE: OnceCell<SpdmSecretMeasurement> = OnceCell::uninit();
static SECRET_PSK_INSTANCE: OnceCell<SpdmSecretPsk> = OnceCell::uninit();
static SECRET_ASYM_INSTANCE: OnceCell<SpdmSecretAsymSign> = OnceCell::uninit();

pub mod measurement {
    use super::{SpdmSecretMeasurement, SECRET_MEASUREMENT_INSTANCE};
    use crate::protocol::*;

    pub fn register(context: SpdmSecretMeasurement) -> bool {
        SECRET_MEASUREMENT_INSTANCE
            .try_init_once(|| context)
            .is_ok()
    }

    static UNIMPLETEMTED: SpdmSecretMeasurement = SpdmSecretMeasurement {
        measurement_collection_cb: |_spdm_version: SpdmVersion,
                                    _measurement_specification: SpdmMeasurementSpecification,
                                    _measurement_hash_algo: SpdmMeasurementHashAlgo,
                                    _measurement_index: usize|
         -> Option<SpdmMeasurementRecordStructure> {
            unimplemented!()
        },

        generate_measurement_summary_hash_cb:
            |_spdm_version: SpdmVersion,
             _base_hash_algo: SpdmBaseHashAlgo,
             _measurement_specification: SpdmMeasurementSpecification,
             _measurement_hash_algo: SpdmMeasurementHashAlgo,
             _measurement_summary_hash_type: SpdmMeasurementSummaryHashType|
             -> Option<SpdmDigestStruct> { unimplemented!() },
    };

    /*
        Function to get measurements.

        This function wraps SpdmSecret.measurement_collection_cb callback
        Device security lib is responsible for the implementation of SpdmSecret.
        If SECRET_INSTANCE got no registered, a panic with string "not implemented"
        will be emit.

        @When measurement_index == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
                A dummy Some(SpdmMeasurementRecordStructure) is returned, with its number_of_blocks
                field set and all other field reserved.
        @When measurement_index != SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
                A normal Some(SpdmMeasurementRecordStructure) is returned, with all fields valid.
    */
    pub fn measurement_collection(
        spdm_version: SpdmVersion,
        measurement_specification: SpdmMeasurementSpecification,
        measurement_hash_algo: SpdmMeasurementHashAlgo,
        measurement_index: usize,
    ) -> Option<SpdmMeasurementRecordStructure> {
        (SECRET_MEASUREMENT_INSTANCE
            .try_get_or_init(|| UNIMPLETEMTED.clone())
            .ok()?
            .measurement_collection_cb)(
            spdm_version,
            measurement_specification,
            measurement_hash_algo,
            measurement_index,
        )
    }
    pub fn generate_measurement_summary_hash(
        spdm_version: SpdmVersion,
        base_hash_algo: SpdmBaseHashAlgo,
        measurement_specification: SpdmMeasurementSpecification,
        measurement_hash_algo: SpdmMeasurementHashAlgo,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> Option<SpdmDigestStruct> {
        (SECRET_MEASUREMENT_INSTANCE
            .try_get_or_init(|| UNIMPLETEMTED.clone())
            .ok()?
            .generate_measurement_summary_hash_cb)(
            spdm_version,
            base_hash_algo,
            measurement_specification,
            measurement_hash_algo,
            measurement_summary_hash_type,
        )
    }
}
pub mod psk {
    use super::{SpdmSecretPsk, SECRET_PSK_INSTANCE};
    use crate::protocol::*;
    pub fn register(context: SpdmSecretPsk) -> bool {
        SECRET_PSK_INSTANCE.try_init_once(|| context).is_ok()
    }

    static UNIMPLETEMTED: SpdmSecretPsk = SpdmSecretPsk {
        handshake_secret_hkdf_expand_cb: |_spdm_version: SpdmVersion,
                                          _base_hash_algo: SpdmBaseHashAlgo,
                                          _psk_hint: &SpdmPskHintStruct,
                                          _info: &[u8]|
         -> Option<SpdmHkdfOutputKeyingMaterial> {
            unimplemented!()
        },

        master_secret_hkdf_expand_cb: |_spdm_version: SpdmVersion,
                                       _base_hash_algo: SpdmBaseHashAlgo,
                                       _psk_hint: &SpdmPskHintStruct,
                                       _info: &[u8]|
         -> Option<SpdmHkdfOutputKeyingMaterial> {
            unimplemented!()
        },
    };

    pub fn handshake_secret_hkdf_expand(
        spdm_version: SpdmVersion,
        base_hash_algo: SpdmBaseHashAlgo,
        psk_hint: &SpdmPskHintStruct,
        info: &[u8],
    ) -> Option<SpdmHkdfOutputKeyingMaterial> {
        (SECRET_PSK_INSTANCE
            .try_get_or_init(|| UNIMPLETEMTED.clone())
            .ok()?
            .handshake_secret_hkdf_expand_cb)(spdm_version, base_hash_algo, psk_hint, info)
    }

    pub fn master_secret_hkdf_expand(
        spdm_version: SpdmVersion,
        base_hash_algo: SpdmBaseHashAlgo,
        psk_hint: &SpdmPskHintStruct,
        info: &[u8],
    ) -> Option<SpdmHkdfOutputKeyingMaterial> {
        (SECRET_PSK_INSTANCE
            .try_get_or_init(|| UNIMPLETEMTED.clone())
            .ok()?
            .master_secret_hkdf_expand_cb)(spdm_version, base_hash_algo, psk_hint, info)
    }
}

pub mod asym_sign {
    use super::SECRET_ASYM_INSTANCE;
    use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};
    use crate::secret::SpdmSecretAsymSign;

    pub fn register(context: SpdmSecretAsymSign) -> bool {
        SECRET_ASYM_INSTANCE.try_init_once(|| context).is_ok()
    }

    static DEFAULT: SpdmSecretAsymSign = SpdmSecretAsymSign {
        sign_cb: |_base_hash_algo: SpdmBaseHashAlgo,
                  _base_asym_algo: SpdmBaseAsymAlgo,
                  _data: &[u8]|
         -> Option<SpdmSignatureStruct> { unimplemented!() },
    };

    pub fn sign(
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        data: &[u8],
    ) -> Option<SpdmSignatureStruct> {
        (SECRET_ASYM_INSTANCE
            .try_get_or_init(|| DEFAULT.clone())
            .ok()?
            .sign_cb)(base_hash_algo, base_asym_algo, data)
    }
}
