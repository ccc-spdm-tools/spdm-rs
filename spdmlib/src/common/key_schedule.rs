// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto;
use crate::protocol::*;
use codec::{Codec, Writer};
extern crate alloc;
use crate::secret;
use alloc::boxed::Box;

const MAX_BIN_CONCAT_BUF_SIZE: usize = 2 + 8 + 12 + SPDM_MAX_HASH_SIZE;
const SALT_0: [u8; SPDM_MAX_HASH_SIZE] = [0u8; SPDM_MAX_HASH_SIZE];
const BIN_STR0_LABEL: &[u8] = b"derived";
const BIN_STR1_LABEL: &[u8] = b"req hs data";
const BIN_STR2_LABEL: &[u8] = b"rsp hs data";
const BIN_STR3_LABEL: &[u8] = b"req app data";
const BIN_STR4_LABEL: &[u8] = b"rsp app data";
const BIN_STR5_LABEL: &[u8] = b"key";
const BIN_STR6_LABEL: &[u8] = b"iv";
const BIN_STR7_LABEL: &[u8] = b"finished";
const BIN_STR8_LABEL: &[u8] = b"exp master";
const BIN_STR9_LABEL: &[u8] = b"traffic upd";
const SPDM_VERSION_VALUE: &[u8; 8] = b"spdm .  ";
const SPDM_VERSION_VALUE_MAJOR_INDEX: usize = 4;
const SPDM_VERSION_VALUE_MINOR_INDEX: usize = 6;

#[derive(Clone, Debug)]
pub struct SpdmKeySchedule;

impl Default for SpdmKeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

impl SpdmKeySchedule {
    pub fn new() -> Self {
        SpdmKeySchedule {}
    }

    pub fn derive_handshake_secret(
        &self,
        _spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: &SpdmDheFinalKeyStruct,
    ) -> Option<SpdmHandshakeSecretStruct> {
        let prk = crypto::hkdf::hkdf_extract(
            hash_algo,
            &SALT_0[0..hash_algo.get_size() as usize],
            &SpdmHkdfInputKeyingMaterial::SpdmDheFinalKey(key),
        )?;
        SpdmHandshakeSecretStruct::from_spdm_hkdf_prk(prk)
    }

    pub fn derive_master_secret(
        &self,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: &SpdmHandshakeSecretStruct,
    ) -> Option<SpdmMasterSecretStruct> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str0 = self.binconcat(
            hash_algo.get_size(),
            spdm_version,
            BIN_STR0_LABEL,
            None,
            buffer,
        )?;
        let salt_1 = crypto::hkdf::hkdf_expand(
            hash_algo,
            &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                &SpdmHkdfInputKeyingMaterial::SpdmHandshakeSecret(key),
            )?,
            bin_str0,
            hash_algo.get_size(),
        )?;
        debug!("salt_1 - {:02x?}", salt_1.as_ref());

        let prk = crypto::hkdf::hkdf_extract(
            hash_algo,
            salt_1.as_ref(),
            &SpdmHkdfInputKeyingMaterial::SpdmZeroFilled(&SpdmZeroFilledStruct {
                data_size: hash_algo.get_size(),
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            }),
        )?;

        SpdmMasterSecretStruct::from_spdm_hkdf_prk(prk)
    }

    pub fn derive_request_handshake_secret(
        &self,
        use_psk: bool,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: Option<&SpdmHandshakeSecretStruct>,
        psk_hint: Option<&SpdmPskHintStruct>,
        th1: &[u8],
    ) -> Option<SpdmDirectionHandshakeSecretStruct> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str1 = self.binconcat(
            hash_algo.get_size(),
            spdm_version,
            BIN_STR1_LABEL,
            Some(th1),
            buffer,
        )?;
        let okm = if !use_psk {
            if let Some(k) = key {
                crypto::hkdf::hkdf_expand(
                    hash_algo,
                    &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                        &SpdmHkdfInputKeyingMaterial::SpdmHandshakeSecret(k),
                    )?,
                    bin_str1,
                    hash_algo.get_size(),
                )?
            } else {
                return None;
            }
        } else {
            secret::psk::handshake_secret_hkdf_expand(
                spdm_version,
                hash_algo,
                psk_hint.unwrap(),
                bin_str1,
            )?
        };

        SpdmDirectionHandshakeSecretStruct::from_spdm_hkdf_okm(okm)
    }

    pub fn derive_response_handshake_secret(
        &self,
        use_psk: bool,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: Option<&SpdmHandshakeSecretStruct>,
        psk_hint: Option<&SpdmPskHintStruct>,
        th1: &[u8],
    ) -> Option<SpdmDirectionHandshakeSecretStruct> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str2 = self.binconcat(
            hash_algo.get_size(),
            spdm_version,
            BIN_STR2_LABEL,
            Some(th1),
            buffer,
        )?;
        let okm = if !use_psk {
            if let Some(k) = key {
                crypto::hkdf::hkdf_expand(
                    hash_algo,
                    &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                        &SpdmHkdfInputKeyingMaterial::SpdmHandshakeSecret(k),
                    )?,
                    bin_str2,
                    hash_algo.get_size(),
                )?
            } else {
                return None;
            }
        } else {
            secret::psk::handshake_secret_hkdf_expand(
                spdm_version,
                hash_algo,
                psk_hint.unwrap(),
                bin_str2,
            )?
        };

        SpdmDirectionHandshakeSecretStruct::from_spdm_hkdf_okm(okm)
    }

    pub fn derive_finished_key(
        &self,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: &SpdmDirectionHandshakeSecretStruct,
    ) -> Option<SpdmFinishedKeyStruct> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str7 = self.binconcat(
            hash_algo.get_size(),
            spdm_version,
            BIN_STR7_LABEL,
            None,
            buffer,
        )?;
        let okm = crypto::hkdf::hkdf_expand(
            hash_algo,
            &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                &SpdmHkdfInputKeyingMaterial::SpdmDirectionHandshakeSecret(key),
            )?,
            bin_str7,
            hash_algo.get_size(),
        )?;

        SpdmFinishedKeyStruct::from_spdm_hkdf_okm(okm)
    }

    pub fn derive_aead_key_iv(
        &self,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        aead_algo: SpdmAeadAlgo,
        key: &SpdmMajorSecret,
    ) -> Option<(SpdmAeadKeyStruct, SpdmAeadIvStruct)> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str5 = self.binconcat(
            aead_algo.get_key_size(),
            spdm_version,
            BIN_STR5_LABEL,
            None,
            buffer,
        )?;
        let okm = match key {
            SpdmMajorSecret::SpdmDirectionHandshakeSecret(k) => crypto::hkdf::hkdf_expand(
                hash_algo,
                &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                    &SpdmHkdfInputKeyingMaterial::SpdmDirectionHandshakeSecret(k),
                )?,
                bin_str5,
                SPDM_MAX_AEAD_KEY_SIZE as u16,
            )?,
            SpdmMajorSecret::SpdmDirectionDataSecret(k) => crypto::hkdf::hkdf_expand(
                hash_algo,
                &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                    &SpdmHkdfInputKeyingMaterial::SpdmDirectionDataSecret(k),
                )?,
                bin_str5,
                SPDM_MAX_AEAD_KEY_SIZE as u16,
            )?,
        };
        let encrypt_key = SpdmAeadKeyStruct::from_spdm_hkdf_okm(okm)?;

        let bin_str6 = self.binconcat(
            aead_algo.get_iv_size(),
            spdm_version,
            BIN_STR6_LABEL,
            None,
            buffer,
        )?;
        let okm = match key {
            SpdmMajorSecret::SpdmDirectionHandshakeSecret(k) => crypto::hkdf::hkdf_expand(
                hash_algo,
                &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                    &SpdmHkdfInputKeyingMaterial::SpdmDirectionHandshakeSecret(k),
                )?,
                bin_str6,
                SPDM_MAX_AEAD_IV_SIZE as u16,
            )?,
            SpdmMajorSecret::SpdmDirectionDataSecret(k) => crypto::hkdf::hkdf_expand(
                hash_algo,
                &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                    &SpdmHkdfInputKeyingMaterial::SpdmDirectionDataSecret(k),
                )?,
                bin_str6,
                SPDM_MAX_AEAD_IV_SIZE as u16,
            )?,
        };
        let iv = SpdmAeadIvStruct::from_spdm_hkdf_okm(okm)?;

        Some((encrypt_key, iv))
    }

    pub fn derive_request_data_secret(
        &self,
        use_psk: bool,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: Option<&SpdmMasterSecretStruct>,
        psk_hint: Option<&SpdmPskHintStruct>,
        th2: &[u8],
    ) -> Option<SpdmDirectionDataSecretStruct> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str3 = self.binconcat(
            hash_algo.get_size(),
            spdm_version,
            BIN_STR3_LABEL,
            Some(th2),
            buffer,
        )?;
        let okm = if !use_psk {
            if let Some(k) = key {
                crypto::hkdf::hkdf_expand(
                    hash_algo,
                    &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                        &SpdmHkdfInputKeyingMaterial::SpdmMasterSecret(k),
                    )?,
                    bin_str3,
                    hash_algo.get_size(),
                )?
            } else {
                return None;
            }
        } else {
            secret::psk::master_secret_hkdf_expand(
                spdm_version,
                hash_algo,
                psk_hint.unwrap(),
                bin_str3,
            )?
        };

        SpdmDirectionDataSecretStruct::from_spdm_hkdf_okm(okm)
    }

    pub fn derive_response_data_secret(
        &self,
        use_psk: bool,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: Option<&SpdmMasterSecretStruct>,
        psk_hint: Option<&SpdmPskHintStruct>,
        th2: &[u8],
    ) -> Option<SpdmDirectionDataSecretStruct> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str4 = self.binconcat(
            hash_algo.get_size(),
            spdm_version,
            BIN_STR4_LABEL,
            Some(th2),
            buffer,
        )?;
        let okm = if !use_psk {
            if let Some(k) = key {
                crypto::hkdf::hkdf_expand(
                    hash_algo,
                    &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                        &SpdmHkdfInputKeyingMaterial::SpdmMasterSecret(k),
                    )?,
                    bin_str4,
                    hash_algo.get_size(),
                )?
            } else {
                return None;
            }
        } else {
            secret::psk::master_secret_hkdf_expand(
                spdm_version,
                hash_algo,
                psk_hint.unwrap(),
                bin_str4,
            )?
        };

        SpdmDirectionDataSecretStruct::from_spdm_hkdf_okm(okm)
    }

    pub fn derive_export_master_secret(
        &self,
        use_psk: bool,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: Option<&SpdmMasterSecretStruct>,
        psk_hint: Option<&SpdmPskHintStruct>,
    ) -> Option<SpdmExportMasterSecretStruct> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str8 = self.binconcat(
            hash_algo.get_size(),
            spdm_version,
            BIN_STR8_LABEL,
            None,
            buffer,
        )?;
        let okm = if !use_psk {
            if let Some(k) = key {
                crypto::hkdf::hkdf_expand(
                    hash_algo,
                    &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                        &SpdmHkdfInputKeyingMaterial::SpdmMasterSecret(k),
                    )?,
                    bin_str8,
                    hash_algo.get_size(),
                )?
            } else {
                return None;
            }
        } else {
            secret::psk::master_secret_hkdf_expand(
                spdm_version,
                hash_algo,
                psk_hint.unwrap(),
                bin_str8,
            )?
        };

        SpdmExportMasterSecretStruct::from_spdm_hkdf_okm(okm)
    }

    pub fn derive_update_secret(
        &self,
        spdm_version: SpdmVersion,
        hash_algo: SpdmBaseHashAlgo,
        key: &SpdmDirectionDataSecretStruct,
    ) -> Option<SpdmDirectionDataSecretStruct> {
        let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
        let bin_str9 = self.binconcat(
            hash_algo.get_size(),
            spdm_version,
            BIN_STR9_LABEL,
            None,
            buffer,
        )?;
        let okm = crypto::hkdf::hkdf_expand(
            hash_algo,
            &SpdmHkdfPseudoRandomKey::from_input_keying_material(
                &SpdmHkdfInputKeyingMaterial::SpdmDirectionDataSecret(key),
            )?,
            bin_str9,
            hash_algo.get_size(),
        )?;

        SpdmDirectionDataSecretStruct::from_spdm_hkdf_okm(okm)
    }

    pub fn binconcat<'a>(
        &self,
        length: u16,
        spdm_version: SpdmVersion,
        label: &[u8],
        context: Option<&[u8]>,
        buffer: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let mut len = label.len();
        if let Some(context) = context {
            len += context.len();
        }
        if len > buffer.len() - 2 - 8 {
            return None;
        }

        let mut version = [0u8; 8];
        version.copy_from_slice(SPDM_VERSION_VALUE);
        version[SPDM_VERSION_VALUE_MAJOR_INDEX] = (u8::from(spdm_version) >> 4) + b'0';
        version[SPDM_VERSION_VALUE_MINOR_INDEX] = (u8::from(spdm_version) & 0x0F) + b'0';

        let mut writer = Writer::init(buffer);
        length.encode(&mut writer).ok()?;
        writer.extend_from_slice(&version[..]);
        writer.extend_from_slice(label);
        if let Some(context) = context {
            writer.extend_from_slice(context);
        }

        let len = writer.used();
        Some(&buffer[0..len])
    }
}
