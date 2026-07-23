// Copyright (c) 2025, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use aws_lc_rs::kem::{
    Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024, ML_KEM_512, ML_KEM_768,
};
use spdmlib::crypto::{
    SpdmKemCipherTextExchange, SpdmKemDecap, SpdmKemEncap, SpdmKemEncapKeyExchange,
};
use spdmlib::protocol::{
    SpdmKemAlgo, SpdmKemCipherTextStruct, SpdmKemEncapKeyStruct, SpdmSharedSecretFinalKeyStruct,
    SPDM_MAX_KEM_CIPHER_TEXT_SIZE, SPDM_MAX_KEM_ENCAP_KEY_SIZE, SPDM_MAX_KEM_SHARED_SECRET_SIZE,
};

pub static DEFAULT_DECAP: SpdmKemDecap = SpdmKemDecap {
    generate_key_pair_cb: kem_generate_key_pair,
    import_decap_key_cb: Some(kem_import_decap_key),
};

pub static DEFAULT_ENCAP: SpdmKemEncap = SpdmKemEncap {
    new_key_cb: kem_new_key,
};

struct AwsLcKemDecapKey {
    kem_algo: SpdmKemAlgo,
    decap_key_bytes: Vec<u8>,
}

impl SpdmKemEncapKeyExchange for AwsLcKemDecapKey {
    fn decap_key(
        self: Box<Self>,
        kem_cipher_text: &SpdmKemCipherTextStruct,
    ) -> Option<SpdmSharedSecretFinalKeyStruct> {
        let ct_size = self.kem_algo.get_cipher_text_size() as usize;
        let ct_bytes = &kem_cipher_text.data[..ct_size];

        let shared_secret = match self.kem_algo {
            SpdmKemAlgo::ALG_MLKEM_512 => {
                let dk = DecapsulationKey::new(&ML_KEM_512, &self.decap_key_bytes).ok()?;
                dk.decapsulate(Ciphertext::from(ct_bytes)).ok()?
            }
            SpdmKemAlgo::ALG_MLKEM_768 => {
                let dk = DecapsulationKey::new(&ML_KEM_768, &self.decap_key_bytes).ok()?;
                dk.decapsulate(Ciphertext::from(ct_bytes)).ok()?
            }
            SpdmKemAlgo::ALG_MLKEM_1024 => {
                let dk = DecapsulationKey::new(&ML_KEM_1024, &self.decap_key_bytes).ok()?;
                dk.decapsulate(Ciphertext::from(ct_bytes)).ok()?
            }
            _ => return None,
        };

        let ss_bytes = shared_secret.as_ref();
        let mut result = SpdmSharedSecretFinalKeyStruct::default();
        let len = ss_bytes.len().min(SPDM_MAX_KEM_SHARED_SECRET_SIZE);
        result.data[..len].copy_from_slice(&ss_bytes[..len]);
        result.data_size = len as u16;
        Some(result)
    }

    fn export_decap_key(&self) -> Option<Vec<u8>> {
        // Raw decapsulation (private) key bytes, the same encoding accepted by
        // `kem_import_decap_key` (and by `DecapsulationKey::new`).
        Some(self.decap_key_bytes.clone())
    }
}

struct AwsLcKemEncapKey {
    kem_algo: SpdmKemAlgo,
    encap_key_bytes: Vec<u8>,
}

impl SpdmKemCipherTextExchange for AwsLcKemEncapKey {
    fn encap_key(
        self: Box<Self>,
    ) -> Option<(SpdmKemCipherTextStruct, SpdmSharedSecretFinalKeyStruct)> {
        let (ciphertext, shared_secret) = match self.kem_algo {
            SpdmKemAlgo::ALG_MLKEM_512 => {
                let ek = EncapsulationKey::new(&ML_KEM_512, &self.encap_key_bytes).ok()?;
                ek.encapsulate().ok()?
            }
            SpdmKemAlgo::ALG_MLKEM_768 => {
                let ek = EncapsulationKey::new(&ML_KEM_768, &self.encap_key_bytes).ok()?;
                ek.encapsulate().ok()?
            }
            SpdmKemAlgo::ALG_MLKEM_1024 => {
                let ek = EncapsulationKey::new(&ML_KEM_1024, &self.encap_key_bytes).ok()?;
                ek.encapsulate().ok()?
            }
            _ => return None,
        };

        let ct_bytes = ciphertext.as_ref();
        let mut ct_struct = SpdmKemCipherTextStruct::default();
        let ct_len = ct_bytes.len().min(SPDM_MAX_KEM_CIPHER_TEXT_SIZE);
        ct_struct.data[..ct_len].copy_from_slice(&ct_bytes[..ct_len]);
        ct_struct.data_size = ct_len as u16;

        let ss_bytes = shared_secret.as_ref();
        let mut ss_struct = SpdmSharedSecretFinalKeyStruct::default();
        let ss_len = ss_bytes.len().min(SPDM_MAX_KEM_SHARED_SECRET_SIZE);
        ss_struct.data[..ss_len].copy_from_slice(&ss_bytes[..ss_len]);
        ss_struct.data_size = ss_len as u16;

        Some((ct_struct, ss_struct))
    }
}

fn kem_generate_key_pair(
    kem_algo: SpdmKemAlgo,
) -> Option<(
    SpdmKemEncapKeyStruct,
    Box<dyn SpdmKemEncapKeyExchange + Send>,
)> {
    let (encap_key_bytes, decap_key_bytes) = match kem_algo {
        SpdmKemAlgo::ALG_MLKEM_512 => {
            let dk = DecapsulationKey::generate(&ML_KEM_512).ok()?;
            let ek = dk.encapsulation_key().ok()?;
            let ek_bytes = ek.key_bytes().ok()?;
            let dk_bytes = dk.key_bytes().ok()?;
            (Vec::from(ek_bytes.as_ref()), Vec::from(dk_bytes.as_ref()))
        }
        SpdmKemAlgo::ALG_MLKEM_768 => {
            let dk = DecapsulationKey::generate(&ML_KEM_768).ok()?;
            let ek = dk.encapsulation_key().ok()?;
            let ek_bytes = ek.key_bytes().ok()?;
            let dk_bytes = dk.key_bytes().ok()?;
            (Vec::from(ek_bytes.as_ref()), Vec::from(dk_bytes.as_ref()))
        }
        SpdmKemAlgo::ALG_MLKEM_1024 => {
            let dk = DecapsulationKey::generate(&ML_KEM_1024).ok()?;
            let ek = dk.encapsulation_key().ok()?;
            let ek_bytes = ek.key_bytes().ok()?;
            let dk_bytes = dk.key_bytes().ok()?;
            (Vec::from(ek_bytes.as_ref()), Vec::from(dk_bytes.as_ref()))
        }
        _ => return None,
    };

    let mut ek_struct = SpdmKemEncapKeyStruct::default();
    let ek_len = encap_key_bytes.len().min(SPDM_MAX_KEM_ENCAP_KEY_SIZE);
    ek_struct.data[..ek_len].copy_from_slice(&encap_key_bytes[..ek_len]);
    ek_struct.data_size = ek_len as u16;

    let exchange: Box<dyn SpdmKemEncapKeyExchange + Send> = Box::new(AwsLcKemDecapKey {
        kem_algo,
        decap_key_bytes,
    });

    Some((ek_struct, exchange))
}

fn kem_import_decap_key(
    kem_algo: SpdmKemAlgo,
    decap_key_bytes: &[u8],
) -> Option<Box<dyn SpdmKemEncapKeyExchange + Send>> {
    // Validate that the bytes reconstruct a decapsulation key for this
    // algorithm; defer the actual decapsulation to `decap_key`, which rebuilds
    // the key the same way (matching the DHE import path). This rejects
    // mismatched sizes / wrong algorithms up front.
    match kem_algo {
        SpdmKemAlgo::ALG_MLKEM_512 => {
            DecapsulationKey::new(&ML_KEM_512, decap_key_bytes).ok()?;
        }
        SpdmKemAlgo::ALG_MLKEM_768 => {
            DecapsulationKey::new(&ML_KEM_768, decap_key_bytes).ok()?;
        }
        SpdmKemAlgo::ALG_MLKEM_1024 => {
            DecapsulationKey::new(&ML_KEM_1024, decap_key_bytes).ok()?;
        }
        _ => return None,
    }

    Some(Box::new(AwsLcKemDecapKey {
        kem_algo,
        decap_key_bytes: Vec::from(decap_key_bytes),
    }))
}

fn kem_new_key(
    kem_algo: SpdmKemAlgo,
    kem_encap_key: &SpdmKemEncapKeyStruct,
) -> Option<Box<dyn SpdmKemCipherTextExchange + Send>> {
    let ek_size = kem_algo.get_encap_key_size() as usize;
    let encap_key_bytes = Vec::from(&kem_encap_key.data[..ek_size]);

    Some(Box::new(AwsLcKemEncapKey {
        kem_algo,
        encap_key_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full KEM round-trip: the encapsulator (responder) produces a ciphertext
    /// and shared secret from the encap key; the decapsulator (requester) must
    /// recover the same shared secret from that ciphertext.
    fn roundtrip(kem_algo: SpdmKemAlgo) {
        let (encap_key, decap) = kem_generate_key_pair(kem_algo).unwrap();
        let encap = kem_new_key(kem_algo, &encap_key).unwrap();

        let (ciphertext, secret_encap) = encap.encap_key().unwrap();
        let secret_decap = decap.decap_key(&ciphertext).unwrap();

        assert_eq!(secret_encap.data_size, secret_decap.data_size);
        assert_eq!(
            &secret_encap.data[..secret_encap.data_size as usize],
            &secret_decap.data[..secret_decap.data_size as usize]
        );
    }

    #[test]
    fn test_kem_mlkem512() {
        roundtrip(SpdmKemAlgo::ALG_MLKEM_512);
    }

    #[test]
    fn test_kem_mlkem768() {
        roundtrip(SpdmKemAlgo::ALG_MLKEM_768);
    }

    #[test]
    fn test_kem_mlkem1024() {
        roundtrip(SpdmKemAlgo::ALG_MLKEM_1024);
    }

    /// Exported decapsulation key bytes must re-import and recover the same
    /// shared secret from the same ciphertext — the checkpoint/resume property.
    fn export_import_roundtrip(kem_algo: SpdmKemAlgo) {
        let (encap_key, decap) = kem_generate_key_pair(kem_algo).unwrap();
        let exported = decap.export_decap_key().expect("export supported");

        // Encapsulate against the generated encap key.
        let encap = kem_new_key(kem_algo, &encap_key).unwrap();
        let (ciphertext, secret_encap) = encap.encap_key().unwrap();

        // A freshly imported decap key must decapsulate to the same secret.
        let decap_imported = kem_import_decap_key(kem_algo, &exported).unwrap();
        let secret_imported = decap_imported.decap_key(&ciphertext).unwrap();

        assert_eq!(
            &secret_encap.data[..secret_encap.data_size as usize],
            &secret_imported.data[..secret_imported.data_size as usize],
            "imported decap key must recover the same shared secret"
        );
    }

    #[test]
    fn test_kem_export_import_mlkem512() {
        export_import_roundtrip(SpdmKemAlgo::ALG_MLKEM_512);
    }

    #[test]
    fn test_kem_export_import_mlkem768() {
        export_import_roundtrip(SpdmKemAlgo::ALG_MLKEM_768);
    }

    #[test]
    fn test_kem_export_import_mlkem1024() {
        export_import_roundtrip(SpdmKemAlgo::ALG_MLKEM_1024);
    }

    /// Bad decap-key bytes (wrong length) must be rejected by import.
    #[test]
    fn test_kem_import_rejects_invalid() {
        let invalid = [0u8; 8];
        assert!(kem_import_decap_key(SpdmKemAlgo::ALG_MLKEM_512, &invalid).is_none());
        assert!(kem_import_decap_key(SpdmKemAlgo::ALG_MLKEM_768, &invalid).is_none());
        assert!(kem_import_decap_key(SpdmKemAlgo::ALG_MLKEM_1024, &invalid).is_none());
    }
}
