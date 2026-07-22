// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! ECDHE (P-256, P-384) via aws-lc-rs, for the standalone aws-lc backend.
//!
//! Uses aws-lc-rs's non-ephemeral `agreement::PrivateKey`, which (unlike
//! `EphemeralPrivateKey`) can export its raw big-endian private scalar and be
//! re-imported from it. This gives the same checkpoint/resume support as the
//! ring backend: `export_private_key` returns the raw scalar and
//! `import_private_key_cb` reconstructs the key from it.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
use spdmlib::crypto::{SpdmDhe, SpdmDheKeyExchange};
use spdmlib::protocol::{SpdmDheAlgo, SpdmDheExchangeStruct, SpdmSharedSecretFinalKeyStruct};

pub static DEFAULT: SpdmDhe = SpdmDhe {
    generate_key_pair_cb: generate_key_pair,
    import_private_key_cb: Some(import_private_key),
};

fn algo_of(dhe_algo: SpdmDheAlgo) -> Option<&'static agreement::Algorithm> {
    match dhe_algo {
        SpdmDheAlgo::SECP_256_R1 => Some(&agreement::ECDH_P256),
        SpdmDheAlgo::SECP_384_R1 => Some(&agreement::ECDH_P384),
        _ => None,
    }
}

fn generate_key_pair(
    dhe_algo: SpdmDheAlgo,
) -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
    let alg = algo_of(dhe_algo)?;
    let private_key = PrivateKey::generate(alg).ok()?;
    exchange_from_private_key(alg, private_key)
}

fn import_private_key(
    dhe_algo: SpdmDheAlgo,
    private_key_bytes: &[u8],
) -> Option<Box<dyn SpdmDheKeyExchange + Send>> {
    let alg = algo_of(dhe_algo)?;
    // Raw big-endian fixed-length scalar, same encoding produced by
    // `export_private_key` below (and by the ring backend).
    let private_key = PrivateKey::from_private_key(alg, private_key_bytes).ok()?;
    let (_pub, exchange) = exchange_from_private_key(alg, private_key)?;
    Some(exchange)
}

/// Build the SPDM exchange struct (raw X||Y public point) and the key-exchange
/// object from a private key.
fn exchange_from_private_key(
    alg: &'static agreement::Algorithm,
    private_key: PrivateKey,
) -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
    let public_key = private_key.compute_public_key().ok()?;
    // SPDM carries the raw X||Y (strip the leading 0x04 uncompressed-point tag).
    let public_key_xy = public_key.as_ref()[1..].to_vec();

    let exchange: Box<dyn SpdmDheKeyExchange + Send> = Box::new(SpdmDheKeyExchangeAwsLc {
        alg,
        private_key: Some(private_key),
    });
    let exch_struct = SpdmDheExchangeStruct::from(bytes::BytesMut::from(&public_key_xy[..]));
    Some((exch_struct, exchange))
}

struct SpdmDheKeyExchangeAwsLc {
    alg: &'static agreement::Algorithm,
    private_key: Option<PrivateKey>,
}

impl SpdmDheKeyExchange for SpdmDheKeyExchangeAwsLc {
    fn compute_final_key(
        mut self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmSharedSecretFinalKeyStruct> {
        let private_key = self.private_key.take()?;

        // Reconstruct the uncompressed point: 0x04 || X || Y.
        let mut pubkey = Vec::with_capacity(1 + peer_pub_key.data_size as usize);
        pubkey.push(0x04u8);
        pubkey.extend_from_slice(&peer_pub_key.data[..peer_pub_key.data_size as usize]);
        let peer_public_key = UnparsedPublicKey::new(self.alg, pubkey);

        let mut final_key: Vec<u8> = Vec::new();
        let res = agreement::agree(
            &private_key,
            &peer_public_key,
            aws_lc_rs::error::Unspecified,
            |key_material| {
                final_key.extend_from_slice(key_material);
                Ok(())
            },
        );
        match res {
            Ok(()) => Some(SpdmSharedSecretFinalKeyStruct::from(final_key.as_slice())),
            Err(_) => None,
        }
    }

    fn export_private_key(&self) -> Option<Vec<u8>> {
        let private_key = self.private_key.as_ref()?;
        let bin: EcPrivateKeyBin = private_key.as_be_bytes().ok()?;
        Some(bin.as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(dhe_algo: SpdmDheAlgo) {
        // Two parties generate key pairs and must agree on the same secret.
        let (a_pub, a_ex) = generate_key_pair(dhe_algo).unwrap();
        let (b_pub, b_ex) = generate_key_pair(dhe_algo).unwrap();
        let a_secret = a_ex.compute_final_key(&b_pub).unwrap();
        let b_secret = b_ex.compute_final_key(&a_pub).unwrap();
        assert_eq!(a_secret.data_size, b_secret.data_size);
        assert_eq!(
            &a_secret.data[..a_secret.data_size as usize],
            &b_secret.data[..b_secret.data_size as usize]
        );
    }

    #[test]
    fn test_dhe_p256() {
        roundtrip(SpdmDheAlgo::SECP_256_R1);
    }

    #[test]
    fn test_dhe_p384() {
        roundtrip(SpdmDheAlgo::SECP_384_R1);
    }

    /// Exported private key bytes must re-import and reproduce the same agreed
    /// secret — the checkpoint/resume property.
    fn export_import_roundtrip(dhe_algo: SpdmDheAlgo) {
        let (_a_pub, a_ex) = generate_key_pair(dhe_algo).unwrap();
        let exported = a_ex.export_private_key().expect("export supported");

        // Original A and re-imported A agree with the same peer B; because the
        // imported key is byte-identical, both must yield the same secret.
        let a_imported = import_private_key(dhe_algo, &exported).unwrap();
        let (b_pub, _b_ex) = generate_key_pair(dhe_algo).unwrap();

        let secret_orig = a_ex.compute_final_key(&b_pub).unwrap();
        let secret_imported = a_imported.compute_final_key(&b_pub).unwrap();

        assert_eq!(
            &secret_orig.data[..secret_orig.data_size as usize],
            &secret_imported.data[..secret_imported.data_size as usize],
            "imported key must reproduce the same shared secret"
        );
    }

    #[test]
    fn test_dhe_export_import_p256() {
        export_import_roundtrip(SpdmDheAlgo::SECP_256_R1);
    }

    #[test]
    fn test_dhe_export_import_p384() {
        export_import_roundtrip(SpdmDheAlgo::SECP_384_R1);
    }
}
