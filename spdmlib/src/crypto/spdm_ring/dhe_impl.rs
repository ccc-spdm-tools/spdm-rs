// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::bytes_mut_scrubbed::BytesMutStrubbed;
use crate::crypto::{SpdmDhe, SpdmDheKeyExchange};
use crate::protocol::{SpdmDheAlgo, SpdmDheExchangeStruct, SpdmSharedSecretFinalKeyStruct};
use bytes::{BufMut, BytesMut};

pub static DEFAULT: SpdmDhe = SpdmDhe {
    generate_key_pair_cb: generate_key_pair,
    import_private_key_cb: Some(import_private_key),
};

fn generate_key_pair(
    dhe_algo: SpdmDheAlgo,
) -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
    match dhe_algo {
        SpdmDheAlgo::SECP_256_R1 => SpdmDheKeyExchangeP256::generate_key_pair(),
        SpdmDheAlgo::SECP_384_R1 => SpdmDheKeyExchangeP384::generate_key_pair(),
        _ => None,
    }
}

fn import_private_key(
    dhe_algo: SpdmDheAlgo,
    private_key_data: &[u8],
) -> Option<Box<dyn SpdmDheKeyExchange + Send>> {
    match dhe_algo {
        SpdmDheAlgo::SECP_256_R1 => {
            let key = SpdmDheKeyExchangeP256::from_private_key_bytes(private_key_data)?;
            Some(Box::new(key))
        }
        SpdmDheAlgo::SECP_384_R1 => {
            let key = SpdmDheKeyExchangeP384::from_private_key_bytes(private_key_data)?;
            Some(Box::new(key))
        }
        _ => None,
    }
}

struct SpdmDheKeyExchangeP256 {
    private_key: ring::agreement::EphemeralPrivateKey,
    private_key_bytes: alloc::vec::Vec<u8>, // For serialization
}

impl SpdmDheKeyExchange for SpdmDheKeyExchangeP256 {
    fn compute_final_key(
        self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmSharedSecretFinalKeyStruct> {
        let mut pubkey = BytesMutStrubbed::new();
        pubkey.put_u8(0x4u8);
        pubkey.extend_from_slice(peer_pub_key.as_ref());

        let peer_public_key =
            ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P256, pubkey.as_ref());
        let mut final_key = BytesMutStrubbed::new();
        let agree_ephemeral_result =
            ring::agreement::agree_ephemeral(self.private_key, &peer_public_key, |key_material| {
                final_key.extend_from_slice(key_material);
            });
        match agree_ephemeral_result {
            Ok(()) => Some(SpdmSharedSecretFinalKeyStruct::from(final_key)),
            Err(_) => None,
        }
    }

    fn export_private_key(&self) -> Option<alloc::vec::Vec<u8>> {
        Some(self.private_key_bytes.clone())
    }
}

impl SpdmDheKeyExchangeP256 {
    fn generate_key_pair() -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
        let rng = ring::rand::SystemRandom::new();
        let private_key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
                .ok()?;

        // Store private key bytes for serialization
        let private_key_bytes = private_key.export_private_key_bytes().to_vec();

        let public_key_old = private_key.compute_public_key().ok()?;
        let public_key = BytesMut::from(&public_key_old.as_ref()[1..]);

        let res: Box<dyn SpdmDheKeyExchange + Send> = Box::new(Self {
            private_key,
            private_key_bytes,
        });

        Some((SpdmDheExchangeStruct::from(public_key), res))
    }

    fn from_private_key_bytes(private_key_bytes: &[u8]) -> Option<Self> {
        if private_key_bytes.len() != 32 {
            return None;
        }
        let private_key = ring::agreement::EphemeralPrivateKey::from_private_key_bytes(
            &ring::agreement::ECDH_P256,
            private_key_bytes,
        )
        .ok()?;
        Some(Self {
            private_key,
            private_key_bytes: private_key_bytes.to_vec(),
        })
    }
}

struct SpdmDheKeyExchangeP384 {
    private_key: ring::agreement::EphemeralPrivateKey,
    private_key_bytes: alloc::vec::Vec<u8>, // For serialization
}

impl SpdmDheKeyExchange for SpdmDheKeyExchangeP384 {
    fn compute_final_key(
        self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmSharedSecretFinalKeyStruct> {
        let mut pubkey = BytesMut::new();
        pubkey.put_u8(0x4u8);
        pubkey.extend_from_slice(peer_pub_key.as_ref());

        let peer_public_key =
            ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P384, pubkey.as_ref());
        let mut final_key = BytesMutStrubbed::new();
        let agree_ephemeral_result =
            ring::agreement::agree_ephemeral(self.private_key, &peer_public_key, |key_material| {
                final_key.extend_from_slice(key_material);
            });
        match agree_ephemeral_result {
            Ok(()) => Some(SpdmSharedSecretFinalKeyStruct::from(final_key)),
            Err(_) => None,
        }
    }

    fn export_private_key(&self) -> Option<alloc::vec::Vec<u8>> {
        Some(self.private_key_bytes.clone())
    }
}

impl SpdmDheKeyExchangeP384 {
    fn generate_key_pair() -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
        let rng = ring::rand::SystemRandom::new();
        let private_key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P384, &rng)
                .ok()?;

        // Store private key bytes for serialization
        let private_key_bytes = private_key.export_private_key_bytes().to_vec();

        let public_key_old = private_key.compute_public_key().ok()?;
        let public_key = BytesMut::from(&public_key_old.as_ref()[1..]);

        let res: Box<dyn SpdmDheKeyExchange + Send> = Box::new(Self {
            private_key,
            private_key_bytes,
        });

        Some((SpdmDheExchangeStruct::from(public_key), res))
    }

    fn from_private_key_bytes(private_key_bytes: &[u8]) -> Option<Self> {
        if private_key_bytes.len() != 48 {
            return None;
        }
        let private_key = ring::agreement::EphemeralPrivateKey::from_private_key_bytes(
            &ring::agreement::ECDH_P384,
            private_key_bytes,
        )
        .ok()?;
        Some(Self {
            private_key,
            private_key_bytes: private_key_bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_case0_dhe() {
        for dhe_algo in [SpdmDheAlgo::SECP_256_R1, SpdmDheAlgo::SECP_384_R1].iter() {
            let (exchange1, private1) = generate_key_pair(*dhe_algo).unwrap();
            let (exchange2, private2) = generate_key_pair(*dhe_algo).unwrap();

            let peer1 = private1.compute_final_key(&exchange2).unwrap();
            let peer2 = private2.compute_final_key(&exchange1).unwrap();

            assert_eq!(peer1.as_ref(), peer2.as_ref());
        }
    }
    #[test]
    fn test_case1_dhe() {
        for dhe_algo in [SpdmDheAlgo::empty()].iter() {
            assert_eq!(generate_key_pair(*dhe_algo).is_none(), true);
        }
    }

    #[test]
    fn test_serialize_deserialize_p256() {
        // Generate a key pair
        let (public_key, private_key_box) = generate_key_pair(SpdmDheAlgo::SECP_256_R1).unwrap();

        // Export the private key
        let private_key_bytes = private_key_box
            .export_private_key()
            .expect("Failed to export private key");

        // Verify the exported key length
        assert_eq!(
            private_key_bytes.len(),
            32,
            "P256 private key should be 32 bytes"
        );

        // Re-import the private key
        let restored_private_key = import_private_key(SpdmDheAlgo::SECP_256_R1, &private_key_bytes)
            .expect("Failed to import private key");

        // Generate a second key pair for testing key agreement
        let (public_key2, private_key2) = generate_key_pair(SpdmDheAlgo::SECP_256_R1).unwrap();

        // Compute shared secrets using original and restored keys
        let shared_secret1 = private_key_box
            .compute_final_key(&public_key2)
            .expect("Failed to compute shared secret with original key");

        let shared_secret2 = restored_private_key
            .compute_final_key(&public_key2)
            .expect("Failed to compute shared secret with restored key");

        // Verify that both keys produce the same shared secret
        assert_eq!(
            shared_secret1.as_ref(),
            shared_secret2.as_ref(),
            "Shared secrets should match after serialization round-trip"
        );

        // Also verify the reverse direction
        let shared_secret3 = private_key2
            .compute_final_key(&public_key)
            .expect("Failed to compute shared secret in reverse");

        assert_eq!(
            shared_secret1.as_ref(),
            shared_secret3.as_ref(),
            "Shared secrets should match in both directions"
        );
    }

    #[test]
    fn test_serialize_deserialize_p384() {
        // Generate a key pair
        let (public_key, private_key_box) = generate_key_pair(SpdmDheAlgo::SECP_384_R1).unwrap();

        // Export the private key
        let private_key_bytes = private_key_box
            .export_private_key()
            .expect("Failed to export private key");

        // Verify the exported key length
        assert_eq!(
            private_key_bytes.len(),
            48,
            "P384 private key should be 48 bytes"
        );

        // Re-import the private key
        let restored_private_key = import_private_key(SpdmDheAlgo::SECP_384_R1, &private_key_bytes)
            .expect("Failed to import private key");

        // Generate a second key pair for testing key agreement
        let (public_key2, private_key2) = generate_key_pair(SpdmDheAlgo::SECP_384_R1).unwrap();

        // Compute shared secrets using original and restored keys
        let shared_secret1 = private_key_box
            .compute_final_key(&public_key2)
            .expect("Failed to compute shared secret with original key");

        let shared_secret2 = restored_private_key
            .compute_final_key(&public_key2)
            .expect("Failed to compute shared secret with restored key");

        // Verify that both keys produce the same shared secret
        assert_eq!(
            shared_secret1.as_ref(),
            shared_secret2.as_ref(),
            "Shared secrets should match after serialization round-trip"
        );

        // Also verify the reverse direction
        let shared_secret3 = private_key2
            .compute_final_key(&public_key)
            .expect("Failed to compute shared secret in reverse");

        assert_eq!(
            shared_secret1.as_ref(),
            shared_secret3.as_ref(),
            "Shared secrets should match in both directions"
        );
    }

    #[test]
    fn test_import_invalid_key_length() {
        // Test P256 with wrong length
        let invalid_bytes_short = vec![0u8; 16];
        assert!(
            import_private_key(SpdmDheAlgo::SECP_256_R1, &invalid_bytes_short).is_none(),
            "Should reject P256 key with invalid length"
        );

        let invalid_bytes_long = vec![0u8; 64];
        assert!(
            import_private_key(SpdmDheAlgo::SECP_256_R1, &invalid_bytes_long).is_none(),
            "Should reject P256 key with invalid length"
        );

        // Test P384 with wrong length
        let invalid_bytes_short = vec![0u8; 32];
        assert!(
            import_private_key(SpdmDheAlgo::SECP_384_R1, &invalid_bytes_short).is_none(),
            "Should reject P384 key with invalid length"
        );

        let invalid_bytes_long = vec![0u8; 96];
        assert!(
            import_private_key(SpdmDheAlgo::SECP_384_R1, &invalid_bytes_long).is_none(),
            "Should reject P384 key with invalid length"
        );
    }

    #[test]
    fn test_multiple_serialization_rounds() {
        // Test that we can serialize and deserialize multiple times
        for dhe_algo in [SpdmDheAlgo::SECP_256_R1, SpdmDheAlgo::SECP_384_R1].iter() {
            let (_public_key, mut private_key_box) =
                generate_key_pair(*dhe_algo).expect("Failed to generate initial key pair");

            // Perform multiple serialization/deserialization rounds
            for round in 0..3 {
                let private_key_bytes = private_key_box
                    .export_private_key()
                    .expect(&alloc::format!("Failed to export key in round {}", round));

                private_key_box = import_private_key(*dhe_algo, &private_key_bytes)
                    .expect(&alloc::format!("Failed to import key in round {}", round));
            }

            // Generate a peer key and verify the final key still works
            let (peer_public_key, _) =
                generate_key_pair(*dhe_algo).expect("Failed to generate peer key");

            let shared_secret = private_key_box
                .compute_final_key(&peer_public_key)
                .expect("Failed to compute shared secret after multiple rounds");

            assert!(
                !shared_secret.as_ref().is_empty(),
                "Shared secret should not be empty after multiple serialization rounds"
            );
        }
    }

    #[test]
    fn test_export_consistency() {
        // Verify that exporting the same key multiple times produces identical bytes
        for dhe_algo in [SpdmDheAlgo::SECP_256_R1, SpdmDheAlgo::SECP_384_R1].iter() {
            let (_public_key, private_key_box) =
                generate_key_pair(*dhe_algo).expect("Failed to generate key pair");

            let export1 = private_key_box
                .export_private_key()
                .expect("First export failed");
            let export2 = private_key_box
                .export_private_key()
                .expect("Second export failed");
            let export3 = private_key_box
                .export_private_key()
                .expect("Third export failed");

            assert_eq!(
                export1, export2,
                "First and second exports should be identical"
            );
            assert_eq!(
                export2, export3,
                "Second and third exports should be identical"
            );
        }
    }
}
