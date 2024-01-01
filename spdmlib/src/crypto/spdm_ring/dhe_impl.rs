// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::bytes_mut_scrubbed::BytesMutStrubbed;
use crate::crypto::{SpdmDhe, SpdmDheKeyExchange};
use crate::protocol::{SpdmDheAlgo, SpdmDheExchangeStruct, SpdmDheFinalKeyStruct};
use bytes::{BufMut, BytesMut};

pub static DEFAULT: SpdmDhe = SpdmDhe {
    generate_key_pair_cb: generate_key_pair,
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

struct SpdmDheKeyExchangeP256(ring::agreement::EphemeralPrivateKey);

impl SpdmDheKeyExchange for SpdmDheKeyExchangeP256 {
    fn compute_final_key(
        self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmDheFinalKeyStruct> {
        let mut pubkey = BytesMutStrubbed::new();
        pubkey.put_u8(0x4u8);
        pubkey.extend_from_slice(peer_pub_key.as_ref());

        let peer_public_key =
            ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P256, pubkey.as_ref());
        let mut final_key = BytesMutStrubbed::new();
        match ring::agreement::agree_ephemeral(self.0, &peer_public_key, |key_material| {
            final_key.extend_from_slice(key_material);
        }) {
            Ok(()) => Some(SpdmDheFinalKeyStruct::from(final_key)),
            Err(_) => None,
        }
    }
}

impl SpdmDheKeyExchangeP256 {
    fn generate_key_pair() -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
        let rng = ring::rand::SystemRandom::new();
        let private_key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
                .ok()?;
        let public_key_old = private_key.compute_public_key().ok()?;
        let public_key = BytesMut::from(&public_key_old.as_ref()[1..]);

        let res: Box<dyn SpdmDheKeyExchange + Send> = Box::new(Self(private_key));

        Some((SpdmDheExchangeStruct::from(public_key), res))
    }
}

struct SpdmDheKeyExchangeP384(ring::agreement::EphemeralPrivateKey);

impl SpdmDheKeyExchange for SpdmDheKeyExchangeP384 {
    fn compute_final_key(
        self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmDheFinalKeyStruct> {
        let mut pubkey = BytesMut::new();
        pubkey.put_u8(0x4u8);
        pubkey.extend_from_slice(peer_pub_key.as_ref());

        let peer_public_key =
            ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P384, pubkey.as_ref());
        let mut final_key = BytesMutStrubbed::new();
        match ring::agreement::agree_ephemeral(self.0, &peer_public_key, |key_material| {
            final_key.extend_from_slice(key_material);
        }) {
            Ok(()) => Some(SpdmDheFinalKeyStruct::from(final_key)),
            Err(_) => None,
        }
    }
}

impl SpdmDheKeyExchangeP384 {
    fn generate_key_pair() -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
        let rng = ring::rand::SystemRandom::new();
        let private_key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P384, &rng)
                .ok()?;
        let public_key_old = private_key.compute_public_key().ok()?;
        let public_key = BytesMut::from(&public_key_old.as_ref()[1..]);

        let res: Box<dyn SpdmDheKeyExchange + Send> = Box::new(Self(private_key));

        Some((SpdmDheExchangeStruct::from(public_key), res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
