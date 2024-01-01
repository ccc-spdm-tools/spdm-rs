// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use mbedtls::ecp::EcPoint;
use mbedtls::pk::{EcGroup, EcGroupId, Pk};
use mbedtls::rng::RngCallback;
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use spdmlib::crypto::{SpdmDhe, SpdmDheKeyExchange};
use spdmlib::protocol::{SpdmDheAlgo, SpdmDheExchangeStruct, SpdmDheFinalKeyStruct};
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

pub struct SpdmDheKeyExchangeP256(Pk);

impl SpdmDheKeyExchangeP256 {
    fn generate_key_pair() -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
        let mut peer = SpdmDheExchangeStruct::default();
        let mut rng = RdRand;
        let secp256r1 = EcGroup::new(EcGroupId::SecP256R1).ok()?;
        let pk = Pk::generate_ec(&mut rng, secp256r1.clone()).ok()?;
        let peer_key = pk.ec_public().ok()?.to_binary(&secp256r1, false).ok()?;
        peer.data.as_mut_slice()[0..(peer_key.len() - 1)]
            .copy_from_slice(&peer_key.as_slice()[1..(peer_key.len())]);
        peer.data_size = (peer_key.len() - 1) as u16;
        let res: Box<dyn SpdmDheKeyExchange + Send> = Box::new(Self(pk));
        Some((peer, res))
    }
}

impl SpdmDheKeyExchange for SpdmDheKeyExchangeP256 {
    fn compute_final_key(
        mut self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmDheFinalKeyStruct> {
        let mut final_key = SpdmDheFinalKeyStruct::default();
        let mut rng = RdRand;
        let secp256r1 = EcGroup::new(EcGroupId::SecP256R1).ok()?;
        let mut peer = Vec::new();
        peer.push(0x4u8);
        peer.extend_from_slice(peer_pub_key.as_ref());
        let peer = EcPoint::from_binary(&secp256r1, peer.as_slice()).ok()?;
        let peer = &Pk::public_from_ec_components(secp256r1, peer).ok()?;
        let len = self
            .0
            .agree(peer, final_key.data.as_mut_slice(), &mut rng)
            .ok()?;
        final_key.data_size = len as u16;
        Some(final_key)
    }
}

pub struct SpdmDheKeyExchangeP384(Pk);

impl SpdmDheKeyExchangeP384 {
    fn generate_key_pair() -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
        let mut peer = SpdmDheExchangeStruct::default();
        let mut rng = RdRand;
        let secp384r1 = EcGroup::new(EcGroupId::SecP384R1).ok()?;
        let pk = Pk::generate_ec(&mut rng, secp384r1.clone()).ok()?;
        let peer_key = pk.ec_public().ok()?.to_binary(&secp384r1, false).ok()?;
        peer.data.as_mut_slice()[0..(peer_key.len() - 1)]
            .copy_from_slice(&peer_key.as_slice()[1..(peer_key.len())]);
        peer.data_size = (peer_key.len() - 1) as u16;
        let res: Box<dyn SpdmDheKeyExchange + Send> = Box::new(Self(pk));
        Some((peer, res))
    }
}

impl SpdmDheKeyExchange for SpdmDheKeyExchangeP384 {
    fn compute_final_key(
        mut self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmDheFinalKeyStruct> {
        let mut final_key = SpdmDheFinalKeyStruct::default();
        let mut rng = RdRand;
        let secp384r1 = EcGroup::new(EcGroupId::SecP384R1).ok()?;
        let mut peer = Vec::new();
        peer.push(0x4u8);
        peer.extend_from_slice(peer_pub_key.as_ref());
        let peer = EcPoint::from_binary(&secp384r1, peer.as_slice()).ok()?;
        let peer = &Pk::public_from_ec_components(secp384r1, peer).ok()?;
        let len = self
            .0
            .agree(peer, final_key.data.as_mut_slice(), &mut rng)
            .ok()?;
        final_key.data_size = len as u16;
        Some(final_key)
    }
}

#[derive(Default)]
pub struct RdRand;

impl RngCallback for RdRand {
    unsafe extern "C" fn call(_user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int
    where
        Self: Sized,
    {
        use crate::rand_impl::random;
        random(data, len)
    }

    fn data_ptr(&self) -> *mut c_void {
        core::ptr::null_mut()
    }
}

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
