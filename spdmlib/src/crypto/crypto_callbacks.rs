// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::SpdmResult;

extern crate alloc;
use alloc::boxed::Box;

use crate::protocol::{
    SpdmAeadAlgo, SpdmAeadIvStruct, SpdmAeadKeyStruct, SpdmBaseAsymAlgo, SpdmBaseHashAlgo,
    SpdmDheAlgo, SpdmDheExchangeStruct, SpdmDheFinalKeyStruct, SpdmDigestStruct,
    SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial, SpdmHkdfPseudoRandomKey,
    SpdmSignatureStruct,
};

#[cfg(not(feature = "hashed-transcript-data"))]
#[derive(Clone)]
pub struct SpdmHash {
    pub hash_all_cb: fn(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct>,
}

#[cfg(feature = "hashed-transcript-data")]
#[derive(Clone)]
pub struct SpdmHash {
    pub hash_all_cb: fn(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct>,
    pub hash_ctx_init_cb: fn(base_hash_algo: SpdmBaseHashAlgo) -> Option<usize>,
    pub hash_ctx_update_cb: fn(ctx: usize, data: &[u8]) -> SpdmResult,
    pub hash_ctx_finalize_cb: fn(ctx: usize) -> Option<SpdmDigestStruct>,
    pub hash_ctx_dup_cb: fn(ctx: usize) -> Option<usize>,
}

#[derive(Clone)]
pub struct SpdmHmac {
    pub hmac_cb:
        fn(base_hash_algo: SpdmBaseHashAlgo, key: &[u8], data: &[u8]) -> Option<SpdmDigestStruct>,

    pub hmac_verify_cb: fn(
        base_hash_algo: SpdmBaseHashAlgo,
        key: &[u8],
        data: &[u8],
        hmac: &SpdmDigestStruct,
    ) -> SpdmResult,
}

type EncryptCb = fn(
    aead_algo: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &SpdmAeadIvStruct,
    aad: &[u8],
    plain_text: &[u8],
    tag: &mut [u8],
    cipher_text: &mut [u8],
) -> SpdmResult<(usize, usize)>;

type DecryptCb = fn(
    aead_algo: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &SpdmAeadIvStruct,
    aad: &[u8],
    cipher_text: &[u8],
    tag: &[u8],
    plain_text: &mut [u8],
) -> SpdmResult<usize>;

#[derive(Clone)]
pub struct SpdmAead {
    pub encrypt_cb: EncryptCb,

    pub decrypt_cb: DecryptCb,
}

#[derive(Clone)]
pub struct SpdmAsymVerify {
    pub verify_cb: fn(
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        public_cert_der: &[u8],
        data: &[u8],
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult,
}

#[derive(Clone)]
pub struct SpdmHkdf {
    pub hkdf_extract_cb: fn(
        hash_algo: SpdmBaseHashAlgo,
        salt: &[u8],
        ikm: &SpdmHkdfInputKeyingMaterial,
    ) -> Option<SpdmHkdfPseudoRandomKey>,
    pub hkdf_expand_cb: fn(
        hash_algo: SpdmBaseHashAlgo,
        prk: &SpdmHkdfPseudoRandomKey,
        info: &[u8],
        out_size: u16,
    ) -> Option<SpdmHkdfOutputKeyingMaterial>,
}

type GetCertFromCertChainCb = fn(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)>;

#[derive(Clone)]
pub struct SpdmCertOperation {
    pub get_cert_from_cert_chain_cb: GetCertFromCertChainCb,

    pub verify_cert_chain_cb: fn(cert_chain: &[u8]) -> SpdmResult,
}

type GenerateKeyPairCb = fn(
    dhe_algo: SpdmDheAlgo,
) -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)>;

#[derive(Clone)]
pub struct SpdmDhe {
    pub generate_key_pair_cb: GenerateKeyPairCb,
}

pub trait SpdmDheKeyExchange {
    fn compute_final_key(
        self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmDheFinalKeyStruct>;
}

#[derive(Clone)]
pub struct SpdmCryptoRandom {
    pub get_random_cb: fn(data: &mut [u8]) -> SpdmResult<usize>,
}
