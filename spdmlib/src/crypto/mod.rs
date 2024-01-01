// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

pub mod bytes_mut_scrubbed;
mod crypto_callbacks;
mod x509v3;
pub use x509v3::*;

#[cfg(feature = "spdm-ring")]
mod spdm_ring;

pub use crypto_callbacks::{
    SpdmAead, SpdmAsymVerify, SpdmCertOperation, SpdmCryptoRandom, SpdmDhe, SpdmDheKeyExchange,
    SpdmHash, SpdmHkdf, SpdmHmac,
};

#[cfg(feature = "hashed-transcript-data")]
pub use self::hash::SpdmHashCtx;

use conquer_once::spin::OnceCell;

static CRYPTO_HASH: OnceCell<SpdmHash> = OnceCell::uninit();
static CRYPTO_HMAC: OnceCell<SpdmHmac> = OnceCell::uninit();
static CRYPTO_AEAD: OnceCell<SpdmAead> = OnceCell::uninit();
static CRYPTO_ASYM_VERIFY: OnceCell<SpdmAsymVerify> = OnceCell::uninit();
static CRYPTO_DHE: OnceCell<SpdmDhe> = OnceCell::uninit();
static CRYPTO_CERT_OPERATION: OnceCell<SpdmCertOperation> = OnceCell::uninit();
static CRYPTO_HKDF: OnceCell<SpdmHkdf> = OnceCell::uninit();
static CRYPTO_RAND: OnceCell<SpdmCryptoRandom> = OnceCell::uninit();

pub mod hash {
    use super::CRYPTO_HASH;
    use crate::crypto::SpdmHash;
    use crate::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

    // -ring -transcript
    #[cfg(all(
        not(any(feature = "spdm-ring")),
        not(feature = "hashed-transcript-data")
    ))]
    static DEFAULT: SpdmHash = SpdmHash {
        hash_all_cb: |_base_hash_algo: SpdmBaseHashAlgo,
                      _data: &[u8]|
         -> Option<SpdmDigestStruct> { unimplemented!() },
    };
    // +ring -transcript
    #[cfg(all(feature = "spdm-ring", not(feature = "hashed-transcript-data")))]
    use super::spdm_ring::hash_impl::DEFAULT;

    // +-ring +transcript
    #[cfg(feature = "hashed-transcript-data")]
    pub use hash_ext::DEFAULT;

    pub fn register(context: SpdmHash) -> bool {
        CRYPTO_HASH.try_init_once(|| context).is_ok()
    }

    pub fn hash_all(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct> {
        (CRYPTO_HASH
            .try_get_or_init(|| DEFAULT.clone())
            .ok()?
            .hash_all_cb)(base_hash_algo, data)
    }

    #[cfg(feature = "hashed-transcript-data")]
    mod hash_ext {
        use super::{SpdmBaseHashAlgo, SpdmDigestStruct, CRYPTO_HASH};
        use crate::error::SpdmResult;
        #[derive(Ord, PartialEq, PartialOrd, Eq, Debug, Default)]
        pub struct SpdmHashCtx(usize);

        impl Clone for SpdmHashCtx {
            fn clone(&self) -> Self {
                hash_ctx_dup(self).expect("Out of resource")
            }
        }

        impl Drop for SpdmHashCtx {
            fn drop(&mut self) {
                if self.0 != 0 {
                    hash_ctx_finalize(SpdmHashCtx(self.0));
                }
            }
        }

        pub fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<SpdmHashCtx> {
            let ret = (CRYPTO_HASH
                .try_get_or_init(|| DEFAULT.clone())
                .ok()?
                .hash_ctx_init_cb)(base_hash_algo)?;
            Some(SpdmHashCtx(ret))
        }

        pub fn hash_ctx_update(ctx: &SpdmHashCtx, data: &[u8]) -> SpdmResult {
            use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;

            (CRYPTO_HASH
                .try_get_or_init(|| DEFAULT.clone())
                .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
                .hash_ctx_update_cb)(ctx.0, data)
        }

        pub fn hash_ctx_finalize(mut ctx: SpdmHashCtx) -> Option<SpdmDigestStruct> {
            let handle = ctx.0;
            ctx.0 = 0;
            (CRYPTO_HASH
                .try_get_or_init(|| DEFAULT.clone())
                .ok()?
                .hash_ctx_finalize_cb)(handle)
        }

        pub fn hash_ctx_dup(ctx: &SpdmHashCtx) -> Option<SpdmHashCtx> {
            let ret = (CRYPTO_HASH
                .try_get_or_init(|| DEFAULT.clone())
                .expect("Functions should be registered before using")
                .hash_ctx_dup_cb)(ctx.0)?;
            Some(SpdmHashCtx(ret))
        }

        // - ring +transcript
        #[cfg(not(feature = "spdm-ring"))]
        use super::SpdmHash;
        #[cfg(not(feature = "spdm-ring"))]
        pub static DEFAULT: SpdmHash = SpdmHash {
            hash_all_cb: |_base_hash_algo: SpdmBaseHashAlgo,
                          _data: &[u8]|
             -> Option<SpdmDigestStruct> { unimplemented!() },
            hash_ctx_init_cb: |_base_hash_algo: SpdmBaseHashAlgo| -> Option<usize> {
                unimplemented!()
            },
            hash_ctx_update_cb: |_handle: usize, _data: &[u8]| -> SpdmResult { unimplemented!() },
            hash_ctx_finalize_cb: |_handle: usize| -> Option<SpdmDigestStruct> { unimplemented!() },
            hash_ctx_dup_cb: |_handle: usize| -> Option<usize> { unimplemented!() },
        };

        // + ring +transcript
        #[cfg(feature = "spdm-ring")]
        pub use crate::crypto::spdm_ring::hash_impl::DEFAULT;
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub use self::hash_ext::{
        hash_ctx_dup, hash_ctx_finalize, hash_ctx_init, hash_ctx_update, SpdmHashCtx,
    };
}

pub mod hmac {
    use super::CRYPTO_HMAC;
    use crate::crypto::SpdmHmac;
    use crate::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
    use crate::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

    #[cfg(not(any(feature = "spdm-ring")))]
    static DEFAULT: SpdmHmac = SpdmHmac {
        hmac_cb: |_base_hash_algo: SpdmBaseHashAlgo,
                  _key: &[u8],
                  _data: &[u8]|
         -> Option<SpdmDigestStruct> { unimplemented!() },
        hmac_verify_cb: |_base_hash_algo: SpdmBaseHashAlgo,
                         _key: &[u8],
                         _data: &[u8],
                         _hmac: &SpdmDigestStruct|
         -> SpdmResult { unimplemented!() },
    };

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::hmac_impl::DEFAULT;

    pub fn register(context: SpdmHmac) -> bool {
        CRYPTO_HMAC.try_init_once(|| context).is_ok()
    }

    pub fn hmac(
        base_hash_algo: SpdmBaseHashAlgo,
        key: &[u8],
        data: &[u8],
    ) -> Option<SpdmDigestStruct> {
        (CRYPTO_HMAC
            .try_get_or_init(|| DEFAULT.clone())
            .ok()?
            .hmac_cb)(base_hash_algo, key, data)
    }

    pub fn hmac_verify(
        base_hash_algo: SpdmBaseHashAlgo,
        key: &[u8],
        data: &[u8],
        hmac: &SpdmDigestStruct,
    ) -> SpdmResult {
        (CRYPTO_HMAC
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_VERIF_FAIL)?
            .hmac_verify_cb)(base_hash_algo, key, data, hmac)
    }
}

pub mod asym_verify {
    use super::CRYPTO_ASYM_VERIFY;
    use crate::crypto::SpdmAsymVerify;
    use crate::error::{SpdmResult, SPDM_STATUS_INVALID_STATE_LOCAL};
    use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};

    #[cfg(not(any(feature = "spdm-ring")))]
    static DEFAULT: SpdmAsymVerify = SpdmAsymVerify {
        verify_cb: |_base_hash_algo: SpdmBaseHashAlgo,
                    _base_asym_algo: SpdmBaseAsymAlgo,
                    _public_cert_der: &[u8],
                    _data: &[u8],
                    _signature: &SpdmSignatureStruct|
         -> SpdmResult { unimplemented!() },
    };

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::asym_verify_impl::DEFAULT;

    pub fn register(context: SpdmAsymVerify) -> bool {
        CRYPTO_ASYM_VERIFY.try_get_or_init(|| context).is_ok()
    }

    pub fn verify(
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        public_cert_der: &[u8],
        data: &[u8],
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        (CRYPTO_ASYM_VERIFY
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .verify_cb)(
            base_hash_algo,
            base_asym_algo,
            public_cert_der,
            data,
            signature,
        )
    }
}

pub mod dhe {
    extern crate alloc;
    use alloc::boxed::Box;

    use super::CRYPTO_DHE;
    use crate::crypto::{SpdmDhe, SpdmDheKeyExchange};
    use crate::protocol::{SpdmDheAlgo, SpdmDheExchangeStruct};

    #[cfg(not(any(feature = "spdm-ring")))]
    static DEFAULT: SpdmDhe = SpdmDhe {
        generate_key_pair_cb: |_dhe_algo: SpdmDheAlgo| -> Option<(
            SpdmDheExchangeStruct,
            Box<dyn SpdmDheKeyExchange + Send>,
        )> { unimplemented!() },
    };
    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::dhe_impl::DEFAULT;

    pub fn register(context: SpdmDhe) -> bool {
        CRYPTO_DHE.try_init_once(|| context).is_ok()
    }

    pub fn generate_key_pair(
        dhe_algo: SpdmDheAlgo,
    ) -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
        (CRYPTO_DHE
            .try_get_or_init(|| DEFAULT.clone())
            .ok()?
            .generate_key_pair_cb)(dhe_algo)
    }
}

pub mod cert_operation {
    use super::CRYPTO_CERT_OPERATION;
    use crate::crypto::SpdmCertOperation;
    use crate::error::{SpdmResult, SPDM_STATUS_INVALID_STATE_LOCAL};

    #[cfg(not(any(feature = "spdm-ring")))]
    static DEFAULT: SpdmCertOperation = SpdmCertOperation {
        get_cert_from_cert_chain_cb: |_cert_chain: &[u8],
                                      _index: isize|
         -> SpdmResult<(usize, usize)> { unimplemented!() },
        verify_cert_chain_cb: |_cert_chain: &[u8]| -> SpdmResult { unimplemented!() },
    };

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::cert_operation_impl::DEFAULT;

    pub fn register(context: SpdmCertOperation) -> bool {
        CRYPTO_CERT_OPERATION.try_init_once(|| context).is_ok()
    }

    pub fn get_cert_from_cert_chain(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
        (CRYPTO_CERT_OPERATION
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .get_cert_from_cert_chain_cb)(cert_chain, index)
    }

    pub fn verify_cert_chain(cert_chain: &[u8]) -> SpdmResult {
        (CRYPTO_CERT_OPERATION
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .verify_cert_chain_cb)(cert_chain)
    }
}

pub mod hkdf {
    use super::CRYPTO_HKDF;
    use crate::crypto::SpdmHkdf;
    use crate::protocol::{
        SpdmBaseHashAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
        SpdmHkdfPseudoRandomKey,
    };

    #[cfg(not(any(feature = "spdm-ring")))]
    static DEFAULT: SpdmHkdf = SpdmHkdf {
        hkdf_extract_cb: |_hash_algo: SpdmBaseHashAlgo,
                          _salt: &[u8],
                          _ikm: &SpdmHkdfInputKeyingMaterial|
         -> Option<SpdmHkdfPseudoRandomKey> { unimplemented!() },
        hkdf_expand_cb: |_hash_algo: SpdmBaseHashAlgo,
                         _prk: &SpdmHkdfPseudoRandomKey,
                         _info: &[u8],
                         _out_size: u16|
         -> Option<SpdmHkdfOutputKeyingMaterial> { unimplemented!() },
    };

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::hkdf_impl::DEFAULT;

    pub fn register(context: SpdmHkdf) -> bool {
        CRYPTO_HKDF.try_init_once(|| context).is_ok()
    }

    pub fn hkdf_extract(
        hash_algo: SpdmBaseHashAlgo,
        salt: &[u8],
        ikm: &SpdmHkdfInputKeyingMaterial,
    ) -> Option<SpdmHkdfPseudoRandomKey> {
        (CRYPTO_HKDF
            .try_get_or_init(|| DEFAULT.clone())
            .ok()?
            .hkdf_extract_cb)(hash_algo, salt, ikm)
    }

    pub fn hkdf_expand(
        hash_algo: SpdmBaseHashAlgo,
        prk: &SpdmHkdfPseudoRandomKey,
        info: &[u8],
        out_size: u16,
    ) -> Option<SpdmHkdfOutputKeyingMaterial> {
        (CRYPTO_HKDF
            .try_get_or_init(|| DEFAULT.clone())
            .ok()?
            .hkdf_expand_cb)(hash_algo, prk, info, out_size)
    }
}

pub mod aead {
    use super::CRYPTO_AEAD;
    use crate::crypto::SpdmAead;
    use crate::error::{SpdmResult, SPDM_STATUS_INVALID_STATE_LOCAL};
    use crate::protocol::{SpdmAeadAlgo, SpdmAeadIvStruct, SpdmAeadKeyStruct};

    #[cfg(not(any(feature = "spdm-ring")))]
    static DEFAULT: SpdmAead = SpdmAead {
        encrypt_cb: |_aead_algo: SpdmAeadAlgo,
                     _key: &SpdmAeadKeyStruct,
                     _iv: &SpdmAeadIvStruct,
                     _aad: &[u8],
                     _plain_text: &[u8],
                     _tag: &mut [u8],
                     _cipher_text: &mut [u8]|
         -> SpdmResult<(usize, usize)> { unimplemented!() },
        decrypt_cb: |_aead_algo: SpdmAeadAlgo,
                     _key: &SpdmAeadKeyStruct,
                     _iv: &SpdmAeadIvStruct,
                     _aad: &[u8],
                     _cipher_text: &[u8],
                     _tag: &[u8],
                     _plain_text: &mut [u8]|
         -> SpdmResult<usize> { unimplemented!() },
    };

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::aead_impl::DEFAULT;

    pub fn register(context: SpdmAead) -> bool {
        CRYPTO_AEAD.try_init_once(|| context).is_ok()
    }

    pub fn encrypt(
        aead_algo: SpdmAeadAlgo,
        key: &SpdmAeadKeyStruct,
        iv: &SpdmAeadIvStruct,
        aad: &[u8],
        plain_text: &[u8],
        tag: &mut [u8],
        cipher_text: &mut [u8],
    ) -> SpdmResult<(usize, usize)> {
        (CRYPTO_AEAD
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .encrypt_cb)(aead_algo, key, iv, aad, plain_text, tag, cipher_text)
    }

    pub fn decrypt(
        aead_algo: SpdmAeadAlgo,
        key: &SpdmAeadKeyStruct,
        iv: &SpdmAeadIvStruct,
        aad: &[u8],
        cipher_text: &[u8],
        tag: &[u8],
        plain_text: &mut [u8],
    ) -> SpdmResult<usize> {
        (CRYPTO_AEAD
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .decrypt_cb)(aead_algo, key, iv, aad, cipher_text, tag, plain_text)
    }
}

pub mod rand {
    use super::CRYPTO_RAND;
    use crate::crypto::SpdmCryptoRandom;
    use crate::error::{SpdmResult, SPDM_STATUS_INVALID_STATE_LOCAL};

    #[cfg(not(any(feature = "spdm-ring")))]
    static DEFAULT: SpdmCryptoRandom = SpdmCryptoRandom {
        get_random_cb: |_data: &mut [u8]| -> SpdmResult<usize> { unimplemented!() },
    };

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::rand_impl::DEFAULT;

    pub fn register(context: SpdmCryptoRandom) -> bool {
        CRYPTO_RAND.try_init_once(|| context).is_ok()
    }

    pub fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
        (CRYPTO_RAND
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .get_random_cb)(data)
    }
}

#[cfg(test)]
mod crypto_tests;
