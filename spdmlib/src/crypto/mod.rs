// Copyright (c) 2021-2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

pub mod bytes_mut_scrubbed;
mod crypto_callbacks;

extern crate spdm_x509;

extern crate alloc;
use alloc::boxed::Box;

#[cfg(not(feature = "spdm-ring"))]
mod crypto_null;

#[cfg(feature = "spdm-ring")]
mod spdm_ring;

pub use crypto_callbacks::{
    SpdmAead, SpdmAsymVerify, SpdmCertOperation, SpdmCryptoRandom, SpdmDhe, SpdmDheKeyExchange,
    SpdmHash, SpdmHkdf, SpdmHmac, SpdmKemCipherTextExchange, SpdmKemDecap, SpdmKemEncap,
    SpdmKemEncapKeyExchange, SpdmPqcAsymVerify,
};

#[cfg(feature = "hashed-transcript-data")]
pub use self::hash::SpdmHashCtx;

use crate::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};
use conquer_once::spin::OnceCell;

/// Check if a certificate is a root certificate (self-signed).
///
/// A self-signed root must be self-issued (issuer == subject) and have a valid
/// self-signature (RFC 5280).
///
/// The root's self-signature is verified cryptographically by the registered
/// `cert_operation::verify_cert_chain`, which runs before this function in the
/// GET_CERTIFICATE / ENCAP_GET_CERTIFICATE flow: the X.509 chain walk verifies
/// the root (last cert) against its own public key using the *active* crypto
/// backend (ring, mbedtls, or aws-lc). This function therefore only checks the
/// self-issued property here, avoiding a second, backend-hardcoded signature
/// check — which is what lets a post-quantum backend (aws-lc, verifying ML-DSA)
/// validate an ML-DSA root without a separate ring-only re-verification.
pub fn is_root_certificate(cert_der: &[u8]) -> SpdmResult {
    let cert = spdm_x509::Certificate::from_der(cert_der).map_err(|_| SPDM_STATUS_INVALID_CERT)?;

    // Check self-issued: issuer == subject.
    if cert.tbs_certificate.issuer != cert.tbs_certificate.subject {
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    Ok(())
}

/// Check leaf certificate validity per DSP0274 Table 42.
///
/// Validates:
/// - Basic Constraints: if present, cA MUST be FALSE (DSP0274 Table 42 /
///   RFC 5280 §4.2.1.9 — absence is permitted and implies cA=FALSE)
/// - Key Usage, if present, MUST assert digitalSignature (RFC 5280 §4.2.1.3)
/// - AliasCert model: SPDM HW Identity OID must NOT be present
/// - Non-alias certs (DeviceCert/GenericCert): treated as GenericCert;
///   absence of the SPDM extension is accepted so that standard chains
///   (stock spdm-rs test certs, real device chains without SPDM extension)
///   are not rejected.
pub fn check_leaf_certificate(cert_der: &[u8], is_alias_cert: bool) -> SpdmResult {
    use spdm_x509::x509::extensions::{BasicConstraints, KeyUsage, BASIC_CONSTRAINTS, KEY_USAGE};

    let cert = spdm_x509::Certificate::from_der(cert_der).map_err(|_| SPDM_STATUS_INVALID_CERT)?;

    // Extensions block may legitimately be absent for simple end-entity certs.
    let extensions = cert.tbs_certificate.extensions.as_ref();

    // 1. Basic Constraints: if present, cA MUST be FALSE (DSP0274 Table 42).
    //    The spec mandates BC with cA=TRUE only for intermediate/root certs.
    //    For leaf certs the extension is optional; absence implies cA=FALSE.
    if let Some(exts) = extensions {
        if let Some(bc_ext) = exts.find(&BASIC_CONSTRAINTS) {
            if let Ok(bc) = BasicConstraints::from_extension(bc_ext) {
                if bc.ca {
                    return Err(SPDM_STATUS_INVALID_CERT);
                }
            } else {
                return Err(SPDM_STATUS_INVALID_CERT);
            }
        }

        // 2. Key Usage, if present, MUST assert digitalSignature (RFC 5280 §4.2.1.3)
        if let Some(ku_ext) = exts.find(&KEY_USAGE) {
            let ku = KeyUsage::from_extension(ku_ext).map_err(|_| SPDM_STATUS_INVALID_CERT)?;
            if !ku.has(KeyUsage::DIGITAL_SIGNATURE) {
                return Err(SPDM_STATUS_INVALID_CERT);
            }
        }
    }

    // 3. DeviceID / Alias cert model checks via SPDM HW Identity OID.
    //    Non-alias certs are treated as GenericCert: many SPDM implementations
    //    and real device chains do not include the SPDM extension, so requiring
    //    it would reject valid chains.  AliasCert certs must NOT contain the
    //    HW Identity OID per DSP0274.
    let model = if is_alias_cert {
        spdm_x509::x509::spdm_validator::SpdmCertificateModel::AliasCert
    } else {
        spdm_x509::x509::spdm_validator::SpdmCertificateModel::GenericCert
    };
    // Hardware-identity validation inspects only extension bytes (no crypto), so
    // use the backend-free helper — this keeps check_leaf_certificate independent
    // of any specific crypto backend (ring/mbedtls/aws-lc).
    if spdm_x509::x509::spdm_validator::validate_hardware_identity(&cert, model).is_err() {
        log::error!(
            "Leaf certificate hardware identity check failed for model {:?}",
            model
        );
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    Ok(())
}

static CRYPTO_HASH: OnceCell<SpdmHash> = OnceCell::uninit();
static CRYPTO_HMAC: OnceCell<SpdmHmac> = OnceCell::uninit();
static CRYPTO_AEAD: OnceCell<SpdmAead> = OnceCell::uninit();
static CRYPTO_ASYM_VERIFY: OnceCell<SpdmAsymVerify> = OnceCell::uninit();
static CRYPTO_PQC_ASYM_VERIFY: OnceCell<SpdmPqcAsymVerify> = OnceCell::uninit();
static CRYPTO_DHE: OnceCell<SpdmDhe> = OnceCell::uninit();
static CRYPTO_KEM_DECAP: OnceCell<SpdmKemDecap> = OnceCell::uninit();
static CRYPTO_KEM_ENCAP: OnceCell<SpdmKemEncap> = OnceCell::uninit();
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
    use super::crypto_null::hash_impl::DEFAULT;

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
        extern crate alloc;
        use super::{SpdmBaseHashAlgo, SpdmDigestStruct, CRYPTO_HASH};
        use crate::error::SpdmResult;
        use codec::Codec;
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

        impl Codec for SpdmHashCtx {
            fn encode(&self, writer: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
                let serialized = hash_ctx_serialize(self).ok_or(codec::EncodeErr {})?;
                let len = serialized.len() as u16;
                len.encode(writer)?;
                writer
                    .extend_from_slice(&serialized)
                    .ok_or(codec::EncodeErr {})?;
                Ok(2 + serialized.len())
            }

            fn read(reader: &mut codec::Reader) -> Option<Self> {
                let len = u16::read(reader)? as usize;
                let bytes = reader.take(len)?;
                hash_ctx_deserialize(bytes)
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

        pub fn hash_ctx_serialize(ctx: &SpdmHashCtx) -> Option<alloc::vec::Vec<u8>> {
            (CRYPTO_HASH
                .try_get_or_init(|| DEFAULT.clone())
                .ok()?
                .hash_ctx_serialize_cb)(ctx.0)
        }

        pub fn hash_ctx_deserialize(bytes: &[u8]) -> Option<SpdmHashCtx> {
            let handle = (CRYPTO_HASH
                .try_get_or_init(|| DEFAULT.clone())
                .ok()?
                .hash_ctx_deserialize_cb)(bytes)?;
            Some(SpdmHashCtx(handle))
        }

        // - ring +transcript
        #[cfg(not(feature = "spdm-ring"))]
        pub use crate::crypto::crypto_null::hash_impl::DEFAULT;

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
    use super::crypto_null::hmac_impl::DEFAULT;

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
    use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDer, SpdmSignatureStruct};

    #[cfg(not(any(feature = "spdm-ring")))]
    use super::crypto_null::asym_verify_impl::DEFAULT;

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::asym_verify_impl::DEFAULT;

    pub fn register(context: SpdmAsymVerify) -> bool {
        CRYPTO_ASYM_VERIFY.try_get_or_init(|| context).is_ok()
    }

    pub fn verify(
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        der: SpdmDer,
        data: &[u8],
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        (CRYPTO_ASYM_VERIFY
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .verify_cb)(base_hash_algo, base_asym_algo, der, data, signature)
    }
}

pub mod pqc_asym_verify {
    use super::CRYPTO_PQC_ASYM_VERIFY;
    use crate::crypto::SpdmPqcAsymVerify;
    use crate::error::{SpdmResult, SPDM_STATUS_INVALID_STATE_LOCAL};
    use crate::protocol::{SpdmBaseHashAlgo, SpdmPqcAsymAlgo, SpdmSignatureStruct};

    #[cfg(not(any(feature = "spdm-ring")))]
    use super::crypto_null::pqc_asym_verify_impl::DEFAULT;

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::pqc_asym_verify_impl::DEFAULT;

    pub fn register(context: SpdmPqcAsymVerify) -> bool {
        CRYPTO_PQC_ASYM_VERIFY.try_get_or_init(|| context).is_ok()
    }

    pub fn verify(
        base_hash_algo: SpdmBaseHashAlgo,
        pqc_asym_algo: SpdmPqcAsymAlgo,
        public_cert_der: &[u8],
        data: &[u8],
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        (CRYPTO_PQC_ASYM_VERIFY
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .verify_cb)(
            base_hash_algo,
            pqc_asym_algo,
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
    use super::crypto_null::dhe_impl::DEFAULT;

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

    /// Import a private key from serialized bytes for checkpoint/resume
    pub fn import_private_key(
        dhe_algo: SpdmDheAlgo,
        private_key_bytes: &[u8],
    ) -> Option<Box<dyn SpdmDheKeyExchange + Send>> {
        let crypto_dhe = CRYPTO_DHE.try_get_or_init(|| DEFAULT.clone()).ok()?;
        let import_cb = crypto_dhe.import_private_key_cb?;
        import_cb(dhe_algo, private_key_bytes)
    }
}

pub mod kem_decap {
    extern crate alloc;
    use alloc::boxed::Box;

    use super::CRYPTO_KEM_DECAP;
    use crate::crypto::{SpdmKemDecap, SpdmKemEncapKeyExchange};
    use crate::protocol::{SpdmKemAlgo, SpdmKemEncapKeyStruct};

    #[cfg(not(any(feature = "spdm-ring")))]
    use super::crypto_null::kem_impl::DEFAULT_DECAP;

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::kem_impl::DEFAULT_DECAP;

    pub fn register(context: SpdmKemDecap) -> bool {
        CRYPTO_KEM_DECAP.try_init_once(|| context).is_ok()
    }

    pub fn generate_key_pair(
        kem_algo: SpdmKemAlgo,
    ) -> Option<(
        SpdmKemEncapKeyStruct,
        Box<dyn SpdmKemEncapKeyExchange + Send>,
    )> {
        (CRYPTO_KEM_DECAP
            .try_get_or_init(|| DEFAULT_DECAP.clone())
            .ok()?
            .generate_key_pair_cb)(kem_algo)
    }
}

pub mod kem_encap {
    extern crate alloc;
    use alloc::boxed::Box;

    use super::CRYPTO_KEM_ENCAP;
    use crate::crypto::{SpdmKemCipherTextExchange, SpdmKemEncap};
    use crate::protocol::{SpdmKemAlgo, SpdmKemEncapKeyStruct};

    #[cfg(not(any(feature = "spdm-ring")))]
    use super::crypto_null::kem_impl::DEFAULT_ENCAP;

    #[cfg(feature = "spdm-ring")]
    use super::spdm_ring::kem_impl::DEFAULT_ENCAP;

    pub fn register(context: SpdmKemEncap) -> bool {
        CRYPTO_KEM_ENCAP.try_init_once(|| context).is_ok()
    }

    pub fn new_key(
        kem_algo: SpdmKemAlgo,
        kem_encap_key: &SpdmKemEncapKeyStruct,
    ) -> Option<Box<dyn SpdmKemCipherTextExchange + Send>> {
        (CRYPTO_KEM_ENCAP
            .try_get_or_init(|| DEFAULT_ENCAP.clone())
            .ok()?
            .new_key_cb)(kem_algo, kem_encap_key)
    }
}

pub mod cert_operation {
    use super::CRYPTO_CERT_OPERATION;
    use crate::crypto::SpdmCertOperation;
    use crate::error::{SpdmResult, SPDM_STATUS_INVALID_STATE_LOCAL};
    use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo};

    #[cfg(not(any(feature = "spdm-ring")))]
    use super::crypto_null::cert_operation_impl::DEFAULT;

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

    pub fn verify_cert_chain(
        cert_chain: &[u8],
        base_asym_algo: SpdmBaseAsymAlgo,
        base_hash_algo: SpdmBaseHashAlgo,
    ) -> SpdmResult {
        let asym = if base_asym_algo.bits() != 0 {
            Some(base_asym_algo.bits())
        } else {
            None
        };
        let hash = if base_hash_algo.bits() != 0 {
            Some(base_hash_algo.bits())
        } else {
            None
        };
        (CRYPTO_CERT_OPERATION
            .try_get_or_init(|| DEFAULT.clone())
            .map_err(|_| SPDM_STATUS_INVALID_STATE_LOCAL)?
            .verify_cert_chain_cb)(cert_chain, asym, hash)
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
    use super::crypto_null::hkdf_impl::DEFAULT;

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
    use super::crypto_null::aead_impl::DEFAULT;

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
    use super::crypto_null::rand_impl::DEFAULT;

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
#[cfg(feature = "fips")]
pub mod fips;

use crate::protocol::{
    SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDer, SpdmPqcAsymAlgo, SpdmSignatureStruct,
};

pub fn spdm_asym_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    pqc_asym_algo: SpdmPqcAsymAlgo,
    der: SpdmDer,
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    if pqc_asym_algo != SpdmPqcAsymAlgo::empty() {
        match der {
            SpdmDer::SpdmDerCertChain(public_cert_der) => self::pqc_asym_verify::verify(
                base_hash_algo,
                pqc_asym_algo,
                public_cert_der,
                data,
                signature,
            ),
            SpdmDer::SpdmDerPubKeyRfc7250(public_key) => self::pqc_asym_verify::verify(
                base_hash_algo,
                pqc_asym_algo,
                public_key,
                data,
                signature,
            ),
        }
    } else {
        self::asym_verify::verify(base_hash_algo, base_asym_algo, der, data, signature)
    }
}

pub enum SpdmReqExchangeContext {
    SpdmReqExchangeContextDhe(Box<dyn SpdmDheKeyExchange + Send>),
    SpdmReqExchangeContextKem(Box<dyn SpdmKemEncapKeyExchange + Send>),
}

pub enum SpdmRspExchangeContext {
    SpdmRspExchangeContextDhe(Box<dyn SpdmDheKeyExchange + Send>),
    SpdmRspExchangeContextKem(Box<dyn SpdmKemCipherTextExchange + Send>),
}

#[cfg(test)]
mod crypto_tests;
