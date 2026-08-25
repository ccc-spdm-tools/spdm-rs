// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SHA-256/384/512 hashing via aws-lc-rs, for the standalone aws-lc backend.

extern crate alloc;

use spdmlib::crypto::SpdmHash;
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

#[cfg(not(feature = "hashed-transcript-data"))]
pub static DEFAULT: SpdmHash = SpdmHash {
    hash_all_cb: hash_all,
};
#[cfg(feature = "hashed-transcript-data")]
pub static DEFAULT: SpdmHash = SpdmHash {
    hash_all_cb: hash_all,
    hash_ctx_init_cb: hash_ext::hash_ctx_init,
    hash_ctx_update_cb: hash_ext::hash_ctx_update,
    hash_ctx_finalize_cb: hash_ext::hash_ctx_finalize,
    hash_ctx_dup_cb: hash_ext::hash_ctx_dup,
    hash_ctx_serialize_cb: hash_ext::hash_ctx_serialize,
    hash_ctx_deserialize_cb: hash_ext::hash_ctx_deserialize,
};

fn hash_all(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct> {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &aws_lc_rs::digest::SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &aws_lc_rs::digest::SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &aws_lc_rs::digest::SHA512,
        _ => return None,
    };
    let digest_value = aws_lc_rs::digest::digest(algorithm, data);
    Some(SpdmDigestStruct::from(digest_value.as_ref()))
}

#[cfg(feature = "hashed-transcript-data")]
mod hash_ext {
    use super::*;
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use aws_lc_sys::{SHA256_CTX, SHA512_CTX};
    use lazy_static::lazy_static;
    use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};
    use spin::Mutex;

    const HASH_CTX_FORMAT_VERSION: u8 = 1;
    const SHA256_KIND: u8 = 1;
    const SHA384_KIND: u8 = 2;
    const SHA512_KIND: u8 = 3;

    #[derive(Clone)]
    pub enum HashCtxConcrete {
        Sha256(SHA256_CTX),
        Sha384(SHA512_CTX),
        Sha512(SHA512_CTX),
    }

    lazy_static! {
        static ref HASH_CTX_TABLE: Mutex<BTreeMap<usize, Box<HashCtxConcrete>>> =
            Mutex::new(BTreeMap::new());
    }

    pub fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<usize> {
        let ctx = match base_hash_algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => {
                let mut ctx = SHA256_CTX::default();
                (unsafe { aws_lc_sys::SHA256_Init(&mut ctx) } == 1)
                    .then_some(HashCtxConcrete::Sha256(ctx))?
            }
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => {
                let mut ctx = SHA512_CTX::default();
                (unsafe { aws_lc_sys::SHA384_Init(&mut ctx) } == 1)
                    .then_some(HashCtxConcrete::Sha384(ctx))?
            }
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => {
                let mut ctx = SHA512_CTX::default();
                (unsafe { aws_lc_sys::SHA512_Init(&mut ctx) } == 1)
                    .then_some(HashCtxConcrete::Sha512(ctx))?
            }
            _ => return None,
        };
        Some(insert_to_table(Box::new(ctx)))
    }

    pub fn hash_ctx_update(handle: usize, data: &[u8]) -> SpdmResult {
        let mut table = HASH_CTX_TABLE.lock();
        let ctx = table.get_mut(&handle).ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        let result = unsafe {
            match ctx.as_mut() {
                HashCtxConcrete::Sha256(ctx) => {
                    aws_lc_sys::SHA256_Update(ctx, data.as_ptr().cast(), data.len())
                }
                HashCtxConcrete::Sha384(ctx) => {
                    aws_lc_sys::SHA384_Update(ctx, data.as_ptr().cast(), data.len())
                }
                HashCtxConcrete::Sha512(ctx) => {
                    aws_lc_sys::SHA512_Update(ctx, data.as_ptr().cast(), data.len())
                }
            }
        };
        (result == 1).then_some(()).ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    pub fn hash_ctx_finalize(handle: usize) -> Option<SpdmDigestStruct> {
        let mut ctx = HASH_CTX_TABLE.lock().remove(&handle)?;
        let mut digest = [0u8; 64];
        let (result, size) = unsafe {
            match ctx.as_mut() {
                HashCtxConcrete::Sha256(ctx) => {
                    (aws_lc_sys::SHA256_Final(digest.as_mut_ptr(), ctx), 32)
                }
                HashCtxConcrete::Sha384(ctx) => {
                    (aws_lc_sys::SHA384_Final(digest.as_mut_ptr(), ctx), 48)
                }
                HashCtxConcrete::Sha512(ctx) => {
                    (aws_lc_sys::SHA512_Final(digest.as_mut_ptr(), ctx), 64)
                }
            }
        };
        (result == 1).then(|| SpdmDigestStruct::from(&digest[..size]))
    }

    pub fn hash_ctx_dup(handle: usize) -> Option<usize> {
        let ctx_new = {
            let table = HASH_CTX_TABLE.lock();
            let ctx = table.get(&handle)?;
            ctx.clone()
        };
        Some(insert_to_table(ctx_new))
    }

    fn insert_to_table(value: Box<HashCtxConcrete>) -> usize {
        let handle_ptr: *const HashCtxConcrete = &*value;
        let handle = handle_ptr as usize;
        HASH_CTX_TABLE.lock().insert(handle, value);
        handle
    }

    /// Serialize an AWS-LC hash context for trusted local checkpointing.
    ///
    /// The little-endian format is tied to the pinned AWS-LC context ABI and
    /// is not suitable for untrusted input or cross-version persistence.
    pub fn hash_ctx_serialize(handle: usize) -> Option<Vec<u8>> {
        let table = HASH_CTX_TABLE.lock();
        let ctx = table.get(&handle)?;
        let mut bytes = Vec::new();
        bytes.push(HASH_CTX_FORMAT_VERSION);
        match ctx.as_ref() {
            HashCtxConcrete::Sha256(ctx) => {
                bytes.push(SHA256_KIND);
                for value in ctx.h {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
                bytes.extend_from_slice(&ctx.Nl.to_le_bytes());
                bytes.extend_from_slice(&ctx.Nh.to_le_bytes());
                bytes.extend_from_slice(&ctx.data);
                bytes.extend_from_slice(&ctx.num.to_le_bytes());
                bytes.extend_from_slice(&ctx.md_len.to_le_bytes());
            }
            HashCtxConcrete::Sha384(ctx) => {
                bytes.push(SHA384_KIND);
                for value in ctx.h {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
                bytes.extend_from_slice(&ctx.Nl.to_le_bytes());
                bytes.extend_from_slice(&ctx.Nh.to_le_bytes());
                bytes.extend_from_slice(&ctx.p);
                bytes.extend_from_slice(&ctx.num.to_le_bytes());
                bytes.extend_from_slice(&ctx.md_len.to_le_bytes());
            }
            HashCtxConcrete::Sha512(ctx) => {
                bytes.push(SHA512_KIND);
                for value in ctx.h {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
                bytes.extend_from_slice(&ctx.Nl.to_le_bytes());
                bytes.extend_from_slice(&ctx.Nh.to_le_bytes());
                bytes.extend_from_slice(&ctx.p);
                bytes.extend_from_slice(&ctx.num.to_le_bytes());
                bytes.extend_from_slice(&ctx.md_len.to_le_bytes());
            }
        }
        Some(bytes)
    }

    /// Restore a context emitted by `hash_ctx_serialize` in the same build.
    pub fn hash_ctx_deserialize(bytes: &[u8]) -> Option<usize> {
        fn take<const N: usize>(bytes: &mut &[u8]) -> Option<[u8; N]> {
            let (value, rest) = bytes.split_at_checked(N)?;
            *bytes = rest;
            value.try_into().ok()
        }

        let (&version, bytes) = bytes.split_first()?;
        if version != HASH_CTX_FORMAT_VERSION {
            return None;
        }
        let (&kind, mut bytes) = bytes.split_first()?;
        let ctx = match kind {
            SHA256_KIND => {
                let mut ctx = SHA256_CTX::default();
                for value in &mut ctx.h {
                    *value = u32::from_le_bytes(take(&mut bytes)?);
                }
                ctx.Nl = u32::from_le_bytes(take(&mut bytes)?);
                ctx.Nh = u32::from_le_bytes(take(&mut bytes)?);
                ctx.data = take(&mut bytes)?;
                ctx.num = u32::from_le_bytes(take(&mut bytes)?);
                ctx.md_len = u32::from_le_bytes(take(&mut bytes)?);
                (ctx.num < 64 && ctx.md_len == 32 && bytes.is_empty())
                    .then_some(HashCtxConcrete::Sha256(ctx))?
            }
            SHA384_KIND | SHA512_KIND => {
                let mut ctx = SHA512_CTX::default();
                for value in &mut ctx.h {
                    *value = u64::from_le_bytes(take(&mut bytes)?);
                }
                ctx.Nl = u64::from_le_bytes(take(&mut bytes)?);
                ctx.Nh = u64::from_le_bytes(take(&mut bytes)?);
                ctx.p = take(&mut bytes)?;
                ctx.num = u32::from_le_bytes(take(&mut bytes)?);
                ctx.md_len = u32::from_le_bytes(take(&mut bytes)?);
                if ctx.num >= 128 || !bytes.is_empty() {
                    return None;
                }
                match kind {
                    SHA384_KIND if ctx.md_len == 48 => HashCtxConcrete::Sha384(ctx),
                    SHA512_KIND if ctx.md_len == 64 => HashCtxConcrete::Sha512(ctx),
                    _ => return None,
                }
            }
            _ => return None,
        };
        Some(insert_to_table(Box::new(ctx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "hashed-transcript-data")]
    fn test_hash_ctx_round_trip(base_hash_algo: SpdmBaseHashAlgo) {
        let first = b"SPDM transcript before checkpoint";
        let second = b" and after restore";
        let handle = hash_ext::hash_ctx_init(base_hash_algo).unwrap();
        hash_ext::hash_ctx_update(handle, first).unwrap();
        let serialized = hash_ext::hash_ctx_serialize(handle).unwrap();
        let restored_handle = hash_ext::hash_ctx_deserialize(&serialized).unwrap();
        hash_ext::hash_ctx_update(restored_handle, second).unwrap();
        let actual = hash_ext::hash_ctx_finalize(restored_handle).unwrap();

        let mut message = first.to_vec();
        message.extend_from_slice(second);
        assert_eq!(actual, hash_all(base_hash_algo, &message).unwrap());
        hash_ext::hash_ctx_finalize(handle).unwrap();
    }

    #[test]
    fn test_hash_all_sha256() {
        let d = hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, &[0u8; 32]).unwrap();
        assert_eq!(d.data_size, 32);
    }

    #[test]
    fn test_hash_all_sha384() {
        let d = hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_384, &[0u8; 48]).unwrap();
        assert_eq!(d.data_size, 48);
    }

    #[test]
    fn test_hash_all_sha512() {
        let d = hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_512, &[0u8; 64]).unwrap();
        assert_eq!(d.data_size, 64);
    }

    #[test]
    fn test_hash_all_invalid() {
        assert!(hash_all(SpdmBaseHashAlgo::empty(), &[0u8; 32]).is_none());
    }

    #[cfg(feature = "hashed-transcript-data")]
    #[test]
    fn test_hash_context_checkpoint_round_trip() {
        test_hash_ctx_round_trip(SpdmBaseHashAlgo::TPM_ALG_SHA_256);
        test_hash_ctx_round_trip(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        test_hash_ctx_round_trip(SpdmBaseHashAlgo::TPM_ALG_SHA_512);
    }

    #[cfg(feature = "hashed-transcript-data")]
    #[test]
    fn test_hash_context_checkpoint_rejects_malformed_data() {
        let handle = hash_ext::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384).unwrap();
        let serialized = hash_ext::hash_ctx_serialize(handle).unwrap();
        hash_ext::hash_ctx_finalize(handle).unwrap();

        let mut wrong_version = serialized.clone();
        wrong_version[0] = wrong_version[0].wrapping_add(1);
        assert!(hash_ext::hash_ctx_deserialize(&wrong_version).is_none());
        assert!(hash_ext::hash_ctx_deserialize(&serialized[..serialized.len() - 1]).is_none());

        let mut trailing_data = serialized;
        trailing_data.push(0);
        assert!(hash_ext::hash_ctx_deserialize(&trailing_data).is_none());
    }
}
