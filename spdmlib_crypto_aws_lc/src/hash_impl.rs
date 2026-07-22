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
    use lazy_static::lazy_static;
    use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};
    use spin::Mutex;

    pub type HashCtxConcrete = aws_lc_rs::digest::Context;

    lazy_static! {
        static ref HASH_CTX_TABLE: Mutex<BTreeMap<usize, Box<HashCtxConcrete>>> =
            Mutex::new(BTreeMap::new());
    }

    pub fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<usize> {
        let algorithm = match base_hash_algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &aws_lc_rs::digest::SHA256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &aws_lc_rs::digest::SHA384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &aws_lc_rs::digest::SHA512,
            _ => return None,
        };
        let ctx = Box::new(HashCtxConcrete::new(algorithm));
        Some(insert_to_table(ctx))
    }

    pub fn hash_ctx_update(handle: usize, data: &[u8]) -> SpdmResult {
        let mut table = HASH_CTX_TABLE.lock();
        let ctx = table.get_mut(&handle).ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        ctx.update(data);
        Ok(())
    }

    pub fn hash_ctx_finalize(handle: usize) -> Option<SpdmDigestStruct> {
        let ctx = HASH_CTX_TABLE.lock().remove(&handle)?;
        let digest_value = ctx.finish();
        Some(SpdmDigestStruct::from(digest_value.as_ref()))
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

    // aws-lc-rs digest::Context does not expose serialize/deserialize of the
    // in-progress state, so checkpoint/resume of a hash context is unsupported
    // on this backend. These return None; callers that need transcript
    // checkpointing must use a backend that supports it.
    pub fn hash_ctx_serialize(_handle: usize) -> Option<alloc::vec::Vec<u8>> {
        None
    }

    pub fn hash_ctx_deserialize(_bytes: &[u8]) -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
