// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use mbedtls::hash;
use spdmlib::crypto::SpdmHash;
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

#[cfg(feature = "hashed-transcript-data")]
pub use hash_ext::DEFAULT;

#[cfg(feature = "hashed-transcript-data")]
mod hash_ext {
    extern crate alloc;
    use super::*;
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use lazy_static::lazy_static;
    use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};
    use spin::Mutex;
    pub type HashCtxConcrete = hash::Md;
    lazy_static! {
        static ref HASH_CTX_TABLE: Mutex<BTreeMap<usize, Box<HashCtxConcrete>>> =
            Mutex::new(BTreeMap::new());
    }

    pub static DEFAULT: SpdmHash = SpdmHash {
        hash_all_cb: hash_all,
        hash_ctx_init_cb: hash_ctx_init,
        hash_ctx_update_cb: hash_ctx_update,
        hash_ctx_finalize_cb: hash_ctx_finalize,
        hash_ctx_dup_cb: hash_ctx_dup,
    };

    pub(crate) fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<usize> {
        let hash_algo = match base_hash_algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(hash::Type::Sha256),
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(hash::Type::Sha384),
            _ => None,
        }?;

        let md = hash::Md::new(hash_algo).ok()?;
        let ctx = Box::new(md);
        Some(insert_to_table(ctx))
    }

    pub(crate) fn hash_ctx_update(handle: usize, data: &[u8]) -> SpdmResult {
        let mut table = HASH_CTX_TABLE.lock();
        let ctx = table.get_mut(&handle).ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        ctx.update(data).map_err(|_e| SPDM_STATUS_CRYPTO_ERROR)
    }

    pub(crate) fn hash_ctx_finalize(handle: usize) -> Option<SpdmDigestStruct> {
        let ctx = HASH_CTX_TABLE.lock().remove(&handle)?;
        let mut digest = SpdmDigestStruct::default();
        let digest_len = ctx.finish(digest.data.as_mut()).ok()?;
        if digest_len > u16::MAX as usize {
            return None;
        }
        digest.data_size = digest_len as u16;
        Some(digest)
    }

    pub(crate) fn hash_ctx_dup(handle: usize) -> Option<usize> {
        let ctx = {
            let table = HASH_CTX_TABLE.lock();
            let ctx = table.get(&handle)?;
            ctx.clone()
        };
        Some(insert_to_table(ctx))
    }

    pub(crate) fn insert_to_table(value: Box<HashCtxConcrete>) -> usize {
        let handle_ptr: *const HashCtxConcrete = &*value;
        let handle = handle_ptr as usize;
        HASH_CTX_TABLE.lock().insert(handle, value);
        handle
    }

    #[allow(dead_code)]
    #[cfg(test)]
    pub fn get_hash_ctx_count() -> usize {
        HASH_CTX_TABLE.lock().len()
    }
}

#[cfg(not(feature = "hashed-transcript-data"))]
pub static DEFAULT: SpdmHash = SpdmHash {
    hash_all_cb: hash_all,
};

fn hash_all(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct> {
    let mut spdm_digest = SpdmDigestStruct::default();
    let hash_algo = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(hash::Type::Sha256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(hash::Type::Sha384),
        _ => None,
    }?;

    let mut md = hash::Md::new(hash_algo).ok()?;
    md.update(data).ok()?;
    let hash_len = md.finish(spdm_digest.data.as_mut()).ok()?;
    spdm_digest.data_size = hash_len as u16;
    Some(spdm_digest)
}

#[test]
fn test_case1_hash_all() {
    use std::fmt::Write;
    use std::string::String;
    let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    let data = &b"hello"[..];

    let mut res = String::new();
    let hash_all = hash_all(base_hash_algo, data).unwrap();
    for d in hash_all.as_ref() {
        let _ = write!(&mut res, "{:02x}", d);
    }
    println!("res: {}", String::from_utf8_lossy(res.as_ref()));
    assert_eq!(hash_all.data_size, 32);

    assert_eq!(
        res,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string()
    )
}
