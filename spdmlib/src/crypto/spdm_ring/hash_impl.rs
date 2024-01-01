// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;

use crate::crypto::SpdmHash;

use crate::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

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
};

fn hash_all(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct> {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &ring::digest::SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &ring::digest::SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &ring::digest::SHA512,
        _ => return None,
    };
    let digest_value = ring::digest::digest(algorithm, data);
    Some(SpdmDigestStruct::from(digest_value.as_ref()))
}

#[cfg(feature = "hashed-transcript-data")]
mod hash_ext {
    use super::*;
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use lazy_static::lazy_static;
    use spin::Mutex;

    pub type HashCtxConcrete = ring::digest::Context;

    lazy_static! {
        static ref HASH_CTX_TABLE: Mutex<BTreeMap<usize, Box<HashCtxConcrete>>> =
            Mutex::new(BTreeMap::new());
    }
    use crate::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};

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
        let new_handle = insert_to_table(ctx_new);
        Some(new_handle)
    }

    pub fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<usize> {
        let algorithm = match base_hash_algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &ring::digest::SHA256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &ring::digest::SHA384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &ring::digest::SHA512,
            _ => return None,
        };
        let ctx = Box::new(HashCtxConcrete::new(algorithm));
        Some(insert_to_table(ctx))
    }

    fn insert_to_table(value: Box<HashCtxConcrete>) -> usize {
        let handle_ptr: *const HashCtxConcrete = &*value;
        let handle = handle_ptr as usize;
        HASH_CTX_TABLE.lock().insert(handle, value);
        handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_hash_all() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let data = &mut [0u8; 64];

        let hash_all = hash_all(base_hash_algo, data).unwrap();
        assert_eq!(hash_all.data_size, 64);
    }
    #[test]
    fn test_case1_hash_all() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let data = &mut [0u8; 32];

        let hash_all = hash_all(base_hash_algo, data).unwrap();
        assert_eq!(hash_all.data_size, 32);
    }
    #[test]
    fn test_case2_hash_all() {
        let base_hash_algo = SpdmBaseHashAlgo::empty();
        let data = &mut [0u8; 64];

        let hash_all = hash_all(base_hash_algo, data);
        assert_eq!(hash_all.is_none(), true);
    }
    #[test]
    fn test_case0_hash_update() {
        let helloworld = ring::digest::digest(&ring::digest::SHA384, b"hello, world");
        let hellobuddy = ring::digest::digest(&ring::digest::SHA384, b"hello, buddy");
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA384);
        ctx.update(b"hello");
        ctx.update(b", ");
        let mut ctx_d = ctx.clone();
        ctx_d.update(b"buddy");
        ctx.update(b"world");
        let multi_part_helloworld = ctx.finish();
        let multi_part_hellobuddy = ctx_d.clone().finish();
        let multi_part_hellobuddy_twice = ctx_d.finish();
        assert_eq!(&helloworld.as_ref(), &multi_part_helloworld.as_ref());
        assert_eq!(&hellobuddy.as_ref(), &multi_part_hellobuddy.as_ref());
        assert_eq!(&hellobuddy.as_ref(), &multi_part_hellobuddy_twice.as_ref());
    }
}
