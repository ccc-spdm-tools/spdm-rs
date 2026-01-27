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
pub mod hash_ext {
    use super::*;
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use lazy_static::lazy_static;
    use spin::Mutex;

    pub type HashCtxConcrete = ring::digest::Context;

    /// Hash context with replay buffer for serialization support
    struct HashCtxWithReplay {
        ctx: HashCtxConcrete,
        replay_buffer: Vec<u8>, // Store all data for replay after deserialization
        algo: SpdmBaseHashAlgo,
    }

    lazy_static! {
        static ref HASH_CTX_TABLE: Mutex<BTreeMap<usize, Box<HashCtxWithReplay>>> =
            Mutex::new(BTreeMap::new());
    }
    use crate::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};

    /// Serializable hash state - just the algorithm and replay buffer
    #[derive(Debug, Clone)]
    pub struct HashCtxState {
        pub algo: SpdmBaseHashAlgo,
        pub replay_buffer: Vec<u8>,
    }

    /// Export hash context state for serialization
    pub fn hash_ctx_export(handle: usize) -> Option<HashCtxState> {
        let table = HASH_CTX_TABLE.lock();
        let ctx_with_replay = table.get(&handle)?;

        Some(HashCtxState {
            algo: ctx_with_replay.algo,
            replay_buffer: ctx_with_replay.replay_buffer.clone(),
        })
    }

    /// Import hash context state from serialized form
    pub fn hash_ctx_import(state: &HashCtxState) -> Option<usize> {
        let algorithm = match state.algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &ring::digest::SHA256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &ring::digest::SHA384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &ring::digest::SHA512,
            _ => return None,
        };

        // Create new context and replay all data
        let mut ctx = HashCtxConcrete::new(algorithm);
        ctx.update(&state.replay_buffer);

        let ctx_with_replay = Box::new(HashCtxWithReplay {
            ctx,
            replay_buffer: state.replay_buffer.clone(),
            algo: state.algo,
        });

        Some(insert_to_table(ctx_with_replay))
    }

    pub fn hash_ctx_update(handle: usize, data: &[u8]) -> SpdmResult {
        let mut table = HASH_CTX_TABLE.lock();
        let ctx_with_replay = table.get_mut(&handle).ok_or(SPDM_STATUS_CRYPTO_ERROR)?;

        // Update both the hash context and replay buffer
        ctx_with_replay.ctx.update(data);
        ctx_with_replay.replay_buffer.extend_from_slice(data);

        Ok(())
    }

    pub fn hash_ctx_finalize(handle: usize) -> Option<SpdmDigestStruct> {
        let ctx_with_replay = HASH_CTX_TABLE.lock().remove(&handle)?;
        let digest_value = ctx_with_replay.ctx.finish();
        Some(SpdmDigestStruct::from(digest_value.as_ref()))
    }

    pub fn hash_ctx_dup(handle: usize) -> Option<usize> {
        let ctx_with_replay_new = {
            let table = HASH_CTX_TABLE.lock();
            let ctx_with_replay = table.get(&handle)?;
            Box::new(HashCtxWithReplay {
                ctx: ctx_with_replay.ctx.clone(),
                replay_buffer: ctx_with_replay.replay_buffer.clone(),
                algo: ctx_with_replay.algo,
            })
        };
        let new_handle = insert_to_table(ctx_with_replay_new);
        Some(new_handle)
    }

    pub fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<usize> {
        let algorithm = match base_hash_algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &ring::digest::SHA256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &ring::digest::SHA384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &ring::digest::SHA512,
            _ => return None,
        };
        let ctx_with_replay = Box::new(HashCtxWithReplay {
            ctx: HashCtxConcrete::new(algorithm),
            replay_buffer: Vec::new(),
            algo: base_hash_algo,
        });
        Some(insert_to_table(ctx_with_replay))
    }

    fn insert_to_table(value: Box<HashCtxWithReplay>) -> usize {
        let handle_ptr: *const HashCtxWithReplay = &*value;
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
