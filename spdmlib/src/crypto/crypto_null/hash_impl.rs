// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

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
    unimplemented!()
}

#[cfg(feature = "hashed-transcript-data")]
mod hash_ext {
    use crate::error::SpdmResult;
    use crate::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

    pub fn hash_ctx_update(handle: usize, data: &[u8]) -> SpdmResult {
        unimplemented!()
    }

    pub fn hash_ctx_finalize(handle: usize) -> Option<SpdmDigestStruct> {
        unimplemented!()
    }

    pub fn hash_ctx_dup(handle: usize) -> Option<usize> {
        unimplemented!()
    }

    pub fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<usize> {
        unimplemented!()
    }
}
