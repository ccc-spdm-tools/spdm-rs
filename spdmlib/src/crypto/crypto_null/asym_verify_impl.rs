// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::SpdmAsymVerify;
use crate::error::SpdmResult;
use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDer, SpdmSignatureStruct};

pub static DEFAULT: SpdmAsymVerify = SpdmAsymVerify {
    verify_cb: asym_verify,
};

fn asym_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    der: SpdmDer,
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    unimplemented!()
}
