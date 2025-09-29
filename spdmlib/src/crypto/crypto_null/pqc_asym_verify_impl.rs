// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::SpdmPqcAsymVerify;
use crate::error::SpdmResult;
use crate::protocol::{SpdmBaseHashAlgo, SpdmPqcAsymAlgo, SpdmSignatureStruct};

pub static DEFAULT: SpdmPqcAsymVerify = SpdmPqcAsymVerify {
    verify_cb: pqc_asym_verify,
};

fn pqc_asym_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    pqc_asym_algo: SpdmPqcAsymAlgo,
    public_cert_der: &[u8],
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    unimplemented!()
}
