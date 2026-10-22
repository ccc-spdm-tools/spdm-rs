// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::crypto::SpdmPqcAsymVerify;
use spdmlib::error::SpdmResult;
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDer, SpdmPqcAsymAlgo, SpdmSignatureStruct};

pub static DEFAULT: SpdmPqcAsymVerify = SpdmPqcAsymVerify {
    verify_cb: pqc_asym_verify,
    fips_self_test_cb: None,
};

fn pqc_asym_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _pqc_asym_algo: SpdmPqcAsymAlgo,
    _der: SpdmDer,
    _data: &[u8],
    _signature: &SpdmSignatureStruct,
) -> SpdmResult {
    unimplemented!()
}
