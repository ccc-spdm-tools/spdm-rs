// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::crypto::SpdmPqcAsymVerify;
use spdmlib::error::SpdmResult;
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmPqcAsymAlgo, SpdmSignatureStruct};

pub static DEFAULT: SpdmPqcAsymVerify = SpdmPqcAsymVerify {
    verify_cb: pqc_asym_verify,
};

fn pqc_asym_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _pqc_asym_algo: SpdmPqcAsymAlgo,
    _public_cert_der: &[u8],
    _data: &[u8],
    _signature: &SpdmSignatureStruct,
) -> SpdmResult {
    unimplemented!()
}
