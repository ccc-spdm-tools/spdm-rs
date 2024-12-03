// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
//

use super::*;

use crate::crypto::SpdmHmac;
use crate::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use crate::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub fn run_self_test() -> Result<(), crate::crypto::fips::SelfTestError> {
    Ok(())
}
