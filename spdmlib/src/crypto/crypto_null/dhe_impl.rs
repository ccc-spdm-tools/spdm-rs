// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::{SpdmDhe, SpdmDheKeyExchange};
use crate::protocol::{SpdmDheAlgo, SpdmDheExchangeStruct};

pub static DEFAULT: SpdmDhe = SpdmDhe {
    generate_key_pair_cb: generate_key_pair,
};

fn generate_key_pair(
    dhe_algo: SpdmDheAlgo,
) -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange + Send>)> {
    unimplemented!()
}
