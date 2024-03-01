// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../../fuzz-target/requester/algorithm_req/src/main.rs");

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = fuzz_send_receive_spdm_algorithm(Arc::new(data.to_vec()));
});
