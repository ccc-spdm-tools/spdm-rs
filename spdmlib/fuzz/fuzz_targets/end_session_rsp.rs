// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../../fuzz-target/responder/end_session_rsp/src/main.rs");

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = fuzz_handle_spdm_end_session(Arc::new(data.to_vec()));
});
