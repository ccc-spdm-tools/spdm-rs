// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../../fuzz-target/responder/deliver_encapsulated_response_certificate_rsp/src/main.rs");

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = fuzz_handle_encap_response_certificate(Arc::new(data.to_vec()));
});
