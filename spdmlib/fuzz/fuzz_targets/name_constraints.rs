// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_main]

use der::Decode;
use libfuzzer_sys::fuzz_target;
use spdm_x509::certificate::name::SubjectAltName;
use spdm_x509::NameConstraints;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let split =
        usize::from(u16::from_be_bytes([data[0], data[1]])).min(data.len().saturating_sub(2));
    let payload = &data[2..];
    let (constraints, subject_alt_name) = payload.split_at(split);

    let _ = NameConstraints::from_der(constraints);
    let _ = SubjectAltName::from_der(subject_alt_name);
});
