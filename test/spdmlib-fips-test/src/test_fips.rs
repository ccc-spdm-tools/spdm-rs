// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[test]
fn test_fips_self_tests() {
    let result = spdmlib::crypto::fips::run_self_tests();
    assert!(result.is_ok());
}
