// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::vec::Vec;

use core::convert::TryInto;

mod algo;
mod capability;
mod version;
pub use algo::*;
pub use capability::*;
pub use version::*;

// util function
pub fn gen_array<T: Default, const N: usize>(count: usize) -> [T; N] {
    let mut vec = Vec::new();
    for _i in 0..count {
        vec.push(T::default());
    }
    vec.try_into()
        .unwrap_or_else(|_| panic!("gen_array error!"))
}

// util function
pub fn gen_array_clone<T: Clone, const N: usize>(v: T, count: usize) -> [T; N] {
    let mut vec = Vec::new();
    for _i in 1..count {
        vec.push(v.clone());
    }
    vec.push(v);
    vec.try_into()
        .unwrap_or_else(|_| panic!("gen_array_clone error!"))
}
