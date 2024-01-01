// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[derive(Clone)]
pub struct SpdmTime {
    pub sleep_cb: fn(us: usize),
}
